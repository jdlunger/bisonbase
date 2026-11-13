//! The relational API on a user database: structured select / insert / update / delete, and
//! bringing tables in line with what an app declares.
//!
//! No caller-supplied SQL reaches SQLite. Every table and column named in a request is looked up
//! in the database's schema and quoted, and every value is a bound parameter. The database
//! itself is resolved by the caller: inside the requesting user's own file tree ([`Access::All`]),
//! or in a registered app's own storage ([`Access::Rows`]). App databases are shared by all of
//! the app's users, so each of their rows belongs to one user (the `_owner` column, which the
//! server fills in), and requests only reach the caller's own rows, plus, for reading, every
//! row of tables declared `shared`.
//!
//! Everything here is synchronous; callers run it on a blocking thread.

use rusqlite::{Connection, TransactionBehavior, types::Value};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value as Json};

use super::{
    rows::quote_ident,
    sql::{
        self, ColumnSchema, QueryResult, TableSchema, UserConn, json_to_sql, run_prepared, sql_err,
    },
};
use crate::error::{AppError, AppResult};

// ---- row ownership ----

/// The column holding a row's owner (a user id) in app databases.
pub const OWNER_COLUMN: &str = "_owner";
/// Where app databases record each table's sharing policy. Hidden from the API.
pub const META_TABLE: &str = "_bisonbase_tables";

/// Tables the server keeps for itself: never reachable through the API, and not listed.
pub fn is_internal(table: &str) -> bool {
    table
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("_bisonbase"))
}

/// Which rows a request may reach.
#[derive(Debug, Clone)]
pub enum Access {
    /// Every row: a database in the user's own files.
    All,
    /// An app database: reads see the user's own rows (and every row of shared tables), and
    /// writes only touch, and create, rows owned by `user`.
    Rows { user: String },
}

/// Who may read a table's rows in an app database. Only a row's owner may change it either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Sharing {
    /// Each user sees only their own rows.
    #[default]
    Private,
    /// Every user of the app sees every row.
    Shared,
}

impl Sharing {
    fn as_str(self) -> &'static str {
        match self {
            Sharing::Private => "private",
            Sharing::Shared => "shared",
        }
    }
}

/// A table's sharing policy in an app database (private unless recorded otherwise).
pub fn sharing(conn: &Connection, table: &str) -> AppResult<Sharing> {
    if sql::table(conn, META_TABLE)?.is_none() {
        return Ok(Sharing::Private);
    }
    let v: Option<String> = conn
        .query_row(
            &format!(
                "SELECT sharing FROM {} WHERE name = ?1 COLLATE NOCASE",
                quote_ident(META_TABLE)
            ),
            [table],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(sql_err(e)),
        })?;
    Ok(match v.as_deref() {
        Some("shared") => Sharing::Shared,
        _ => Sharing::Private,
    })
}

/// The owner a request is limited to on `t`, if any. `reading`: shared tables are readable in
/// full.
fn owner_filter(
    conn: &Connection,
    t: &TableSchema,
    access: &Access,
    reading: bool,
) -> AppResult<Option<String>> {
    let Access::Rows { user } = access else {
        return Ok(None);
    };
    if !has_column(t, OWNER_COLUMN) {
        return Err(AppError::forbidden(format!(
            "\"{}\" has no {OWNER_COLUMN} column, so the app's users can't use it",
            t.name
        )));
    }
    if reading && sharing(conn, &t.name)? == Sharing::Shared {
        return Ok(None);
    }
    Ok(Some(user.clone()))
}

fn has_column(t: &TableSchema, name: &str) -> bool {
    t.columns.iter().any(|c| c.name.eq_ignore_ascii_case(name))
}

/// Refuse a request that tries to set `_owner` itself.
fn check_not_owner(access: &Access, name: &str) -> AppResult<()> {
    if matches!(access, Access::Rows { .. }) && name.eq_ignore_ascii_case(OWNER_COLUMN) {
        return Err(AppError::bad(format!(
            "{OWNER_COLUMN} is set by the server to the signed-in user"
        )));
    }
    Ok(())
}

// ---- requests ----

/// Rows match when every listed column matches: `{"col": value}`, `{"col": null}` (IS NULL), or
/// `{"col": {"$gte": 1, "$lt": 5}}` with `$ne`, `$lt`, `$lte`, `$gt`, `$gte` and `$in`.
pub type Where = Map<String, Json>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Select {
    pub table: String,
    #[serde(default, rename = "where")]
    pub filter: Where,
    /// Column names, each optionally followed by ` asc` or ` desc`.
    #[serde(default)]
    pub order_by: Vec<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Insert {
    pub table: String,
    /// Each row maps column names to values; columns left out get the database's default.
    pub rows: Vec<Map<String, Json>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub table: String,
    /// Required, so that a misspelled key can't widen an update to every row. `{}` matches all.
    #[serde(rename = "where")]
    pub filter: Where,
    pub set: Map<String, Json>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delete {
    pub table: String,
    /// Required, as for [`Update`].
    #[serde(rename = "where")]
    pub filter: Where,
}

/// One write in a [`Transact`].
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum WriteOp {
    Insert(Insert),
    Update(Update),
    Delete(Delete),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transact {
    pub ops: Vec<WriteOp>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migrate {
    pub tables: Vec<TableSpec>,
}

/// A table as an app declares it. It always gets an `id INTEGER PRIMARY KEY` column as well.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableSpec {
    pub name: String,
    pub columns: Vec<ColumnSpec>,
    /// App databases only: who may read the table's rows. Default: private.
    #[serde(default)]
    pub sharing: Option<Sharing>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ColumnType,
    #[serde(default)]
    pub nullable: bool,
    /// Present (possibly `null`) when the column has a default.
    #[serde(default, deserialize_with = "present")]
    pub default: Option<Json>,
}

fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Json>, D::Error> {
    Json::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnType {
    Text,
    Integer,
    Real,
    Boolean,
    Blob,
    Json,
}

impl ColumnType {
    fn sql(self) -> &'static str {
        match self {
            ColumnType::Text => "TEXT",
            ColumnType::Integer => "INTEGER",
            ColumnType::Real => "REAL",
            ColumnType::Boolean => "BOOLEAN",
            ColumnType::Blob => "BLOB",
            ColumnType::Json => "JSON",
        }
    }
}

// ---- responses ----

#[derive(Debug, Serialize)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Json>>,
    /// More rows matched than the server returns in one response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl From<QueryResult> for Rows {
    fn from(r: QueryResult) -> Self {
        Rows {
            columns: r.columns,
            rows: r.rows,
            truncated: r.truncated,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum WriteResult {
    /// From an insert: the rows as stored.
    Rows(Rows),
    /// From an update or delete: how many rows it changed.
    Changes { changes: u64 },
}

#[derive(Debug, Serialize)]
pub struct Migrated {
    /// The statements that were run, if any.
    pub applied: Vec<String>,
}

// ---- operations ----

pub fn select(c: &UserConn, access: &Access, q: &Select) -> AppResult<Rows> {
    let max_rows = c.max_rows();
    c.guarded(|conn| {
        let t = find(conn, &q.table, false)?;
        let owner = owner_filter(conn, &t, access, true)?;
        let mut params = Vec::new();
        let mut sql = format!("SELECT {} FROM {}", all_columns(&t), quote_ident(&t.name));
        sql += &where_sql(&t, &q.filter, owner.as_deref(), &mut params)?;
        sql += &order_sql(&t, &q.order_by)?;
        if q.limit.is_some() || q.offset.is_some() {
            sql += " LIMIT ?";
            params.push(Value::Integer(
                q.limit.map(to_i64).transpose()?.unwrap_or(-1),
            ));
        }
        if let Some(o) = q.offset {
            sql += " OFFSET ?";
            params.push(Value::Integer(to_i64(o)?));
        }
        let st = conn.prepare(&sql).map_err(sql_err)?;
        Ok(run_prepared(conn, st, &params, true, max_rows)?.into())
    })
}

/// Run writes in one transaction: all of them take effect, or none do.
pub fn transact(c: &UserConn, access: &Access, ops: &[WriteOp]) -> AppResult<Vec<WriteResult>> {
    c.guarded(|conn| {
        let tx = conn.unchecked_transaction().map_err(sql_err)?;
        let mut out = Vec::with_capacity(ops.len());
        for (i, op) in ops.iter().enumerate() {
            let r = write(&tx, access, op).map_err(|e| match e {
                AppError::BadRequest(m) => AppError::bad(format!("op {i}: {m}")),
                AppError::NotFound(m) => AppError::not_found(format!("op {i}: {m}")),
                AppError::Forbidden(m) => AppError::forbidden(format!("op {i}: {m}")),
                e => e,
            })?;
            out.push(r);
        }
        tx.commit().map_err(sql_err)?;
        Ok(out)
    })
}

/// Run one write (in a transaction, so a multi-row insert is all or nothing).
pub fn write_one(c: &UserConn, access: &Access, op: WriteOp) -> AppResult<WriteResult> {
    c.guarded(|conn| {
        let tx = conn.unchecked_transaction().map_err(sql_err)?;
        let r = write(&tx, access, &op)?;
        tx.commit().map_err(sql_err)?;
        Ok(r)
    })
}

fn write(conn: &Connection, access: &Access, op: &WriteOp) -> AppResult<WriteResult> {
    match op {
        WriteOp::Insert(q) => insert(conn, access, q).map(WriteResult::Rows),
        WriteOp::Update(q) => {
            update(conn, access, q).map(|changes| WriteResult::Changes { changes })
        }
        WriteOp::Delete(q) => {
            delete(conn, access, q).map(|changes| WriteResult::Changes { changes })
        }
    }
}

fn insert(conn: &Connection, access: &Access, q: &Insert) -> AppResult<Rows> {
    let t = find(conn, &q.table, true)?;
    let owner = owner_filter(conn, &t, access, false)?;
    let returning = all_columns(&t);
    let mut out = Rows {
        columns: t.columns.iter().map(|c| c.name.clone()).collect(),
        rows: Vec::with_capacity(q.rows.len()),
        truncated: false,
    };
    for row in &q.rows {
        let mut names = Vec::with_capacity(row.len());
        let mut params = Vec::with_capacity(row.len());
        for (name, v) in row {
            check_not_owner(access, name)?;
            names.push(column(&t, name)?);
            params.push(value(name, v)?);
        }
        if let Some(o) = &owner {
            names.push(quote_ident(OWNER_COLUMN));
            params.push(Value::Text(o.clone()));
        }
        let sql = if names.is_empty() {
            format!("INSERT INTO {} DEFAULT VALUES", quote_ident(&t.name))
        } else {
            format!(
                "INSERT INTO {} ({}) VALUES ({})",
                quote_ident(&t.name),
                names.join(", "),
                vec!["?"; names.len()].join(", ")
            )
        };
        let st = conn
            .prepare(&format!("{sql} RETURNING {returning}"))
            .map_err(sql_err)?;
        out.rows
            .extend(run_prepared(conn, st, &params, false, usize::MAX)?.rows);
    }
    Ok(out)
}

fn update(conn: &Connection, access: &Access, q: &Update) -> AppResult<u64> {
    let t = find(conn, &q.table, true)?;
    let owner = owner_filter(conn, &t, access, false)?;
    if q.set.is_empty() {
        return Err(AppError::bad("nothing to set"));
    }
    let mut params = Vec::new();
    let mut sets = Vec::with_capacity(q.set.len());
    for (name, v) in &q.set {
        check_not_owner(access, name)?;
        sets.push(format!("{} = ?", column(&t, name)?));
        params.push(value(name, v)?);
    }
    let sql = format!(
        "UPDATE {} SET {}{}",
        quote_ident(&t.name),
        sets.join(", "),
        where_sql(&t, &q.filter, owner.as_deref(), &mut params)?
    );
    let st = conn.prepare(&sql).map_err(sql_err)?;
    Ok(run_prepared(conn, st, &params, false, 0)?.changes)
}

fn delete(conn: &Connection, access: &Access, q: &Delete) -> AppResult<u64> {
    let t = find(conn, &q.table, true)?;
    let owner = owner_filter(conn, &t, access, false)?;
    let mut params = Vec::new();
    let sql = format!(
        "DELETE FROM {}{}",
        quote_ident(&t.name),
        where_sql(&t, &q.filter, owner.as_deref(), &mut params)?
    );
    let st = conn.prepare(&sql).map_err(sql_err)?;
    Ok(run_prepared(conn, st, &params, false, 0)?.changes)
}

// ---- building SQL from checked names ----

/// The table (or, for reads, view) called `name`.
fn find(conn: &Connection, name: &str, writing: bool) -> AppResult<TableSchema> {
    let t = sql::table(conn, name)?
        .filter(|t| !is_internal(&t.name))
        .ok_or_else(|| AppError::not_found(format!("no table \"{name}\"")))?;
    if writing && t.kind != "table" {
        return Err(AppError::bad(format!(
            "\"{}\" is a {}; it can't be changed",
            t.name, t.kind
        )));
    }
    Ok(t)
}

/// The quoted name of a column of `t`.
fn column(t: &TableSchema, name: &str) -> AppResult<String> {
    t.columns
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))
        .map(|c| quote_ident(&c.name))
        .ok_or_else(|| AppError::bad(format!("table \"{}\" has no column \"{name}\"", t.name)))
}

fn all_columns(t: &TableSchema) -> String {
    t.columns
        .iter()
        .map(|c| quote_ident(&c.name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn value(column: &str, v: &Json) -> AppResult<Value> {
    json_to_sql(v).map_err(|e| AppError::bad(format!("column \"{column}\": {e}")))
}

fn to_i64(n: u64) -> AppResult<i64> {
    i64::try_from(n).map_err(|_| AppError::bad("limit and offset must fit in 64 bits"))
}

/// `{"$gte": 1}`-style conditions, as opposed to a value (`{"$base64": ...}` is a value).
fn is_ops(o: &Map<String, Json>) -> bool {
    !o.is_empty()
        && o.keys().all(|k| k.starts_with('$'))
        && !(o.len() == 1 && o.contains_key("$base64"))
}

/// The `WHERE` clause for `w`, limited to rows of `owner` if given.
fn where_sql(
    t: &TableSchema,
    w: &Where,
    owner: Option<&str>,
    params: &mut Vec<Value>,
) -> AppResult<String> {
    let mut terms = Vec::new();
    if let Some(o) = owner {
        terms.push(format!("{} = ?", quote_ident(OWNER_COLUMN)));
        params.push(Value::Text(o.to_string()));
    }
    for (name, cond) in w {
        let col = column(t, name)?;
        match cond {
            Json::Null => terms.push(format!("{col} IS NULL")),
            Json::Object(ops) if is_ops(ops) => {
                for (op, v) in ops {
                    let cmp = match op.as_str() {
                        "$in" => {
                            let Json::Array(items) = v else {
                                return Err(AppError::bad(format!(
                                    "where.{name}.$in must be an array"
                                )));
                            };
                            if items.is_empty() {
                                terms.push("0".into());
                            } else {
                                for item in items {
                                    params.push(value(name, item)?);
                                }
                                terms.push(format!(
                                    "{col} IN ({})",
                                    vec!["?"; items.len()].join(", ")
                                ));
                            }
                            continue;
                        }
                        "$ne" if v.is_null() => {
                            terms.push(format!("{col} IS NOT NULL"));
                            continue;
                        }
                        // Like JavaScript's !==, NULL counts as different from any value.
                        "$ne" => "IS NOT",
                        "$lt" => "<",
                        "$lte" => "<=",
                        "$gt" => ">",
                        "$gte" => ">=",
                        _ => {
                            return Err(AppError::bad(format!(
                                "unknown operator where.{name}.{op}"
                            )));
                        }
                    };
                    terms.push(format!("{col} {cmp} ?"));
                    params.push(value(name, v)?);
                }
            }
            v => {
                terms.push(format!("{col} = ?"));
                params.push(value(name, v)?);
            }
        }
    }
    Ok(if terms.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", terms.join(" AND "))
    })
}

fn order_sql(t: &TableSchema, items: &[String]) -> AppResult<String> {
    if items.is_empty() {
        return Ok(String::new());
    }
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        let mut words = item.split_whitespace();
        let (Some(name), dir, None) = (words.next(), words.next(), words.next()) else {
            return Err(AppError::bad(format!(
                "bad order_by \"{item}\"; use \"column\" or \"column desc\""
            )));
        };
        let dir = match dir.map(str::to_ascii_lowercase).as_deref() {
            None | Some("asc") => "ASC",
            Some("desc") => "DESC",
            _ => {
                return Err(AppError::bad(format!(
                    "bad order_by \"{item}\"; use \"column\" or \"column desc\""
                )));
            }
        };
        parts.push(format!("{} {dir}", column(t, name)?));
    }
    Ok(format!(" ORDER BY {}", parts.join(", ")))
}

// ---- migration ----

/// Create missing tables and add new columns so a database in the user's own files matches
/// `spec`. Refuses (with [`AppError::SchemaMismatch`]) anything that would change or drop
/// existing data. With `read_only`, succeeds only if nothing needs to change.
pub fn migrate(c: &UserConn, spec: &Migrate, read_only: bool) -> AppResult<Migrated> {
    let refuse = read_only.then(|| {
        "the database needs changing to match the app's tables, and the token lacks the db:write scope".to_string()
    });
    migrate_with(c, spec, false, refuse)
}

/// [`migrate`], for a user database or (`app`) an app database, whose tables also get an
/// `_owner` column and a sharing policy. With `refuse` set, succeeds only if nothing needs to
/// change, and otherwise fails with that message.
pub fn migrate_with(
    c: &UserConn,
    spec: &Migrate,
    app: bool,
    refuse: Option<String>,
) -> AppResult<Migrated> {
    check_spec(spec, app)?;
    let read_only = refuse.is_some();
    c.guarded(|conn| {
        // Take the write lock before reading the schema, so two clients migrating at once can't
        // both decide to add the same column.
        let tx = if read_only {
            None
        } else {
            Some(
                rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                    .map_err(sql_err)?,
            )
        };
        let existing = sql::schema(conn)?;
        let applied = if app {
            plan_app(conn, spec, &existing)?
        } else {
            plan(spec, &existing, false)?
        };
        if let Some(msg) = refuse.filter(|_| !applied.is_empty()) {
            return Err(AppError::forbidden(msg));
        }
        for s in &applied {
            conn.execute(s, []).map_err(sql_err)?;
        }
        if let Some(tx) = tx {
            tx.commit().map_err(sql_err)?;
        }
        Ok(Migrated { applied })
    })
}

/// Validate names in a spec, before touching the database.
fn check_spec(spec: &Migrate, app: bool) -> AppResult<()> {
    let mut seen = std::collections::HashSet::new();
    for t in &spec.tables {
        check_name("table", &t.name)?;
        if t.sharing.is_some() && !app {
            return Err(AppError::bad(format!(
                "table \"{}\": sharing only applies to app databases",
                t.name
            )));
        }
        if !seen.insert(t.name.to_ascii_lowercase()) {
            return Err(AppError::bad(format!(
                "table \"{}\" is declared twice",
                t.name
            )));
        }
        let mut cols = std::collections::HashSet::new();
        for c in &t.columns {
            check_name("column", &c.name)?;
            if c.name.eq_ignore_ascii_case("id") {
                return Err(AppError::bad(format!(
                    "table \"{}\": every table gets an \"id\" column automatically; don't declare one",
                    t.name
                )));
            }
            if app && c.name.eq_ignore_ascii_case(OWNER_COLUMN) {
                return Err(AppError::bad(format!(
                    "table \"{}\": every table in an app database gets an \"{OWNER_COLUMN}\" column automatically; don't declare one",
                    t.name
                )));
            }
            if !cols.insert(c.name.to_ascii_lowercase()) {
                return Err(AppError::bad(format!(
                    "table \"{}\": column \"{}\" is declared twice",
                    t.name, c.name
                )));
            }
            if c.default.as_ref().is_some_and(Json::is_null) && !c.nullable {
                return Err(AppError::bad(format!(
                    "table \"{}\": column \"{}\" isn't nullable, so its default can't be null",
                    t.name, c.name
                )));
            }
        }
    }
    Ok(())
}

fn check_name(kind: &str, name: &str) -> AppResult<()> {
    let mut chars = name.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(AppError::bad(format!(
            "{kind} name \"{name}\" must be letters, digits and underscores, not starting with a digit"
        )));
    }
    if name.to_ascii_lowercase().starts_with("sqlite_") {
        return Err(AppError::bad(format!(
            "{kind} name \"{name}\" is reserved by SQLite"
        )));
    }
    if is_internal(name) {
        return Err(AppError::bad(format!(
            "{kind} name \"{name}\" is reserved by bisonbase"
        )));
    }
    Ok(())
}

/// [`plan`] for an app database: tables also get an `_owner` column (with an index, since every
/// request filters on it), and their sharing policy is recorded in [`META_TABLE`].
fn plan_app(conn: &Connection, spec: &Migrate, existing: &[TableSchema]) -> AppResult<Vec<String>> {
    let mut out = plan(spec, existing, true)?;
    let meta = quote_ident(META_TABLE);
    let mut policies = Vec::new();
    for t in &spec.tables {
        let want = t.sharing.unwrap_or_default();
        let is_new = !existing
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&t.name));
        if is_new {
            out.push(format!(
                "CREATE INDEX {} ON {} ({})",
                quote_ident(&format!("{META_TABLE}_{}_owner", t.name)),
                quote_ident(&t.name),
                quote_ident(OWNER_COLUMN)
            ));
        }
        if is_new || sharing(conn, &t.name)? != want {
            policies.push(format!(
                "INSERT INTO {meta} (name, sharing) VALUES ({}, '{}') \
                 ON CONFLICT(name) DO UPDATE SET sharing = excluded.sharing",
                literal(&Value::Text(t.name.clone())),
                want.as_str()
            ));
        }
    }
    if !policies.is_empty() && sql::table(conn, META_TABLE)?.is_none() {
        out.push(format!(
            "CREATE TABLE {meta} (name TEXT PRIMARY KEY COLLATE NOCASE, sharing TEXT NOT NULL)"
        ));
    }
    out.extend(policies);
    Ok(out)
}

/// The statements that bring `existing` in line with `spec`. In an app database (`app`),
/// tables have an `_owner` column too.
fn plan(spec: &Migrate, existing: &[TableSchema], app: bool) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for t in &spec.tables {
        let fail = |msg: String| {
            Err(AppError::SchemaMismatch(format!(
                "table \"{}\": {msg}",
                t.name
            )))
        };
        let Some(found) = existing
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&t.name))
        else {
            let mut cols = vec!["\"id\" INTEGER PRIMARY KEY".to_string()];
            if app {
                cols.push(format!("{} TEXT NOT NULL", quote_ident(OWNER_COLUMN)));
            }
            for c in &t.columns {
                cols.push(column_def(c)?);
            }
            out.push(format!(
                "CREATE TABLE {} ({})",
                quote_ident(&t.name),
                cols.join(", ")
            ));
            continue;
        };
        if found.kind != "table" {
            return fail(format!("the database has a {} with this name", found.kind));
        }
        let have = |name: &str| -> Option<&ColumnSchema> {
            found
                .columns
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(name))
        };
        let id_ok = have("id").is_some_and(|c| c.pk && c.decl_type.eq_ignore_ascii_case("INTEGER"));
        if !id_ok {
            return fail(
                "it exists but has no \"id INTEGER PRIMARY KEY\" column, so it wasn't created by this API".into(),
            );
        }
        if found.columns.iter().filter(|c| c.pk).count() > 1 {
            return fail("it has a composite primary key".into());
        }
        if app && have(OWNER_COLUMN).is_none() {
            return fail(format!(
                "it exists but has no \"{OWNER_COLUMN}\" column, so it wasn't created by this API"
            ));
        }
        for c in &t.columns {
            let Some(h) = have(&c.name) else {
                if !c.nullable && c.default.is_none() {
                    return fail(format!(
                        "new column \"{}\" needs a default (or make it nullable) so existing rows get a value",
                        c.name
                    ));
                }
                out.push(format!(
                    "ALTER TABLE {} ADD COLUMN {}",
                    quote_ident(&t.name),
                    column_def(c)?
                ));
                continue;
            };
            if !h.decl_type.eq_ignore_ascii_case(c.kind.sql()) {
                let was = if h.decl_type.is_empty() {
                    "untyped"
                } else {
                    &h.decl_type
                };
                return fail(format!(
                    "column \"{}\" is {was} in the database but declared as {}; changing a column's type isn't supported",
                    c.name,
                    c.kind.sql().to_ascii_lowercase()
                ));
            }
            if h.not_null == c.nullable {
                let (was, now) = if h.not_null {
                    ("NOT NULL", "nullable")
                } else {
                    ("nullable", "not nullable")
                };
                return fail(format!(
                    "column \"{}\" is {was} in the database but declared {now}; changing that isn't supported",
                    c.name
                ));
            }
        }
        for h in &found.columns {
            let declared = h.name.eq_ignore_ascii_case("id")
                || (app && h.name.eq_ignore_ascii_case(OWNER_COLUMN))
                || t.columns
                    .iter()
                    .any(|c| c.name.eq_ignore_ascii_case(&h.name));
            if !declared {
                return fail(format!(
                    "column \"{}\" is in the database but not declared; removing columns isn't supported because it would lose data. Declare it again",
                    h.name
                ));
            }
        }
    }
    Ok(out)
}

fn column_def(c: &ColumnSpec) -> AppResult<String> {
    let mut s = format!("{} {}", quote_ident(&c.name), c.kind.sql());
    if !c.nullable {
        s += " NOT NULL";
    }
    if let Some(d) = &c.default {
        s += " DEFAULT ";
        s += &literal(&value(&c.name, d)?);
    }
    Ok(s)
}

/// A value as an SQL literal (DEFAULT clauses can't take parameters).
fn literal(v: &Value) -> String {
    match v {
        Value::Null => "NULL".into(),
        Value::Integer(i) => i.to_string(),
        // Debug keeps a decimal point or exponent, so the literal stays a REAL.
        Value::Real(f) => format!("{f:?}"),
        Value::Text(s) => format!("'{}'", s.replace('\'', "''")),
        Value::Blob(b) => format!("X'{}'", hex::encode(b)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::storage::sql::SqlLimits;

    fn open(dir: &tempfile::TempDir) -> UserConn {
        let path = dir.path().join("t.db");
        let limits = SqlLimits {
            timeout: Duration::from_millis(500),
            max_rows: 3,
            max_db_bytes: 1 << 20,
        };
        UserConn::open(&path, !path.exists(), limits).unwrap()
    }

    fn de<T: serde::de::DeserializeOwned>(v: Json) -> T {
        serde_json::from_value(v).unwrap()
    }

    fn todos() -> Migrate {
        de(json!({"tables": [{"name": "todos", "columns": [
            {"name": "content", "type": "text"},
            {"name": "done", "type": "boolean", "default": 0},
            {"name": "pic", "type": "blob", "nullable": true},
        ]}]}))
    }

    #[test]
    fn internal_names() {
        assert!(is_internal("_bisonbase_tables"));
        assert!(is_internal("_BisonBase"));
        assert!(!is_internal("_bison"));
        // Not on a character boundary at byte 10: no panic.
        assert!(!is_internal("ééééééé"));
    }

    #[test]
    fn crud() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(&dir);
        assert_eq!(migrate(&c, &todos(), false).unwrap().applied.len(), 1);
        assert!(migrate(&c, &todos(), false).unwrap().applied.is_empty());

        let r = write_one(
            &c,
            &Access::All,
            de(json!({"op": "insert", "table": "todos", "rows": [
                {"content": "a"},
                {"content": "b", "done": 1, "pic": {"$base64": "AAE="}},
                {"content": "c"},
                {"content": "d"},
            ]})),
        )
        .unwrap();
        let WriteResult::Rows(r) = r else { panic!() };
        assert_eq!(r.columns, ["id", "content", "done", "pic"]);
        assert_eq!(
            r.rows[1],
            [json!(2), json!("b"), json!(1), json!({"$base64": "AAE="})]
        );

        let sel = |q: Json| select(&c, &Access::All, &de(q)).unwrap();
        let r = sel(json!({"table": "TODOS", "where": {"done": 0}, "order_by": ["id desc"]}));
        let ids: Vec<_> = r.rows.iter().map(|r| r[0].clone()).collect();
        assert_eq!(ids, [json!(4), json!(3), json!(1)]);
        let r = sel(json!({"table": "todos", "where": {"id": {"$in": [1, 4]}, "pic": null}}));
        assert_eq!(r.rows.len(), 2);
        let r = sel(json!({"table": "todos", "where": {"pic": {"$ne": null}}}));
        assert_eq!(r.rows.len(), 1);
        let r = sel(
            json!({"table": "todos", "where": {"id": {"$gt": 1, "$lte": 3}}, "limit": 1, "offset": 1}),
        );
        assert_eq!(r.rows[0][0], json!(3));
        // The server's row limit is 3.
        let r = sel(json!({"table": "todos"}));
        assert!(r.truncated && r.rows.len() == 3);

        let r = write_one(
            &c,
            &Access::All,
            de(json!({"op": "update", "table": "todos", "where": {"done": 0}, "set": {"done": 1}})),
        );
        assert!(matches!(r, Ok(WriteResult::Changes { changes: 3 })));
        let r = write_one(
            &c,
            &Access::All,
            de(json!({"op": "delete", "table": "todos", "where": {"id": 1}})),
        );
        assert!(matches!(r, Ok(WriteResult::Changes { changes: 1 })));
    }

    #[test]
    fn names_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(&dir);
        migrate(&c, &todos(), false).unwrap();
        let bad = |q: Json| select(&c, &Access::All, &de(q)).unwrap_err();
        assert!(matches!(
            bad(json!({"table": "nope"})),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            bad(json!({"table": "sqlite_schema"})),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            bad(json!({"table": "todos", "where": {"x\" OR 1=1 --": 1}})),
            AppError::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({"table": "todos", "order_by": ["id; DROP TABLE todos"]})),
            AppError::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({"table": "todos", "where": {"id": {"$like": "%"}}})),
            AppError::BadRequest(_)
        ));
        // Unknown keys are refused rather than ignored, so a typo can't widen a query.
        assert!(
            serde_json::from_value::<Select>(json!({"table": "todos", "were": {"id": 1}})).is_err()
        );
        assert!(
            serde_json::from_value::<WriteOp>(json!({"op": "delete", "table": "todos"})).is_err()
        );
        assert!(
            serde_json::from_value::<WriteOp>(
                json!({"op": "delete", "table": "todos", "where": {}, "x": 1})
            )
            .is_err()
        );
    }

    #[test]
    fn transact_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(&dir);
        migrate(&c, &todos(), false).unwrap();
        let ops: Transact = de(json!({"ops": [
            {"op": "insert", "table": "todos", "rows": [{"content": "a"}]},
            {"op": "insert", "table": "todos", "rows": [{"content": null}]},
        ]}));
        let e = transact(&c, &Access::All, &ops.ops).unwrap_err();
        assert!(e.to_string().starts_with("op 1:"), "{e}");
        assert!(
            select(&c, &Access::All, &de(json!({"table": "todos"})))
                .unwrap()
                .rows
                .is_empty()
        );
    }

    #[test]
    fn migrations() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(&dir);
        migrate(&c, &todos(), false).unwrap();
        let spec =
            |cols: Json| -> Migrate { de(json!({"tables": [{"name": "todos", "columns": cols}]})) };
        let base = json!([
            {"name": "content", "type": "text"},
            {"name": "done", "type": "boolean", "default": 0},
            {"name": "pic", "type": "blob", "nullable": true},
        ]);
        let with = |extra: Json| {
            let mut v = base.clone();
            v.as_array_mut().unwrap().push(extra);
            spec(v)
        };
        // Adding a column needs write access, and a default or nullability.
        let add = with(json!({"name": "tags", "type": "json", "default": "[]"}));
        assert!(matches!(
            migrate(&c, &add, true),
            Err(AppError::Forbidden(_))
        ));
        assert_eq!(
            migrate(&c, &add, false).unwrap().applied,
            ["ALTER TABLE \"todos\" ADD COLUMN \"tags\" JSON NOT NULL DEFAULT '[]'"]
        );
        let e = migrate(&c, &with(json!({"name": "n", "type": "integer"})), false).unwrap_err();
        assert!(matches!(e, AppError::SchemaMismatch(_)), "{e}");
        // Columns can't change type or nullability, or disappear.
        let mut changed = base.clone();
        changed[0]["type"] = json!("integer");
        assert!(matches!(
            migrate(&c, &spec(changed), false),
            Err(AppError::SchemaMismatch(_))
        ));
        let mut changed = base.clone();
        changed[0]["nullable"] = json!(true);
        assert!(matches!(
            migrate(&c, &spec(changed), false),
            Err(AppError::SchemaMismatch(_))
        ));
        assert!(matches!(
            migrate(&c, &spec(base), false),
            Err(AppError::SchemaMismatch(_))
        ));
        // Bad names never reach SQL.
        let bad: Migrate =
            de(json!({"tables": [{"name": "x\"; DROP TABLE todos; --", "columns": []}]}));
        assert!(matches!(
            migrate(&c, &bad, false),
            Err(AppError::BadRequest(_))
        ));
        let r: Migrate = de(
            json!({"tables": [{"name": "r", "columns": [{"name": "x", "type": "real", "default": 1.0}]}]}),
        );
        assert_eq!(
            migrate(&c, &r, false).unwrap().applied,
            ["CREATE TABLE \"r\" (\"id\" INTEGER PRIMARY KEY, \"x\" REAL NOT NULL DEFAULT 1.0)"]
        );
    }
}
