//! Per-user SQLite databases: hardened connections and JSON query execution.
//!
//! Everything here is synchronous; callers run it on a blocking thread.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rusqlite::{
    Connection, ErrorCode, OpenFlags,
    config::DbConfig,
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
    types::{Value, ValueRef},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy)]
pub struct SqlLimits {
    pub timeout: Duration,
    pub max_rows: usize,
    /// Size cap for this database: the per-database limit or the user's remaining quota.
    pub max_db_bytes: u64,
}

/// PRAGMAs user SQL may run. Everything else (journal_mode, writable_schema, max_page_count,
/// mmap_size, ...) is denied.
const ALLOWED_PRAGMAS: &[&str] = &[
    "application_id",
    "collation_list",
    "data_version",
    "defer_foreign_keys",
    "foreign_key_check",
    "foreign_key_list",
    "foreign_keys",
    "freelist_count",
    "function_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "optimize",
    "page_count",
    "page_size",
    "pragma_list",
    "quick_check",
    "recursive_triggers",
    "table_info",
    "table_list",
    "table_xinfo",
    "user_version",
];

/// A connection to a user database with sandboxing applied.
pub struct UserConn {
    pub conn: Connection,
    deadline: Arc<AtomicU64>,
    epoch: Instant,
    limits: SqlLimits,
}

impl UserConn {
    /// Open an existing user database, or create a new one. Files users upload are untrusted, so
    /// an existing file must carry the SQLite header (an empty or text file would otherwise be
    /// silently turned into a database) and is opened with corruption checks enabled.
    pub fn open(path: &Path, create: bool, limits: SqlLimits) -> AppResult<Self> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if create {
            if path.exists() {
                return Err(AppError::Conflict(
                    "a file already exists at this path".into(),
                ));
            }
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        } else if !path.is_file() {
            return Err(AppError::not_found("database not found"));
        } else if !crate::storage::fs::is_sqlite_sync(path) {
            return Err(AppError::bad("not a SQLite database"));
        }
        // Note: no SQLITE_OPEN_URI, so file names are never interpreted as URIs.
        let conn = Connection::open_with_flags(path, flags)?;

        conn.busy_timeout(Duration::from_secs(5))?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
        conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, 64 << 20)?;
        conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 1 << 20)?;
        conn.pragma_update(None, "cell_size_check", true)?;
        conn.pragma_update(None, "mmap_size", 0)?;

        if create {
            let mode: String =
                conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
            tracing::debug!("journal_mode={mode}");
        }
        let page_size: u64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let max_pages = (limits.max_db_bytes / page_size.max(512)).max(1);
        conn.pragma_update_and_check(None, "max_page_count", max_pages as i64, |_| Ok(()))?;
        conn.pragma_update(None, "foreign_keys", true)?;

        // Installed last: our own setup pragmas above would otherwise be denied.
        conn.authorizer(Some(authorize));

        let deadline = Arc::new(AtomicU64::new(0));
        let epoch = Instant::now();
        let d = deadline.clone();
        conn.progress_handler(
            1000,
            Some(move || {
                let dl = d.load(Ordering::Relaxed);
                dl != 0 && epoch.elapsed().as_millis() as u64 > dl
            }),
        );
        Ok(Self {
            conn,
            deadline,
            epoch,
            limits,
        })
    }

    fn arm(&self) {
        let dl = self.epoch.elapsed() + self.limits.timeout;
        self.deadline
            .store(dl.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    fn disarm(&self) {
        self.deadline.store(0, Ordering::Relaxed);
    }

    pub fn query(&self, stmt: &Statement, read_only: bool) -> AppResult<QueryResult> {
        self.arm();
        let r = run(&self.conn, stmt, read_only, self.limits.max_rows);
        self.disarm();
        r
    }

    /// Run several statements in one transaction; all or nothing.
    pub fn batch(&mut self, stmts: &[Statement], read_only: bool) -> AppResult<Vec<QueryResult>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        self.arm();
        let max_rows = self.limits.max_rows;
        let r = (|| {
            let tx = self.conn.transaction().map_err(sql_err)?;
            let mut out = Vec::with_capacity(stmts.len());
            for (i, s) in stmts.iter().enumerate() {
                let res = run(&tx, s, read_only, max_rows).map_err(|e| match e {
                    AppError::BadRequest(m) => AppError::bad(format!("statement {i}: {m}")),
                    AppError::Forbidden(m) => AppError::forbidden(format!("statement {i}: {m}")),
                    e => e,
                })?;
                out.push(res);
                if tx.is_autocommit() {
                    return Err(AppError::bad(
                        "transaction control statements are not allowed in a batch",
                    ));
                }
            }
            tx.commit().map_err(sql_err)?;
            Ok(out)
        })();
        self.disarm();
        r
    }

    /// Web UI SQL console; see [`console`].
    pub fn console(&self, sql: &str, read_only: bool) -> AppResult<ConsoleOutcome> {
        self.guarded(|c| console(c, sql, read_only, self.limits.max_rows))
    }

    pub fn schema(&self) -> AppResult<Vec<TableSchema>> {
        schema(&self.conn)
    }

    /// Run `f` against the connection under this connection's time limit.
    pub fn guarded<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        self.arm();
        let r = f(&self.conn);
        self.disarm();
        r
    }

    pub fn max_rows(&self) -> usize {
        self.limits.max_rows
    }

    /// Write a consistent snapshot of the database to `dest`.
    pub fn snapshot_to(&self, dest: &Path) -> AppResult<()> {
        self.conn
            .backup(rusqlite::MAIN_DB, dest, None)
            .map_err(|e| AppError::Internal(e.into()))
    }
}

/// Web UI SQL console: runs each statement in turn (autocommit). Returns the last statement's
/// result if it produced columns, otherwise a summary for multi-statement scripts.
pub fn console(
    conn: &Connection,
    sql: &str,
    read_only: bool,
    max_rows: usize,
) -> AppResult<ConsoleOutcome> {
    let before = conn.total_changes();
    use rusqlite::fallible_iterator::FallibleIterator;
    let mut batch = rusqlite::Batch::new(conn, sql);
    let mut last = None;
    let mut count = 0;
    while let Some(st) = batch.next().map_err(sql_err)? {
        count += 1;
        last = Some(run_prepared(conn, st, &Params::None, read_only, max_rows)?);
    }
    match last {
        None => Err(AppError::bad("empty SQL")),
        Some(r) if count == 1 || !r.columns.is_empty() => Ok(ConsoleOutcome::Result(r)),
        Some(_) => Ok(ConsoleOutcome::Script {
            statements: count,
            changes: conn.total_changes() - before,
        }),
    }
}

/// Tables and views (excluding SQLite's internal ones) with their columns.
pub fn schema(conn: &Connection) -> AppResult<Vec<TableSchema>> {
    let mut st = conn.prepare(
        "SELECT s.name, s.type, s.sql, coalesce(l.wr, 0) FROM sqlite_schema s
         LEFT JOIN pragma_table_list l ON l.schema = 'main' AND l.name = s.name
         WHERE s.type IN ('table','view') AND s.name NOT LIKE 'sqlite_%' ORDER BY s.name",
    )?;
    let tables: Vec<(String, String, Option<String>, bool)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    // table_xinfo also lists generated columns (hidden 2/3), which `SELECT *` returns; hidden
    // virtual-table columns (1) are left out.
    let mut col_st = conn.prepare(
        "SELECT name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo(?1)
         WHERE hidden IN (0, 2, 3) ORDER BY cid",
    )?;
    let mut out = Vec::new();
    for (name, kind, sql, without_rowid) in tables {
        let columns = col_st
            .query_map([&name], |r| {
                let pk: i64 = r.get(4)?;
                let hidden: i64 = r.get(5)?;
                Ok(ColumnSchema {
                    name: r.get(0)?,
                    decl_type: r.get(1)?,
                    not_null: r.get(2)?,
                    default: r.get(3)?,
                    pk: pk > 0,
                    pk_order: pk,
                    generated: hidden != 0,
                })
            })?
            .collect::<Result<_, _>>()?;
        out.push(TableSchema {
            name,
            kind,
            sql,
            without_rowid,
            columns,
        });
    }
    Ok(out)
}

/// Run `f` on a trusted connection (system.db) with a time limit, so a slow query can't hold
/// the connection indefinitely.
pub fn with_deadline<T>(
    conn: &Connection,
    timeout: Duration,
    f: impl FnOnce(&Connection) -> AppResult<T>,
) -> AppResult<T> {
    let deadline = Instant::now() + timeout;
    conn.progress_handler(1000, Some(move || Instant::now() > deadline));
    let r = f(conn);
    conn.progress_handler(1000, None::<fn() -> bool>);
    r
}

/// PRAGMAs a read-only console on a trusted database may run (queries only, no assignments).
const READ_ONLY_PRAGMAS: &[&str] = &[
    "foreign_key_check",
    "foreign_key_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "page_count",
    "page_size",
    "quick_check",
    "table_info",
    "table_list",
    "table_xinfo",
    "user_version",
];

/// Run `f` with an authorizer that only allows reading. Used for the admin console on
/// system.db, which has no sandbox of its own.
pub fn read_only_guard<T>(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> AppResult<T>,
) -> AppResult<T> {
    conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => {
            Authorization::Allow
        }
        AuthAction::Function { function_name }
            if !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        AuthAction::Pragma {
            pragma_name,
            pragma_value: None,
        } if READ_ONLY_PRAGMAS.contains(&pragma_name.to_ascii_lowercase().as_str()) => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }));
    let r = f(conn);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    r
}

fn authorize(ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
        AuthAction::Pragma { pragma_name, .. } => {
            let name = pragma_name.to_ascii_lowercase();
            if ALLOWED_PRAGMAS.contains(&name.as_str()) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Statement {
    pub sql: String,
    #[serde(default)]
    pub params: Params,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
pub enum Params {
    #[default]
    None,
    Positional(Vec<Json>),
    Named(Map<String, Json>),
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Json>>,
    pub truncated: bool,
    pub changes: u64,
    pub last_insert_rowid: i64,
}

pub enum ConsoleOutcome {
    Result(QueryResult),
    Script { statements: usize, changes: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct TableSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub sql: Option<String>,
    #[serde(skip)]
    pub without_rowid: bool,
    pub columns: Vec<ColumnSchema>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColumnSchema {
    pub name: String,
    #[serde(rename = "type")]
    pub decl_type: String,
    pub not_null: bool,
    pub default: Option<String>,
    pub pk: bool,
    /// Position in the primary key (1-based), or 0.
    #[serde(skip)]
    pub pk_order: i64,
    /// A generated column; it can't be written.
    #[serde(skip)]
    pub generated: bool,
}

pub fn sql_err(e: rusqlite::Error) -> AppError {
    match &e {
        rusqlite::Error::SqliteFailure(f, msg) => {
            let msg = msg.clone().unwrap_or_else(|| f.to_string());
            match f.code {
                ErrorCode::OperationInterrupted => AppError::bad("query timed out"),
                ErrorCode::AuthorizationForStatementDenied => {
                    AppError::forbidden(format!("not authorized: {msg}"))
                }
                ErrorCode::DiskFull => {
                    AppError::QuotaExceeded("database size limit reached".into())
                }
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                    AppError::Conflict("database is busy".into())
                }
                ErrorCode::CannotOpen | ErrorCode::SystemIoFailure | ErrorCode::NotADatabase => {
                    AppError::Internal(e.into())
                }
                _ => AppError::bad(msg),
            }
        }
        rusqlite::Error::MultipleStatement => {
            AppError::bad("only one statement per query; use /batch for several")
        }
        rusqlite::Error::InvalidParameterCount(got, want) => {
            AppError::bad(format!("expected {want} parameters, got {got}"))
        }
        rusqlite::Error::InvalidParameterName(n) => AppError::bad(format!("unknown parameter {n}")),
        _ => AppError::bad(e.to_string()),
    }
}

pub fn json_to_sql(v: &Json) -> AppResult<Value> {
    Ok(match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Integer(*b as i64),
        Json::Number(n) => match n.as_i64() {
            Some(i) => Value::Integer(i),
            None => Value::Real(n.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(s) => Value::Text(s.clone()),
        Json::Object(o) if o.len() == 1 && o.contains_key("$base64") => {
            let s = o["$base64"]
                .as_str()
                .ok_or_else(|| AppError::bad("$base64 must be a string"))?;
            Value::Blob(
                B64.decode(s)
                    .map_err(|_| AppError::bad("invalid base64 in parameter"))?,
            )
        }
        _ => {
            return Err(AppError::bad(
                "parameters must be scalars or {\"$base64\": ...}",
            ));
        }
    })
}

pub fn sql_to_json(v: ValueRef<'_>) -> Json {
    match v {
        ValueRef::Null => Json::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => serde_json::Number::from_f64(f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        ValueRef::Text(t) => Json::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => json!({ "$base64": B64.encode(b) }),
    }
}

fn run(
    conn: &Connection,
    stmt: &Statement,
    read_only: bool,
    max_rows: usize,
) -> AppResult<QueryResult> {
    if stmt.sql.trim().is_empty() {
        return Err(AppError::bad("empty SQL"));
    }
    let st = conn.prepare(&stmt.sql).map_err(sql_err)?;
    run_prepared(conn, st, &stmt.params, read_only, max_rows)
}

fn run_prepared(
    conn: &Connection,
    mut st: rusqlite::Statement<'_>,
    params: &Params,
    read_only: bool,
    max_rows: usize,
) -> AppResult<QueryResult> {
    if read_only && !st.readonly() {
        return Err(AppError::forbidden("only read-only statements are allowed"));
    }
    match params {
        Params::None => {}
        Params::Positional(vals) => {
            if vals.len() != st.parameter_count() {
                return Err(AppError::bad(format!(
                    "expected {} parameters, got {}",
                    st.parameter_count(),
                    vals.len()
                )));
            }
            for (i, v) in vals.iter().enumerate() {
                st.raw_bind_parameter(i + 1, json_to_sql(v)?)
                    .map_err(sql_err)?;
            }
        }
        Params::Named(map) => {
            for (k, v) in map {
                let name = if k.starts_with([':', '@', '$']) {
                    k.clone()
                } else {
                    format!(":{k}")
                };
                let idx = st
                    .parameter_index(&name)
                    .map_err(sql_err)?
                    .ok_or_else(|| AppError::bad(format!("unknown parameter {name}")))?;
                st.raw_bind_parameter(idx, json_to_sql(v)?)
                    .map_err(sql_err)?;
            }
        }
    }
    let is_readonly = st.readonly();
    let columns: Vec<String> = st.column_names().into_iter().map(String::from).collect();
    let ncols = columns.len();
    let mut rows = Vec::new();
    let mut truncated = false;
    {
        let mut q = st.raw_query();
        while let Some(row) = q.next().map_err(sql_err)? {
            if rows.len() >= max_rows {
                truncated = true;
                break;
            }
            let mut r = Vec::with_capacity(ncols);
            for i in 0..ncols {
                r.push(sql_to_json(row.get_ref(i).map_err(sql_err)?));
            }
            rows.push(r);
        }
    }
    Ok(QueryResult {
        columns,
        rows,
        truncated,
        changes: if is_readonly { 0 } else { conn.changes() },
        last_insert_rowid: conn.last_insert_rowid(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SqlLimits {
        SqlLimits {
            timeout: Duration::from_millis(300),
            max_rows: 100,
            max_db_bytes: 1 << 20,
        }
    }

    fn s(sql: &str) -> Statement {
        Statement {
            sql: sql.into(),
            params: Params::None,
        }
    }

    #[test]
    fn crud_and_params() {
        let dir = tempfile::tempdir().unwrap();
        let c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        c.query(
            &s("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, data BLOB)"),
            false,
        )
        .unwrap();
        let ins: Statement = serde_json::from_value(json!({
            "sql": "INSERT INTO t(name, data) VALUES (?, ?)",
            "params": ["a", {"$base64": "AAEC"}]
        }))
        .unwrap();
        let r = c.query(&ins, false).unwrap();
        assert_eq!(r.changes, 1);
        assert_eq!(r.last_insert_rowid, 1);
        let sel: Statement = serde_json::from_value(json!({
            "sql": "SELECT id, name, data FROM t WHERE name = :n",
            "params": {"n": "a"}
        }))
        .unwrap();
        let r = c.query(&sel, true).unwrap();
        assert_eq!(r.columns, vec!["id", "name", "data"]);
        assert_eq!(
            r.rows[0],
            vec![json!(1), json!("a"), json!({"$base64": "AAEC"})]
        );
        assert!(matches!(
            c.query(&s("DELETE FROM t"), true),
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            c.query(&s("SELECT 1; SELECT 2"), false),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other.db");
        Connection::open(&other)
            .unwrap()
            .execute_batch("CREATE TABLE secret(x); INSERT INTO secret VALUES ('s');")
            .unwrap();
        let c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        let attach = format!("ATTACH DATABASE '{}' AS o", other.display());
        assert!(c.query(&s(&attach), false).is_err());
        assert!(c.query(&s("PRAGMA writable_schema = 1"), false).is_err());
        assert!(c.query(&s("PRAGMA journal_mode = DELETE"), false).is_err());
        assert!(
            c.query(&s("PRAGMA max_page_count = 999999999"), false)
                .is_err()
        );
        assert!(c.query(&s("SELECT load_extension('x')"), false).is_err());
        let vac = format!("VACUUM INTO '{}'", dir.path().join("copy.db").display());
        assert!(c.query(&s(&vac), false).is_err());
        assert!(!dir.path().join("copy.db").exists());
        // allowed introspection
        c.query(&s("PRAGMA table_list"), false).unwrap();
        c.query(&s("PRAGMA user_version = 3"), false).unwrap();
    }

    #[test]
    fn timeout_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        let slow = s(
            "WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r) SELECT count(*) FROM r",
        );
        let e = c.query(&slow, true).unwrap_err();
        assert!(e.to_string().contains("timed out"), "{e}");
        // connection still usable afterwards
        c.query(&s("SELECT 1"), true).unwrap();
        let many = s(
            "WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r LIMIT 500) SELECT i FROM r",
        );
        let r = c.query(&many, true).unwrap();
        assert_eq!(r.rows.len(), 100);
        assert!(r.truncated);
        // size limit (1 MiB)
        c.query(&s("CREATE TABLE big(b)"), false).unwrap();
        let e = c
            .query(&s("INSERT INTO big SELECT randomblob(2000000)"), false)
            .unwrap_err();
        assert!(matches!(e, AppError::QuotaExceeded(_)), "{e}");
    }

    #[test]
    fn batch_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        c.query(&s("CREATE TABLE t(x UNIQUE)"), false).unwrap();
        let r = c.batch(
            &[s("INSERT INTO t VALUES (1)"), s("INSERT INTO t VALUES (1)")],
            false,
        );
        assert!(r.is_err());
        let r = c.query(&s("SELECT count(*) FROM t"), true).unwrap();
        assert_eq!(r.rows[0][0], json!(0));
        assert!(
            c.batch(&[s("INSERT INTO t VALUES (2)"), s("COMMIT")], false)
                .is_err()
        );
    }
}
