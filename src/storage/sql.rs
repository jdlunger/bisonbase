//! Per-user SQLite databases: hardened connections and JSON query execution.
//!
//! Everything here is synchronous; callers run it on a blocking thread.

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc, Mutex,
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
use serde::Serialize;
use serde_json::{Value as Json, json};

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
    writes: Arc<Mutex<Writes>>,
    start_changes: u64,
}

/// What statements prepared on a connection may have written, as the authorizer saw them.
#[derive(Debug, Default)]
struct Writes {
    tables: BTreeSet<String>,
    /// Some statement changed the schema (tables, views, indexes or triggers).
    schema: bool,
}

/// What a connection changed, for change notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// Rows in these tables.
    Tables(Vec<String>),
    /// The schema, or something too broad to list.
    Everything,
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

        // Installed last: our own setup pragmas above would otherwise be denied. It also notes
        // which tables statements write, so watchers can be told what changed.
        let writes = Arc::new(Mutex::new(Writes::default()));
        let w = writes.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            let verdict = authorize(ctx);
            if verdict == Authorization::Allow {
                note_write(&w, ctx);
            }
            verdict
        }));

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
        let start_changes = conn.total_changes();
        Ok(Self {
            conn,
            deadline,
            epoch,
            limits,
            writes,
            start_changes,
        })
    }

    /// What this connection has changed since it was opened, if anything.
    pub fn changed(&self) -> Option<Changed> {
        let w = self.writes.lock().unwrap_or_else(|p| p.into_inner());
        if w.schema {
            Some(Changed::Everything)
        } else if self.conn.total_changes() != self.start_changes && !w.tables.is_empty() {
            Some(Changed::Tables(w.tables.iter().cloned().collect()))
        } else {
            None
        }
    }

    fn arm(&self) {
        let dl = self.epoch.elapsed() + self.limits.timeout;
        self.deadline
            .store(dl.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    fn disarm(&self) {
        self.deadline.store(0, Ordering::Relaxed);
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
        last = Some(run_prepared(conn, st, &[], read_only, max_rows)?);
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
    tables(conn, None)
}

/// The table or view called `name` (compared case-insensitively, as SQLite does), if any.
pub fn table(conn: &Connection, name: &str) -> AppResult<Option<TableSchema>> {
    Ok(tables(conn, Some(name))?.pop())
}

fn tables(conn: &Connection, only: Option<&str>) -> AppResult<Vec<TableSchema>> {
    let mut st = conn.prepare(
        "SELECT s.name, s.type, s.sql, coalesce(l.wr, 0) FROM sqlite_schema s
         LEFT JOIN pragma_table_list l ON l.schema = 'main' AND l.name = s.name
         WHERE s.type IN ('table','view') AND s.name NOT LIKE 'sqlite_%'
           AND (?1 IS NULL OR s.name = ?1 COLLATE NOCASE)
         ORDER BY s.name",
    )?;
    let tables: Vec<(String, String, Option<String>, bool)> = st
        .query_map([only], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
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

/// Record what an allowed statement writes in the main database.
fn note_write(w: &Mutex<Writes>, ctx: AuthContext<'_>) {
    if ctx.database_name.is_some_and(|d| d != "main") {
        return;
    }
    let mut w = w.lock().unwrap_or_else(|p| p.into_inner());
    match ctx.action {
        AuthAction::Insert { table_name }
        | AuthAction::Update { table_name, .. }
        | AuthAction::Delete { table_name } => {
            if !table_name.starts_with("sqlite_") {
                w.tables.insert(table_name.to_string());
            }
        }
        AuthAction::CreateTable { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::AlterTable { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::DropView { .. }
        | AuthAction::CreateIndex { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropVtable { .. } => w.schema = true,
        _ => {}
    }
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
        rusqlite::Error::MultipleStatement => AppError::bad("only one statement is allowed"),
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

/// Bind `params` to a prepared statement, run it and collect up to `max_rows` rows.
pub(crate) fn run_prepared(
    conn: &Connection,
    mut st: rusqlite::Statement<'_>,
    params: &[Value],
    read_only: bool,
    max_rows: usize,
) -> AppResult<QueryResult> {
    if read_only && !st.readonly() {
        return Err(AppError::forbidden("only read-only statements are allowed"));
    }
    if params.len() != st.parameter_count() {
        return Err(AppError::bad(format!(
            "expected {} parameters, got {}",
            st.parameter_count(),
            params.len()
        )));
    }
    for (i, v) in params.iter().enumerate() {
        st.raw_bind_parameter(i + 1, v).map_err(sql_err)?;
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

    /// Run one statement as the web console would, returning its rows.
    fn run(c: &UserConn, sql: &str, read_only: bool) -> AppResult<QueryResult> {
        match c.console(sql, read_only)? {
            ConsoleOutcome::Result(r) => Ok(r),
            ConsoleOutcome::Script { .. } => panic!("expected one statement"),
        }
    }

    #[test]
    fn crud_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        run(
            &c,
            "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, data BLOB)",
            false,
        )
        .unwrap();
        let st = c
            .conn
            .prepare("INSERT INTO t(name, data) VALUES (?, ?)")
            .unwrap();
        let params = [
            json_to_sql(&json!("a")).unwrap(),
            json_to_sql(&json!({"$base64": "AAEC"})).unwrap(),
        ];
        let r = run_prepared(&c.conn, st, &params, false, 100).unwrap();
        assert_eq!((r.changes, r.last_insert_rowid), (1, 1));
        let r = run(&c, "SELECT id, name, data FROM t", true).unwrap();
        assert_eq!(r.columns, vec!["id", "name", "data"]);
        assert_eq!(
            r.rows[0],
            vec![json!(1), json!("a"), json!({"$base64": "AAEC"})]
        );
        assert!(matches!(
            run(&c, "DELETE FROM t", true),
            Err(AppError::Forbidden(_))
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
        assert!(run(&c, &attach, false).is_err());
        assert!(run(&c, "PRAGMA writable_schema = 1", false).is_err());
        assert!(run(&c, "PRAGMA journal_mode = DELETE", false).is_err());
        assert!(run(&c, "PRAGMA max_page_count = 999999999", false).is_err());
        assert!(run(&c, "SELECT load_extension('x')", false).is_err());
        let vac = format!("VACUUM INTO '{}'", dir.path().join("copy.db").display());
        assert!(run(&c, &vac, false).is_err());
        assert!(!dir.path().join("copy.db").exists());
        // allowed introspection
        run(&c, "PRAGMA table_list", false).unwrap();
        run(&c, "PRAGMA user_version = 3", false).unwrap();
    }

    #[test]
    fn timeout_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let c = UserConn::open(&dir.path().join("t.db"), true, limits()).unwrap();
        let slow =
            "WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r) SELECT count(*) FROM r";
        let e = run(&c, slow, true).unwrap_err();
        assert!(e.to_string().contains("timed out"), "{e}");
        // connection still usable afterwards
        run(&c, "SELECT 1", true).unwrap();
        let many = "WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r LIMIT 500) SELECT i FROM r";
        let r = run(&c, many, true).unwrap();
        assert_eq!(r.rows.len(), 100);
        assert!(r.truncated);
        // size limit (1 MiB)
        run(&c, "CREATE TABLE big(b)", false).unwrap();
        let e = run(&c, "INSERT INTO big SELECT randomblob(2000000)", false).unwrap_err();
        assert!(matches!(e, AppError::QuotaExceeded(_)), "{e}");
    }

    #[test]
    fn tracks_what_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let open = || UserConn::open(&path, false, limits()).unwrap();
        let c = UserConn::open(&path, true, limits()).unwrap();
        assert_eq!(c.changed(), None);
        run(&c, "CREATE TABLE a(x)", false).unwrap();
        assert_eq!(c.changed(), Some(Changed::Everything));
        drop(c);
        let c = open();
        c.console(
            "CREATE TABLE b(x); CREATE TABLE log(t);
                   CREATE TRIGGER tr AFTER INSERT ON a BEGIN INSERT INTO log VALUES ('a'); END;",
            false,
        )
        .unwrap();
        drop(c);

        // Reads and writes that touch no rows change nothing.
        let c = open();
        run(&c, "SELECT * FROM a", true).unwrap();
        run(&c, "DELETE FROM b WHERE x = 1", false).unwrap();
        assert_eq!(c.changed(), None);

        // A trigger's writes count; so does a truncating DELETE (no update hook fires for it).
        let c = open();
        run(&c, "INSERT INTO a VALUES (1)", false).unwrap();
        assert_eq!(
            c.changed(),
            Some(Changed::Tables(vec!["a".into(), "log".into()]))
        );
        let c = open();
        run(&c, "DELETE FROM a", false).unwrap();
        assert_eq!(c.changed(), Some(Changed::Tables(vec!["a".into()])));

        // Temp tables aren't in the database.
        let c = open();
        c.console(
            "CREATE TEMP TABLE tmp(x); INSERT INTO tmp VALUES (1)",
            false,
        )
        .unwrap();
        assert_eq!(c.changed(), None);
    }
}
