//! SQLite databases stored as files in the user's tree. Dispatched from the files API via `?op=`.

use axum::{
    Json,
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use tokio_util::io::ReaderStream;

use crate::{
    auth::ApiAuth,
    error::{AppError, AppResult},
    state::AppState,
    storage::{
        fs::{SafePath, UserStore, is_sqlite},
        sql::{QueryResult, Statement, TableSchema, UserConn},
    },
};

use super::files::content_safety_headers;

// ---- operations shared by the API and the web UI ----

/// Create an empty database at `p`. Returns `false` if a database already exists there.
pub async fn create_db(state: &AppState, store: &UserStore, p: &SafePath) -> AppResult<bool> {
    if p.is_root() {
        return Err(AppError::bad("a database needs a file name"));
    }
    store.ensure().await?;
    let path = store.resolve(p).await?;
    if store.usage().await? >= state.cfg.limits.user_quota_bytes {
        return Err(AppError::QuotaExceeded("storage quota exceeded".into()));
    }
    let _guard = store.lock.write().await;
    match tokio::fs::symlink_metadata(&path).await {
        Ok(m) if m.is_file() && is_sqlite(&path).await => return Ok(false),
        Ok(_) => {
            return Err(AppError::Conflict(
                "a non-database file or directory exists at this path".into(),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let sl = state.sql_limits();
    let r = tokio::task::spawn_blocking(move || UserConn::open(&path, true, sl).map(|_| ())).await;
    store.invalidate_usage();
    r??;
    Ok(true)
}

/// Open the database at `p` on a blocking thread and run `f` with it. Holds the user's storage
/// lock shared, so the file can't be replaced, moved or deleted while it is open.
pub async fn with_db<T, F>(state: &AppState, store: &UserStore, p: &SafePath, f: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut UserConn) -> AppResult<T> + Send + 'static,
{
    let path = store.resolve(p).await?;
    let mut sl = state.sql_limits();
    // A database may grow into whatever is left of the user's quota.
    let size = tokio::fs::metadata(&path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let remaining = state
        .cfg
        .limits
        .user_quota_bytes
        .saturating_sub(store.usage().await?);
    sl.max_db_bytes = sl.max_db_bytes.min(size + remaining);
    let guard = store.lock.clone().read_owned().await;
    let cache = store.usage_cache.clone();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        // Only writes change the user's usage, so keep the cached total unless the database or
        // its WAL changed size.
        let before = db_disk_size(&path);
        let r = UserConn::open(&path, false, sl).and_then(|mut conn| {
            let r = f(&mut conn);
            drop(conn);
            r
        });
        if db_disk_size(&path) != before {
            cache.invalidate();
        }
        r
    })
    .await?
}

/// Bytes of a database file plus its WAL (missing files count as 0).
fn db_disk_size(path: &std::path::Path) -> (u64, u64) {
    let len = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    (len(path), len(std::path::Path::new(&wal)))
}

/// Download a database as a consistent snapshot (its file may have uncheckpointed WAL data or be
/// mid-write, so the raw bytes aren't safe to serve).
pub async fn snapshot_response(
    state: &AppState,
    store: &UserStore,
    p: &SafePath,
    disposition: Option<&str>,
) -> AppResult<Response> {
    store.ensure().await?;
    let tmp = store
        .tmp_dir()
        .join(format!("export-{}", crate::system::random_token()));
    let t = tmp.clone();
    with_db(state, store, p, move |c| c.snapshot_to(&t)).await?;
    let file = tokio::fs::File::open(&tmp).await;
    // Unlink immediately; the open handle keeps the data readable until streaming ends.
    let _ = tokio::fs::remove_file(&tmp).await;
    let file = file?;
    let len = file.metadata().await?.len();
    let mut headers = axum::http::HeaderMap::new();
    content_safety_headers(&mut headers);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    if let Some(d) = disposition {
        let encoded =
            percent_encoding::utf8_percent_encode(p.name(), percent_encoding::NON_ALPHANUMERIC);
        if let Ok(v) = HeaderValue::from_str(&format!("{d}; filename*=UTF-8''{encoded}")) {
            headers.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    Ok((headers, Body::from_stream(ReaderStream::new(file))).into_response())
}

// ---- API ops ----

fn parse_body<T: DeserializeOwned>(body: &Bytes) -> AppResult<T> {
    serde_json::from_slice(body).map_err(|e| AppError::bad(format!("invalid JSON body: {e}")))
}

pub async fn mkdb(state: &AppState, auth: &ApiAuth, p: &SafePath) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_write, "db:write")?;
    let store = state.store(auth.user.id);
    let created = create_db(state, &store, p).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let entry = store.stat(p).await?;
    Ok((status, Json(json!({ "entry": entry, "created": created }))).into_response())
}

pub async fn schema(state: &AppState, auth: &ApiAuth, p: &SafePath) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_read, "db:read")?;
    let store = state.store(auth.user.id);
    let tables: Vec<TableSchema> = with_db(state, &store, p, |c| c.schema()).await?;
    Ok(Json(json!({ "tables": tables })).into_response())
}

pub async fn query(
    state: &AppState,
    auth: &ApiAuth,
    p: &SafePath,
    body: &Bytes,
) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_read, "db:read")?;
    let stmt: Statement = parse_body(body)?;
    let ro = !auth.scopes.db_write;
    let store = state.store(auth.user.id);
    let r: QueryResult = with_db(state, &store, p, move |c| c.query(&stmt, ro)).await?;
    Ok(Json(r).into_response())
}

#[derive(Deserialize)]
struct Batch {
    statements: Vec<Statement>,
}

pub async fn batch(
    state: &AppState,
    auth: &ApiAuth,
    p: &SafePath,
    body: &Bytes,
) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_read, "db:read")?;
    let b: Batch = parse_body(body)?;
    let ro = !auth.scopes.db_write;
    let store = state.store(auth.user.id);
    let results = with_db(state, &store, p, move |c| c.batch(&b.statements, ro)).await?;
    Ok(Json(json!({ "results": results })).into_response())
}
