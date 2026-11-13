//! SQLite databases stored as files in the user's tree. Dispatched from the files API via `?op=`.
//!
//! Apps read and write them through the relational API (`select`, `insert`, `update`, `delete`,
//! `transact`, `migrate`) and follow changes with `watch`; no SQL text is accepted. Every path is
//! resolved inside the requesting user's own tree or, for app databases, inside a registered
//! app's own storage, where requests only reach rows the user owns (see [`rel::Access`]).

use std::{convert::Infallible, time::Duration};

use axum::{
    Json,
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio_util::io::ReaderStream;

use crate::{
    auth::ApiAuth,
    error::{AppError, AppResult},
    state::AppState,
    storage::{
        fs::DbChange,
        fs::{SafePath, UserStore, is_sqlite},
        rel::{self, Access},
        sql::{Changed, TableSchema, UserConn},
    },
};

use super::{files::content_safety_headers, target::Target};

// ---- operations shared by the API and the web UI ----

/// Create an empty database at `p`. Returns `false` if a database already exists there.
pub async fn create_db(state: &AppState, store: &UserStore, p: &SafePath) -> AppResult<bool> {
    if p.is_root() {
        return Err(AppError::bad("a database needs a file name"));
    }
    store.ensure().await?;
    let path = store.resolve(p).await?;
    if store.usage().await? >= store.quota {
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
    store.notify(p, None);
    Ok(true)
}

/// Open the database at `p` on a blocking thread and run `f` with it. Holds the user's storage
/// lock shared, so the file can't be replaced, moved or deleted while it is open. Afterwards,
/// tells anyone watching the database what changed.
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
    let remaining = store.quota.saturating_sub(store.usage().await?);
    sl.max_db_bytes = sl.max_db_bytes.min(size + remaining);
    let guard = store.lock.clone().read_owned().await;
    let cache = store.usage_cache.clone();
    let (r, changed) = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        // Only writes change the user's usage, so keep the cached total unless the database or
        // its WAL changed size.
        let before = db_disk_size(&path);
        let mut changed = None;
        let r = UserConn::open(&path, false, sl).and_then(|mut conn| {
            let r = f(&mut conn);
            changed = conn.changed();
            r
        });
        if db_disk_size(&path) != before {
            cache.invalidate();
        }
        (r, changed)
    })
    .await?;
    // Even a failed call may have committed something (a console script stops at its first
    // error), so report changes either way.
    match changed {
        Some(Changed::Tables(t)) => store.notify(p, Some(t)),
        Some(Changed::Everything) => store.notify(p, None),
        None => {}
    }
    r
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

/// Create a database. In an app's storage only its owners may; others get the existing one.
pub async fn mkdb(state: &AppState, auth: &ApiAuth, t: &Target) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_write, "db:write")?;
    let (store, p) = (&t.store, &t.path);
    let exists = || async {
        let path = store.resolve(p).await?;
        AppResult::Ok(is_sqlite(&path).await)
    };
    let created = if !t.can_manage() && exists().await? {
        false
    } else {
        t.require_manage("create databases")?;
        create_db(state, store, p).await?
    };
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let entry = store.stat(p).await?;
    Ok((status, Json(json!({ "entry": entry, "created": created }))).into_response())
}

pub async fn schema(state: &AppState, auth: &ApiAuth, t: &Target) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_read, "db:read")?;
    let mut tables: Vec<TableSchema> = with_db(state, &t.store, &t.path, |c| c.schema()).await?;
    tables.retain(|t| !rel::is_internal(&t.name));
    Ok(Json(json!({ "tables": tables })).into_response())
}

/// Run `f` on the database the request names, after checking the token may read it.
async fn on_db<T, F>(state: &AppState, auth: &ApiAuth, t: &Target, f: F) -> AppResult<Response>
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce(&mut UserConn, &Access) -> AppResult<T> + Send + 'static,
{
    auth.scopes.require(auth.scopes.db_read, "db:read")?;
    let access = t.access();
    let r = with_db(state, &t.store, &t.path, move |c| f(c, &access)).await?;
    Ok(Json(r).into_response())
}

pub async fn select(
    state: &AppState,
    auth: &ApiAuth,
    t: &Target,
    body: &Bytes,
) -> AppResult<Response> {
    let q: rel::Select = parse_body(body)?;
    on_db(state, auth, t, move |c, a| rel::select(c, a, &q)).await
}

/// `insert`, `update` or `delete`, as named by `op`.
pub async fn write(
    state: &AppState,
    auth: &ApiAuth,
    t: &Target,
    op: &str,
    body: &Bytes,
) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_write, "db:write")?;
    // The op comes from the query string; the body holds the rest.
    let mut v: serde_json::Value = parse_body(body)?;
    let Some(obj) = v.as_object_mut() else {
        return Err(AppError::bad("body must be a JSON object"));
    };
    obj.insert("op".into(), op.into());
    let w: rel::WriteOp =
        serde_json::from_value(v).map_err(|e| AppError::bad(format!("invalid body: {e}")))?;
    on_db(state, auth, t, move |c, a| rel::write_one(c, a, w)).await
}

pub async fn transact(
    state: &AppState,
    auth: &ApiAuth,
    t: &Target,
    body: &Bytes,
) -> AppResult<Response> {
    auth.scopes.require(auth.scopes.db_write, "db:write")?;
    let tr: rel::Transact = parse_body(body)?;
    on_db(state, auth, t, move |c, a| {
        rel::transact(c, a, &tr.ops).map(|results| json!({ "results": results }))
    })
    .await
}

/// Bring tables in line with what the app declares. Anyone may check that nothing needs
/// changing; making changes needs db:write and, in an app's storage, being one of its owners.
pub async fn migrate(
    state: &AppState,
    auth: &ApiAuth,
    t: &Target,
    body: &Bytes,
) -> AppResult<Response> {
    let m: rel::Migrate = parse_body(body)?;
    let refuse = if !t.can_manage() {
        Some("the database needs changing to match the app's tables, and only the app's owners can change them".to_string())
    } else if !auth.scopes.db_write {
        Some("the database needs changing to match the app's tables, and the token lacks the db:write scope".to_string())
    } else {
        None
    };
    let app = t.app.is_some();
    on_db(state, auth, t, move |c, _| {
        rel::migrate_with(c, &m, app, refuse)
    })
    .await
}

// ---- change stream ----

/// How often an open change stream checks that its token is still valid.
const RECHECK_TOKEN: Duration = Duration::from_secs(60);

/// A server-sent event stream of changes at `p`. It starts with a `ready` event, then sends
/// `change` events. For a database, their data is `{"tables": [...]}`, or `{"tables": null}` when
/// anything may have changed (the file was replaced, the schema changed, or the stream fell
/// behind). For any other path (a folder, a plain file, or nothing yet), it is `{"path": ...}`:
/// a file or folder at, under or above `p` was written, created, moved or deleted (`null` when
/// the stream fell behind). Rows changing inside a database aren't reported to folder watchers.
/// The stream ends when the token stops working or the server shuts down; clients reconnect and
/// should treat `ready` as "reload everything".
pub async fn watch(state: &AppState, auth: &ApiAuth, t: &Target) -> AppResult<Response> {
    let (store, p) = (&t.store, &t.path);
    // Subscribe before checking, so no change between the check and the stream is missed.
    let rx = store.changes.subscribe();
    let db = is_sqlite(&store.resolve(p).await?).await;
    if db {
        auth.scopes.require(auth.scopes.db_read, "db:read")?;
    } else {
        auth.scopes.require(auth.scopes.files_read, "files:read")?;
    }
    struct Watch {
        rx: broadcast::Receiver<DbChange>,
        path: SafePath,
        db: bool,
        state: AppState,
        token: String,
        recheck: tokio::time::Interval,
        started: bool,
    }
    let w = Watch {
        rx,
        path: p.clone(),
        db,
        state: state.clone(),
        token: auth.token.clone(),
        recheck: tokio::time::interval_at(
            tokio::time::Instant::now() + RECHECK_TOKEN,
            RECHECK_TOKEN,
        ),
        started: false,
    };
    let change = |data: serde_json::Value| Event::default().event("change").data(data.to_string());
    let stream = futures_util::stream::unfold(w, move |mut w| async move {
        if !w.started {
            w.started = true;
            return Some((
                Ok::<_, Infallible>(Event::default().event("ready").data("{}")),
                w,
            ));
        }
        loop {
            tokio::select! {
                r = w.rx.recv() => match r {
                    Ok(c) if w.db && c.affects(&w.path) => {
                        return Some((Ok(change(json!({ "tables": c.tables.as_deref() }))), w));
                    }
                    Ok(c) if !w.db && c.tables.is_none()
                        && (c.path.starts_with(&w.path) || w.path.starts_with(&c.path)) => {
                        return Some((Ok(change(json!({ "path": c.path.to_string() }))), w));
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        let all = if w.db { json!({ "tables": null }) } else { json!({ "path": null }) };
                        return Some((Ok(change(all)), w));
                    }
                    Err(RecvError::Closed) => return None,
                },
                _ = w.recheck.tick() => {
                    if !matches!(w.state.sys.api_token_user(&w.token).await, Ok(Some(_))) {
                        return None;
                    }
                }
                _ = w.state.closing.cancelled() => return None,
            }
        }
    });
    let mut res = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    // Ask reverse proxies (nginx) not to buffer the stream.
    res.headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(res)
}
