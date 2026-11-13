use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::json;
use tokio_util::io::ReaderStream;

use super::db;
use crate::{
    auth::ApiAuth,
    error::{AppError, AppResult},
    state::AppState,
    storage::fs::{Entry, SafePath, UserStore, etag, is_sqlite},
};

pub const PREFIX: &str = "/api/v1/files";

/// Extract the wildcard file path following `prefix` from the request URI.
pub fn wild_path(uri: &Uri, prefix: &str) -> AppResult<SafePath> {
    let raw = uri.path().strip_prefix(prefix).unwrap_or("");
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| AppError::bad("path is not valid UTF-8"))?;
    SafePath::parse(&decoded)
}

/// Headers that keep user content from executing in our origin.
pub fn content_safety_headers(h: &mut HeaderMap) {
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
}

/// Serve a file's bytes. `disposition` is e.g. `attachment` or `inline`.
pub async fn serve_file(
    store: &UserStore,
    p: &SafePath,
    entry: &Entry,
    req_headers: &HeaderMap,
    disposition: Option<&str>,
) -> AppResult<Response> {
    let tag = etag(entry);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&tag).expect("etag is ascii"),
    );
    content_safety_headers(&mut headers);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    if req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == tag))
    {
        return Ok((StatusCode::NOT_MODIFIED, headers).into_response());
    }
    let mime = mime_guess::from_path(p.name()).first_or_octet_stream();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.essence_str())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(entry.size));
    if let Some(d) = disposition {
        let encoded =
            percent_encoding::utf8_percent_encode(p.name(), percent_encoding::NON_ALPHANUMERIC);
        if let Ok(v) = HeaderValue::from_str(&format!("{d}; filename*=UTF-8''{encoded}")) {
            headers.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    let file = tokio::fs::File::open(store.resolve(p).await?).await?;
    Ok((headers, Body::from_stream(ReaderStream::new(file))).into_response())
}

#[derive(Deserialize)]
pub struct GetQuery {
    #[serde(default)]
    op: Option<String>,
}

pub async fn get(
    State(state): State<AppState>,
    auth: ApiAuth,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<GetQuery>,
) -> AppResult<Response> {
    let p = wild_path(&uri, PREFIX)?;
    auth.check_path(&p)?;
    match q.op.as_deref() {
        None => {}
        Some("schema") => return db::schema(&state, &auth, &p).await,
        Some("watch") => return db::watch(&state, &auth, &p).await,
        Some(other) => return Err(AppError::bad(format!("unknown op '{other}'"))),
    }
    auth.scopes.require(auth.scopes.files_read, "files:read")?;
    let store = state.store(auth.user.id);
    store.ensure().await?;
    let entry = store.stat(&p).await?;
    if entry.is_dir() {
        let entries = store.list(&p).await?;
        return Ok(Json(json!({ "path": p.to_string(), "entries": entries })).into_response());
    }
    if is_sqlite(&store.resolve(&p).await?).await {
        return db::snapshot_response(&state, &store, &p, None).await;
    }
    serve_file(&store, &p, &entry, &headers, None).await
}

pub async fn put(
    State(state): State<AppState>,
    auth: ApiAuth,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    auth.scopes
        .require(auth.scopes.files_write, "files:write")?;
    let p = wild_path(&uri, PREFIX)?;
    auth.check_path(&p)?;
    let store = state.store(auth.user.id);
    store.ensure().await?;

    let existing = store.stat(&p).await.ok();
    if let Some(cond) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        && cond.trim() == "*"
        && existing.is_some()
    {
        return Err(AppError::Conflict("file already exists".into()));
    }
    if let Some(cond) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
        let matches = existing
            .as_ref()
            .is_some_and(|e| cond.trim() == "*" || cond.split(',').any(|t| t.trim() == etag(e)));
        if !matches {
            return Ok((
                StatusCode::PRECONDITION_FAILED,
                Json(json!({
                    "error": {"code": "precondition_failed", "message": "file has changed"}
                })),
            )
                .into_response());
        }
    }

    let limits = &state.cfg.limits;
    let entry = store
        .write_stream(
            &p,
            body.into_data_stream(),
            limits.max_upload_bytes,
            limits.user_quota_bytes,
        )
        .await?;
    let status = if existing.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let tag = etag(&entry);
    Ok((status, [(header::ETAG, tag)], Json(entry)).into_response())
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    recursive: bool,
}

pub async fn delete(
    State(state): State<AppState>,
    auth: ApiAuth,
    uri: Uri,
    Query(q): Query<DeleteQuery>,
) -> AppResult<StatusCode> {
    auth.scopes
        .require(auth.scopes.files_write, "files:write")?;
    let p = wild_path(&uri, PREFIX)?;
    auth.check_path(&p)?;
    state.store(auth.user.id).delete(&p, q.recursive).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PostQuery {
    op: String,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    overwrite: bool,
}

pub async fn post(
    State(state): State<AppState>,
    auth: ApiAuth,
    uri: Uri,
    Query(q): Query<PostQuery>,
    body: Bytes,
) -> AppResult<Response> {
    let p = wild_path(&uri, PREFIX)?;
    auth.check_path(&p)?;
    match q.op.as_str() {
        "mkdb" => return db::mkdb(&state, &auth, &p).await,
        "select" => return db::select(&state, &auth, &p, &body).await,
        op @ ("insert" | "update" | "delete") => {
            return db::write(&state, &auth, &p, op, &body).await;
        }
        "transact" => return db::transact(&state, &auth, &p, &body).await,
        "migrate" => return db::migrate(&state, &auth, &p, &body).await,
        _ => {}
    }
    auth.scopes
        .require(auth.scopes.files_write, "files:write")?;
    let store = state.store(auth.user.id);
    store.ensure().await?;
    match q.op.as_str() {
        "mkdir" => {
            store.mkdir(&p).await?;
            Ok((StatusCode::CREATED, Json(store.stat(&p).await?)).into_response())
        }
        "move" => {
            let to = SafePath::parse(
                q.to.as_deref()
                    .ok_or_else(|| AppError::bad("missing 'to'"))?,
            )?;
            auth.check_path(&to)?;
            store.rename(&p, &to, q.overwrite).await?;
            Ok(Json(store.stat(&to).await?).into_response())
        }
        other => Err(AppError::bad(format!("unknown op '{other}'"))),
    }
}
