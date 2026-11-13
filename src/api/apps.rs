//! `/api/v1/apps/<id>`: a registered app's details, and registering one.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::target::{app_for, client_origin};
use crate::{
    auth::ApiAuth,
    error::{AppError, AppResult},
    oauth::MAX_APP_NAME,
    state::AppState,
    system::RegisteredApp,
};

fn info(auth: &ApiAuth, app: &RegisteredApp, owner: bool) -> serde_json::Value {
    json!({
        "id": app.id,
        "name": app.name,
        "origin": app.origin,
        // Whether the user may create databases and change tables in the app's storage.
        "owner": owner,
        "user": { "id": auth.user.id, "username": auth.user.username },
    })
}

/// `GET /api/v1/apps/<id>`: the app, and what the signed-in user may do with its storage.
pub async fn get(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let a = app_for(&state, &auth, &id).await?;
    Ok(Json(info(&auth, &a.app, a.manage)).into_response())
}

#[derive(Deserialize)]
pub struct PostQuery {
    op: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Register {
    name: Option<String>,
    /// Needed unless the token is the app's own, whose origin is used.
    origin: Option<String>,
}

/// `POST /api/v1/apps/<id>?op=register`: give the app storage of its own (admins only). With the
/// app's own token, the app's origin is taken from the token.
pub async fn post(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(id): Path<String>,
    Query(q): Query<PostQuery>,
    body: Bytes,
) -> AppResult<Response> {
    if q.op != "register" {
        return Err(AppError::bad(format!("unknown op '{}'", q.op)));
    }
    let id = Uuid::parse_str(&id)
        .ok()
        .filter(|u| !u.is_nil())
        .ok_or_else(|| AppError::bad("the app id must be a UUID"))?;
    if !auth.user.is_admin {
        return Err(AppError::forbidden(
            "only an admin can register an app; ask one to sign in to it, or to register it under Admin",
        ));
    }
    if auth.app.is_some_and(|a| a != id) {
        return Err(AppError::forbidden(
            "an app's token can only register that app",
        ));
    }
    let r: Register = if body.is_empty() {
        Register::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AppError::bad(format!("invalid body: {e}")))?
    };
    let origin = match (&auth.client_id, r.origin) {
        (Some(client), _) => client_origin(client).ok_or_else(|| AppError::bad("bad client"))?,
        (None, Some(o)) => check_origin(&o)?,
        (None, None) => return Err(AppError::bad("origin is required")),
    };
    // Default to the name the user saw when signing in to the app.
    let name = match r.name {
        Some(n) => n,
        None => state
            .sys
            .app(auth.user.id, id)
            .await?
            .map(|a| a.name)
            .ok_or_else(|| AppError::bad("name is required"))?,
    };
    let name = check_name(&name)?;
    if let Some(existing) = state.sys.registered_app(id).await? {
        if existing.origin != origin {
            return Err(AppError::Conflict(
                "this app id is registered to another origin".into(),
            ));
        }
        return Ok(Json(info(&auth, &existing, true)).into_response());
    }
    let app = state
        .sys
        .create_registered_app(&auth.user, id, name, origin)
        .await?;
    Ok((StatusCode::CREATED, Json(info(&auth, &app, true))).into_response())
}

/// A valid app name, trimmed.
pub fn check_name(name: &str) -> AppResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_APP_NAME || name.chars().any(char::is_control)
    {
        return Err(AppError::bad(format!(
            "the name must be 1 to {MAX_APP_NAME} characters"
        )));
    }
    Ok(name.to_string())
}

/// An app's origin (`https://host[:port]`), normalized. Plain http only for loopback hosts.
pub fn check_origin(origin: &str) -> AppResult<String> {
    let bad = || AppError::bad("the origin must look like https://app.example.com");
    let u = url::Url::parse(origin.trim()).map_err(|_| bad())?;
    let host = u.host_str().ok_or_else(bad)?;
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host == "127.0.0.1"
        || host == "[::1]";
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(AppError::bad("apps must use https (or http on localhost)")),
    }
    if u.path() != "/" || u.query().is_some() || u.fragment().is_some() || !u.username().is_empty()
    {
        return Err(bad());
    }
    Ok(u.origin().ascii_serialization())
}

/// Delete a user's rows from every registered app's databases (when their account is deleted).
pub async fn purge_user(state: &AppState, user_id: Uuid) -> AppResult<()> {
    use crate::storage::{fs::SafePath, rel, rows::quote_ident, sql};
    for app in state.sys.registered_apps().await? {
        let store = state.app_store(app.id);
        let root = store.files_dir();
        let dbs = tokio::task::spawn_blocking(move || sqlite_files(&root)).await?;
        for rel_path in dbs {
            let p = SafePath::parse(&rel_path)?;
            let user = user_id.to_string();
            let r = crate::api::db::with_db(state, &store, &p, move |c| {
                c.guarded(|conn| {
                    for t in sql::schema(conn)? {
                        let owned = t.kind == "table"
                            && !rel::is_internal(&t.name)
                            && t.columns
                                .iter()
                                .any(|c| c.name.eq_ignore_ascii_case(rel::OWNER_COLUMN));
                        if owned {
                            conn.execute(
                                &format!(
                                    "DELETE FROM {} WHERE {} = ?1",
                                    quote_ident(&t.name),
                                    quote_ident(rel::OWNER_COLUMN)
                                ),
                                [&user],
                            )
                            .map_err(sql::sql_err)?;
                        }
                    }
                    Ok(())
                })
            })
            .await;
            if let Err(e) = r {
                tracing::warn!(app = %app.id, db = %rel_path, "removing a deleted user's rows failed: {e}");
            }
        }
    }
    Ok(())
}

/// Paths (relative to `root`, with `/`) of the SQLite databases under it.
fn sqlite_files(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if ft.is_dir() {
                stack.push((e.path(), rel));
            } else if ft.is_file() && crate::storage::fs::is_sqlite_sync(&e.path()) {
                out.push(rel);
            }
        }
    }
    out
}
