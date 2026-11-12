//! The browser UI: a React app (built from `ui/` and embedded in the binary) and the JSON
//! endpoints under `/ui/` it calls. Those use the session cookie, so they sit behind the CSRF
//! guard and are not open to other origins.

mod account;
mod db;
mod files;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};

use crate::{
    auth::{self, MaybeUser, SessionUser, passkey},
    error::AppError,
    state::AppState,
};

mod ui_files {
    include!(concat!(env!("OUT_DIR"), "/ui_files.rs"));
}

pub fn router(state: &AppState) -> Router<AppState> {
    let upload_limit = state.cfg.limits.max_upload_bytes as usize + (1 << 20);
    Router::new()
        // Pages: all the same app, which routes on the URL.
        .route("/", get(index))
        .route("/login", get(account::login_page))
        .route("/signup", get(public_page))
        .route("/recover", get(public_page))
        .route("/files", get(user_page))
        .route("/files/", get(user_page))
        .route("/files/{*path}", get(user_page))
        .route("/settings", get(user_page))
        .route("/admin", get(user_page))
        .route("/admin/db", get(user_page))
        .route("/admin/users/{id}/files", get(user_page))
        .route("/admin/users/{id}/files/", get(user_page))
        .route("/admin/users/{id}/files/{*path}", get(user_page))
        .route(
            "/oauth/authorize",
            get(user_page).post(crate::oauth::decide),
        )
        .route("/assets/{*file}", get(asset))
        // Downloads.
        .route("/raw/{*path}", get(files::raw))
        .route("/admin/users/{id}/raw/{*path}", get(files::admin_raw))
        // Passkeys.
        .route("/logout", post(passkey::logout))
        .route("/auth/register/start", post(passkey::register_start))
        .route("/auth/register/finish", post(passkey::register_finish))
        .route("/auth/login/start", post(passkey::login_start))
        .route("/auth/login/finish", post(passkey::login_finish))
        .route("/auth/recover/start", post(passkey::recover_start))
        .route("/auth/recover/finish", post(passkey::recover_finish))
        .route("/auth/passkeys/add/start", post(passkey::add_start))
        .route("/auth/passkeys/add/finish", post(passkey::add_finish))
        // JSON for the app.
        .route("/ui/session", get(account::session))
        .route("/ui/signup", get(account::signup_info))
        .route("/ui/recover", get(account::recover_info))
        .route("/ui/files", get(files::browse))
        .route(
            "/ui/upload",
            post(files::upload).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/ui/new", post(files::create))
        .route("/ui/save", post(files::save))
        .route("/ui/delete", post(files::delete))
        .route("/ui/rename", post(files::rename))
        .route("/ui/db", get(db::view))
        .route("/ui/db/row", get(db::row_form).post(db::edit_row))
        .route("/ui/db/sql", post(db::console))
        .route("/ui/sysdb", get(db::system_view))
        .route(
            "/ui/sysdb/row",
            get(db::system_row_form).post(db::system_edit_row),
        )
        .route("/ui/sysdb/sql", post(db::system_console))
        .route("/ui/settings", get(account::settings))
        .route("/ui/tokens/create", post(account::create_token))
        .route("/ui/tokens/delete", post(account::delete_token))
        .route("/ui/apps/disconnect", post(account::disconnect_app))
        .route("/ui/passkeys/delete", post(account::delete_passkey))
        .route("/ui/oauth/authorize", get(crate::oauth::consent))
        .route("/ui/admin", get(account::admin))
        .route("/ui/admin/signup", post(account::set_signup_mode))
        .route("/ui/admin/invites/create", post(account::create_invite))
        .route("/ui/admin/invites/delete", post(account::delete_invite))
        .route("/ui/admin/users/admin", post(account::set_user_admin))
        .route("/ui/admin/users/recover", post(account::create_recovery))
        .route("/ui/admin/users/delete", post(account::delete_user))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::csrf_guard,
        ))
}

async fn index(MaybeUser(u): MaybeUser) -> Redirect {
    if u.is_some() {
        Redirect::to("/files")
    } else {
        Redirect::to("/login")
    }
}

fn ui_file(path: &str) -> Option<&'static [u8]> {
    ui_files::FILES
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, b)| *b)
}

/// The app's HTML page. It is the same for every page; the app routes on the URL.
pub fn shell(status: StatusCode) -> Response {
    let html = ui_file("/index.html").unwrap_or_default();
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        html,
    )
        .into_response()
}

async fn public_page() -> Response {
    shell(StatusCode::OK)
}

/// A page for logged-in users; others are sent to the login page first.
async fn user_page(SessionUser(_): SessionUser) -> Response {
    shell(StatusCode::OK)
}

/// Vite's build output. File names contain a hash of their contents, so they never change.
async fn asset(req: Request) -> Response {
    let path = req.uri().path();
    let Some(body) = ui_file(path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref()).unwrap(),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        body,
    )
        .into_response()
}

/// Unknown URLs: JSON for API-like paths, otherwise the app (which shows "not found").
async fn not_found(req: Request) -> Response {
    let p = req.uri().path();
    if p.starts_with("/ui/") || p.starts_with("/api/") || p.starts_with("/auth/") {
        return AppError::not_found("not found").into_response();
    }
    match ui_file(p) {
        // Files Vite copies from `ui/public`, e.g. a favicon.
        Some(body) if p != "/index.html" => {
            let mime = mime_guess::from_path(p).first_or_octet_stream();
            (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime.as_ref()).unwrap(),
                )],
                body,
            )
                .into_response()
        }
        _ => shell(StatusCode::NOT_FOUND),
    }
}

/// A successful action with nothing to return.
pub fn ok() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "ok": true }))
}

pub type JsonResult<T> = Result<axum::Json<T>, AppError>;
