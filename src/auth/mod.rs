//! Request authentication: session cookies (web UI) and bearer tokens (API).

pub mod passkey;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{Method, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::{error::AppError, state::AppState, storage::fs::SafePath, system::User};

pub const SESSION_COOKIE: &str = "wfs_session";
pub const SESSION_TTL_SECS: i64 = 30 * 24 * 3600;

pub fn session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.cfg.cookie_secure)
        .path("/")
        .max_age(time::Duration::seconds(SESSION_TTL_SECS))
        .build()
}

pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, "")).path("/").build()
}

async fn user_from_cookie(parts: &mut Parts, state: &AppState) -> Result<Option<User>, AppError> {
    let jar = CookieJar::from_headers(&parts.headers);
    match jar.get(SESSION_COOKIE) {
        Some(c) if !c.value().is_empty() => state.sys.session_user(c.value()).await,
        _ => Ok(None),
    }
}

/// Logged-in web UI user. Pages redirect to the login page otherwise; the app's JSON
/// endpoints (`/ui/...`) answer 401.
pub struct SessionUser(pub User);

/// Logged-in web UI user, if any.
pub struct MaybeUser(pub Option<User>);

/// Logged-in admin.
pub struct AdminUser(pub User);

pub enum SessionRejection {
    Login(String),
    Error(AppError),
}

impl IntoResponse for SessionRejection {
    fn into_response(self) -> Response {
        match self {
            SessionRejection::Login(next) => {
                let next = percent_encoding::utf8_percent_encode(
                    &next,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                Redirect::to(&format!("/login?next={next}")).into_response()
            }
            SessionRejection::Error(e) => e.into_response(),
        }
    }
}

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = SessionRejection;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        user_from_cookie(parts, state)
            .await
            .map(MaybeUser)
            .map_err(SessionRejection::Error)
    }
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = SessionRejection;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match user_from_cookie(parts, state)
            .await
            .map_err(SessionRejection::Error)?
        {
            Some(u) => Ok(SessionUser(u)),
            None if parts.uri.path().starts_with("/ui/") => {
                Err(SessionRejection::Error(AppError::Unauthorized))
            }
            None => {
                let next = if parts.method == Method::GET {
                    parts
                        .uri
                        .path_and_query()
                        .map(|p| p.to_string())
                        .unwrap_or_default()
                } else {
                    "/".into()
                };
                Err(SessionRejection::Login(next))
            }
        }
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = SessionRejection;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let SessionUser(u) = SessionUser::from_request_parts(parts, state).await?;
        if u.is_admin {
            Ok(AdminUser(u))
        } else {
            Err(SessionRejection::Error(AppError::forbidden("admins only")))
        }
    }
}

// ---- API tokens ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scopes {
    pub files_read: bool,
    pub files_write: bool,
    pub db_read: bool,
    pub db_write: bool,
}

pub const ALL_SCOPES: &[&str] = &["files:read", "files:write", "db:read", "db:write"];

impl Scopes {
    /// Parse a space-separated scope list. Write scopes imply the matching read scope.
    pub fn parse(s: &str) -> Self {
        let mut sc = Scopes::default();
        for part in s.split_whitespace() {
            match part {
                "files:read" => sc.files_read = true,
                "files:write" => {
                    sc.files_read = true;
                    sc.files_write = true;
                }
                "db:read" => sc.db_read = true,
                "db:write" => {
                    sc.db_read = true;
                    sc.db_write = true;
                }
                _ => {}
            }
        }
        sc
    }

    pub fn require(&self, ok: bool, name: &str) -> Result<(), AppError> {
        if ok {
            Ok(())
        } else {
            Err(AppError::forbidden(format!("token lacks the {name} scope")))
        }
    }
}

/// An API request authenticated with `Authorization: Bearer <token>`.
pub struct ApiAuth {
    pub user: User,
    pub scopes: Scopes,
    /// Set for tokens issued to an app through OAuth: they only reach `apps/<id>/`.
    pub app: Option<uuid::Uuid>,
    /// The bearer token itself, so long-lived responses can check it's still valid.
    pub token: String,
}

/// The folder an app's files live in: `apps/<id>`.
pub fn app_folder(app_id: uuid::Uuid) -> String {
    format!("apps/{app_id}")
}

/// The app whose folder `p` is in, if `p` is `apps/<uuid>` or below it.
pub fn app_of(p: &SafePath) -> Option<uuid::Uuid> {
    match p.components() {
        [apps, id, ..] if apps == "apps" => uuid::Uuid::parse_str(id)
            .ok()
            .filter(|u| u.to_string() == *id),
        _ => None,
    }
}

impl ApiAuth {
    /// Refuse paths outside the token's reach: app tokens only see their own folder.
    pub fn check_path(&self, p: &SafePath) -> Result<(), AppError> {
        match self.app {
            Some(app) if app_of(p) != Some(app) => Err(AppError::forbidden(format!(
                "this app can only use files in {}/",
                app_folder(app)
            ))),
            _ => Ok(()),
        }
    }
}

impl FromRequestParts<AppState> for ApiAuth {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
            })
            .map(str::trim)
            .ok_or(AppError::Unauthorized)?;
        let (user, scopes, app) = state
            .sys
            .api_token_user(token)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok(ApiAuth {
            user,
            scopes: Scopes::parse(&scopes),
            app,
            token: token.to_string(),
        })
    }
}

// ---- CSRF ----

/// Reject cross-site state-changing requests to cookie-authenticated routes.
pub async fn csrf_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe {
        let h = req.headers();
        let site = h.get("sec-fetch-site").and_then(|v| v.to_str().ok());
        let origin = h.get(header::ORIGIN).and_then(|v| v.to_str().ok());
        let ok = match (site, origin) {
            (Some("same-origin"), _) => true,
            (_, Some(o)) => o == state.cfg.origin,
            (Some(_), None) => false,
            // Neither header: not a modern browser, so no ambient-credential risk worth blocking.
            (None, None) => true,
        };
        if !ok {
            return (StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
        }
    }
    next.run(req).await
}
