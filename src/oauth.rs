//! OAuth 2.1 authorization code flow with PKCE, so browser apps can get an API token
//! without the user copying one around.
//!
//! Apps are public clients and need no registration: an app's `client_id` is its URL
//! (e.g. `https://todo.example.com`), and its `redirect_uri` must be on the same origin,
//! so a code can only ever be delivered to the app the user approved. `https` is
//! required except for loopback hosts. Tokens issued here are ordinary API tokens tied
//! to the app; users see and disconnect apps under Settings.
//!
//! Each app also names itself (`app_name`) and picks a UUID (`app_id`). Its tokens only
//! reach the folder `apps/<app_id>/` in the user's files, which the UI labels with the
//! name. The first origin to use an id for a user owns it; other origins can't claim it.

use std::collections::HashMap;

use axum::{
    Form, Json,
    extract::{Query, State, rejection::FormRejection},
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    auth::{ALL_SCOPES, Scopes, SessionUser},
    error::AppError,
    state::AppState,
    system::now,
};

/// How long an authorization code can be exchanged for.
pub const CODE_TTL_SECS: i64 = 60;
/// How long an app's access token lasts. Apps send the user through the flow again after.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

/// Authorization request parameters, from the query string (GET) or the consent form (POST).
#[derive(Debug, Default, Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    /// The app's own UUID; its files go in `apps/<app_id>/`.
    app_id: Option<String>,
    /// What to call the app, e.g. "Todo".
    app_name: Option<String>,
    /// Only on the consent form: "allow" or anything else.
    decision: Option<String>,
}

/// A request that passed validation.
struct Authorization {
    client_id: String,
    /// `scheme://host[:port]` of the app, shown to the user.
    origin: String,
    redirect_uri: Url,
    scopes: String,
    state: Option<String>,
    code_challenge: String,
    app_id: uuid::Uuid,
    app_name: String,
}

/// Longest app name, in characters.
pub const MAX_APP_NAME: usize = 60;

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// Check `client_id` and `redirect_uri`. Until these pass, errors are shown to the user
/// rather than sent to the redirect URI, which can't be trusted yet.
fn check_client(
    client_id: Option<&str>,
    redirect_uri: Option<&str>,
) -> Result<(String, Url), String> {
    let client_id = client_id
        .filter(|s| !s.is_empty())
        .ok_or("client_id is missing")?;
    let redirect_uri = redirect_uri
        .filter(|s| !s.is_empty())
        .ok_or("redirect_uri is missing")?;
    let client = Url::parse(client_id).map_err(|_| "client_id must be the app's URL")?;
    let redirect = Url::parse(redirect_uri).map_err(|_| "redirect_uri is not a valid URL")?;
    for u in [&client, &redirect] {
        let host = u.host_str().unwrap_or("");
        match u.scheme() {
            "https" => {}
            "http" if is_loopback(host) => {}
            _ => return Err("apps must use https (or http on localhost)".into()),
        }
        if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
            return Err(
                "client_id and redirect_uri can't contain credentials or a fragment".into(),
            );
        }
    }
    if client.origin() != redirect.origin() {
        return Err("redirect_uri must be on the same origin as client_id".into());
    }
    Ok((client.origin().ascii_serialization(), redirect))
}

/// Normalize a requested scope list, or `None` if it's empty or has unknown scopes.
fn check_scopes(scope: &str) -> Option<String> {
    let requested: Vec<&str> = scope.split_whitespace().collect();
    if requested.is_empty() || requested.iter().any(|s| !ALL_SCOPES.contains(s)) {
        return None;
    }
    let scopes: Vec<&str> = ALL_SCOPES
        .iter()
        .copied()
        .filter(|s| requested.contains(s))
        .collect();
    Some(scopes.join(" "))
}

/// Why an authorization request can't go ahead.
enum Rejection {
    /// Not even the app's address is usable, so tell the user.
    Invalid(AppError),
    /// Send the user back to the app with an error, per RFC 6749 §4.1.2.1.
    Redirect(Url),
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        match self {
            Rejection::Invalid(e) => e.into_response(),
            Rejection::Redirect(u) => Redirect::to(u.as_str()).into_response(),
        }
    }
}

impl From<AppError> for Rejection {
    fn from(e: AppError) -> Self {
        Rejection::Invalid(e)
    }
}

fn error_redirect(
    state: &AppState,
    redirect_uri: &Url,
    app_state: Option<&str>,
    error: &str,
    description: &str,
) -> Rejection {
    let mut url = redirect_uri.clone();
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("error", error);
        q.append_pair("error_description", description);
        if let Some(s) = app_state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", &state.cfg.origin);
    }
    Rejection::Redirect(url)
}

fn validate(state: &AppState, p: &AuthorizeParams) -> Result<Authorization, Rejection> {
    let (origin, redirect_uri) = check_client(p.client_id.as_deref(), p.redirect_uri.as_deref())
        .map_err(|e| AppError::bad(format!("This app sent an invalid sign-in request: {e}.")))?;
    let app_state = p.state.as_deref();
    let fail = |error: &str, description: &str| {
        error_redirect(state, &redirect_uri, app_state, error, description)
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(fail(
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err(fail(
            "invalid_request",
            "PKCE is required: code_challenge_method must be S256",
        ));
    }
    let code_challenge = p.code_challenge.clone().unwrap_or_default();
    let b64url = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !(43..=128).contains(&code_challenge.len()) || !b64url(&code_challenge) {
        return Err(fail(
            "invalid_request",
            "code_challenge is missing or malformed",
        ));
    }
    let Some(scopes) = check_scopes(p.scope.as_deref().unwrap_or("")) else {
        return Err(fail(
            "invalid_scope",
            &format!("scope must be one or more of: {}", ALL_SCOPES.join(" ")),
        ));
    };
    let Some(app_id) = p
        .app_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok())
        .filter(|u| !u.is_nil())
    else {
        return Err(fail(
            "invalid_request",
            "app_id must be a UUID that identifies the app",
        ));
    };
    let app_name = p.app_name.as_deref().unwrap_or("").trim().to_string();
    if app_name.is_empty()
        || app_name.chars().count() > MAX_APP_NAME
        || app_name.chars().any(char::is_control)
    {
        return Err(fail(
            "invalid_request",
            &format!("app_name must be 1 to {MAX_APP_NAME} characters"),
        ));
    }
    Ok(Authorization {
        app_id,
        app_name,
        client_id: p.client_id.clone().unwrap_or_default(),
        origin,
        redirect_uri,
        scopes,
        state: p.state.clone(),
        code_challenge,
    })
}

/// What a set of scopes lets an app do in its folder, in words.
pub fn describe_scopes(scopes: &str) -> Vec<&'static str> {
    let s = Scopes::parse(scopes);
    let mut out = Vec::new();
    if s.files_write {
        out.push("See, add, change and delete files in its folder, databases included");
    } else if s.files_read {
        out.push("See and download files in its folder, databases included");
    }
    if s.db_write {
        out.push("Create databases in its folder, and read and change them");
    } else if s.db_read {
        out.push("Read databases in its folder");
    }
    out
}

/// A hue (0-359) for an app's label, the same everywhere the app shows up.
pub fn app_hue(app_id: uuid::Uuid) -> u16 {
    let b = app_id.as_bytes();
    u16::from_be_bytes([b[0], b[1]]) % 360
}

/// Check that the app id isn't claimed by another origin: globally, if an admin registered the
/// app, and otherwise for this user.
async fn check_owner(
    state: &AppState,
    user: &crate::system::User,
    a: &Authorization,
) -> Result<(), Rejection> {
    if let Some(r) = state.sys.registered_app(a.app_id).await? {
        if r.origin != a.origin {
            return Err(error_redirect(
                state,
                &a.redirect_uri,
                a.state.as_deref(),
                "invalid_request",
                "app_id is registered to another app",
            ));
        }
        return Ok(());
    }
    match state.sys.app(user.id, a.app_id).await? {
        Some(app) if app.origin != a.origin => Err(error_redirect(
            state,
            &a.redirect_uri,
            a.state.as_deref(),
            "invalid_request",
            "app_id is already used by another app",
        )),
        _ => Ok(()),
    }
}

/// What the consent page shows, and the fields its form posts back to `/oauth/authorize`.
#[derive(Serialize)]
pub struct Consent {
    username: String,
    app_name: String,
    app_id: String,
    hue: u16,
    folder: String,
    origin: String,
    /// The app runs on this computer (plain http on a loopback address).
    local: bool,
    permissions: Vec<&'static str>,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
}

/// `GET /ui/oauth/authorize` with the app's `/oauth/authorize` query: what to ask the signed-in
/// user, or `{"redirect": url}` to send them back to the app with an error.
pub async fn consent(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Query(p): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    let checked = match validate(&state, &p) {
        Ok(a) => check_owner(&state, &user, &a).await.map(|()| a),
        Err(r) => Err(r),
    };
    let a = match checked {
        Ok(a) => a,
        Err(Rejection::Invalid(e)) => return Err(e),
        Err(Rejection::Redirect(u)) => {
            return Ok(Json(json!({ "redirect": u.as_str() })).into_response());
        }
    };
    Ok(Json(Consent {
        username: user.username.clone(),
        hue: app_hue(a.app_id),
        folder: format!("/{}", crate::auth::app_folder(a.app_id)),
        app_id: a.app_id.to_string(),
        app_name: a.app_name,
        local: a.redirect_uri.scheme() == "http",
        permissions: describe_scopes(&a.scopes),
        origin: a.origin,
        client_id: a.client_id,
        redirect_uri: a.redirect_uri.to_string(),
        scope: a.scopes,
        state: a.state.unwrap_or_default(),
        code_challenge: a.code_challenge,
    })
    .into_response())
}

/// `POST /oauth/authorize`: the user's answer. Redirects back to the app with a code.
pub async fn decide(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Form(mut p): Form<AuthorizeParams>,
) -> Result<Response, AppError> {
    // The consent form always carries these; an empty state means the app sent none.
    p.response_type = Some("code".into());
    p.code_challenge_method = Some("S256".into());
    p.state = p.state.filter(|s| !s.is_empty());
    let a = match validate(&state, &p) {
        Ok(a) => a,
        Err(r) => return Ok(r.into_response()),
    };
    if let Err(r) = check_owner(&state, &user, &a).await {
        return Ok(r.into_response());
    }
    if p.decision.as_deref() != Some("allow") {
        return Ok(error_redirect(
            &state,
            &a.redirect_uri,
            a.state.as_deref(),
            "access_denied",
            "the user declined",
        )
        .into_response());
    }
    state
        .sys
        .record_app(user.id, a.app_id, a.app_name, a.origin)
        .await?;
    let code = state
        .sys
        .create_oauth_code(
            user.id,
            a.app_id,
            a.client_id,
            a.redirect_uri.to_string(),
            a.scopes,
            a.code_challenge,
            CODE_TTL_SECS,
        )
        .await?;
    let mut url = a.redirect_uri;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("code", &code);
        if let Some(s) = &a.state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", &state.cfg.origin);
    }
    Ok(Redirect::to(url.as_str()).into_response())
}

fn token_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// base64url(SHA-256(verifier)), the S256 code challenge for a verifier.
pub fn s256(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `POST /oauth/token`: exchange a code (and its PKCE verifier) for an access token.
pub async fn token(
    State(state): State<AppState>,
    form: Result<Form<HashMap<String, String>>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "send an application/x-www-form-urlencoded body",
        );
    };
    let get = |k: &str| f.get(k).map(String::as_str).filter(|v| !v.is_empty());
    if get("grant_type") != Some("authorization_code") {
        return token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be authorization_code",
        );
    }
    let (Some(code), Some(client_id), Some(redirect_uri), Some(verifier)) = (
        get("code"),
        get("client_id"),
        get("redirect_uri"),
        get("code_verifier"),
    ) else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, client_id, redirect_uri and code_verifier are required",
        );
    };
    let stored = match state.sys.take_oauth_code(code).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the code is invalid, expired or already used",
            );
        }
        Err(e) => return e.into_response(),
    };
    if stored.client_id != client_id || stored.redirect_uri != redirect_uri {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id or redirect_uri doesn't match the authorization request",
        );
    }
    if s256(verifier) != stored.code_challenge {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier doesn't match the code_challenge",
        );
    }
    let access_token = match state
        .sys
        .create_app_token(
            stored.user_id,
            stored.client_id,
            stored.app_id,
            stored.scopes.clone(),
            now() + ACCESS_TOKEN_TTL_SECS,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECS,
            "scope": stored.scopes,
            "folder": crate::auth::app_folder(stored.app_id),
        })),
    )
        .into_response()
}

/// `POST /oauth/revoke` (RFC 7009): forget a token. Always succeeds.
pub async fn revoke(
    State(state): State<AppState>,
    form: Result<Form<HashMap<String, String>>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "send an application/x-www-form-urlencoded body",
        );
    };
    let Some(token) = f.get("token").filter(|t| !t.is_empty()) else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is required",
        );
    };
    match state.sys.revoke_token(token).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub async fn metadata(State(state): State<AppState>) -> Response {
    let o = &state.cfg.origin;
    Json(json!({
        "issuer": o,
        "authorization_endpoint": format!("{o}/oauth/authorize"),
        "token_endpoint": format!("{o}/oauth/token"),
        "revocation_endpoint": format!("{o}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ALL_SCOPES,
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}
