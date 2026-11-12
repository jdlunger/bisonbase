//! Session, signup and recovery info, the user's settings, and the admin page.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{JsonResult, ok, shell};
use crate::{
    auth::{AdminUser, MaybeUser, SessionUser},
    error::{AppError, AppResult},
    state::AppState,
    system::{SignupMode, now},
};

// ---- session, login, signup ----

#[derive(Serialize)]
pub struct Me {
    id: Uuid,
    username: String,
    is_admin: bool,
}

#[derive(Serialize)]
pub struct Session {
    user: Option<Me>,
    /// Anyone may sign up, so the login page links to the signup page.
    signup_open: bool,
}

pub async fn session(
    State(state): State<AppState>,
    MaybeUser(u): MaybeUser,
) -> JsonResult<Session> {
    Ok(Json(Session {
        user: u.map(|u| Me {
            id: u.id,
            username: u.username,
            is_admin: u.is_admin,
        }),
        signup_open: state.sys.signup_mode().await? == SignupMode::Open,
    }))
}

#[derive(Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    next: Option<String>,
}

/// Only allow local redirect targets.
fn safe_next(next: Option<String>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n,
        _ => "/files".into(),
    }
}

/// The login page; logged-in users go straight on to `next`.
pub async fn login_page(MaybeUser(u): MaybeUser, Query(q): Query<LoginQuery>) -> Response {
    if u.is_some() {
        return Redirect::to(&safe_next(q.next)).into_response();
    }
    shell(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct SignupQuery {
    #[serde(default)]
    invite: Option<String>,
}

#[derive(Serialize)]
pub struct SignupInfo {
    allowed: bool,
    notice: String,
}

/// Whether the signup page may sign someone up (with this invite), and what to tell them.
pub async fn signup_info(
    State(state): State<AppState>,
    Query(q): Query<SignupQuery>,
) -> JsonResult<SignupInfo> {
    let invite = q.invite.unwrap_or_default();
    let valid_invite = if invite.is_empty() {
        None
    } else {
        state.sys.valid_invite(&invite).await?
    };
    let mode = state.sys.signup_mode().await?;
    let bootstrapping = state.sys.user_count().await? == 0;
    let (allowed, notice) = match (&valid_invite, invite.is_empty()) {
        (None, false) => (
            false,
            "This invite link is invalid, already used, or expired.".into(),
        ),
        _ if bootstrapping && valid_invite.is_none() => (
            false,
            "Use the setup link printed in the server log to create the first (admin) account."
                .into(),
        ),
        _ if bootstrapping => (
            true,
            "Create the first account. It will be an administrator.".into(),
        ),
        _ if mode == SignupMode::Closed => (false, "Signups are closed.".into()),
        (Some(i), _) if i.grants_admin => {
            (true, "This invite creates an administrator account.".into())
        }
        (Some(_), _) => (true, String::new()),
        (None, _) if mode == SignupMode::Invite => (false, "Signups are invite-only.".into()),
        _ => (true, String::new()),
    };
    Ok(Json(SignupInfo { allowed, notice }))
}

#[derive(Deserialize)]
pub struct RecoverQuery {
    #[serde(default)]
    token: String,
}

/// Whose account a recovery link is for, if it is still valid.
pub async fn recover_info(
    State(state): State<AppState>,
    Query(q): Query<RecoverQuery>,
) -> JsonResult<serde_json::Value> {
    let username = match q.token.as_str() {
        "" => None,
        t => state.sys.valid_recovery(t).await?.map(|(_, u)| u.username),
    };
    Ok(Json(json!({ "username": username })))
}

// ---- settings ----

#[derive(Serialize)]
pub struct PasskeyView {
    id: i64,
    name: String,
    created: i64,
    last_used: Option<i64>,
}

#[derive(Serialize)]
pub struct AppView {
    app_id: Uuid,
    name: String,
    hue: u16,
    /// The app's folder, `/apps/<id>`.
    folder: String,
    client_id: String,
    permissions: Vec<&'static str>,
    authorized: i64,
    last_used: Option<i64>,
}

#[derive(Serialize)]
pub struct TokenView {
    id: i64,
    name: String,
    scopes: String,
    created: i64,
    expires: Option<i64>,
    last_used: Option<i64>,
}

#[derive(Serialize)]
pub struct Settings {
    passkeys: Vec<PasskeyView>,
    tokens: Vec<TokenView>,
    apps: Vec<AppView>,
    /// The server's public origin, for the API examples.
    origin: String,
}

pub async fn settings(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> JsonResult<Settings> {
    let passkeys = state
        .sys
        .passkeys(user.id)
        .await?
        .into_iter()
        .map(|p| PasskeyView {
            id: p.id,
            name: p.name,
            created: p.created_at,
            last_used: p.last_used_at,
        })
        .collect();
    let tokens = state
        .sys
        .api_tokens(user.id)
        .await?
        .into_iter()
        .map(|t| TokenView {
            id: t.id,
            name: t.name,
            scopes: t.scopes,
            created: t.created_at,
            expires: t.expires_at,
            last_used: t.last_used_at,
        })
        .collect();
    let apps = state
        .sys
        .connected_apps(user.id)
        .await?
        .into_iter()
        .map(|a| AppView {
            app_id: a.app_id,
            name: a.name,
            hue: crate::oauth::app_hue(a.app_id),
            folder: format!("/{}", crate::auth::app_folder(a.app_id)),
            permissions: crate::oauth::describe_scopes(&a.scopes),
            client_id: a.client_id,
            authorized: a.authorized_at,
            last_used: a.last_used_at,
        })
        .collect();
    Ok(Json(Settings {
        passkeys,
        tokens,
        apps,
        origin: state.cfg.origin.clone(),
    }))
}

#[derive(Deserialize)]
pub struct TokenForm {
    name: String,
    scopes: Vec<String>,
    /// Days until it expires; none for never.
    #[serde(default)]
    expires_days: Option<i64>,
}

/// Create an API token. Its value is only ever shown in this response.
pub async fn create_token(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<TokenForm>,
) -> JsonResult<serde_json::Value> {
    let name = f.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("token name is required"));
    }
    let scopes: Vec<&str> = crate::auth::ALL_SCOPES
        .iter()
        .copied()
        .filter(|s| f.scopes.iter().any(|x| x == s))
        .collect();
    if scopes.is_empty() {
        return Err(AppError::bad("select at least one scope"));
    }
    let expires_at = match f.expires_days {
        None | Some(0) => None,
        Some(n) if (1..36500).contains(&n) => Some(now() + n * 86400),
        Some(_) => return Err(AppError::bad("invalid expiry")),
    };
    let token = state
        .sys
        .create_api_token(
            user.id,
            name.chars().take(64).collect(),
            scopes.join(" "),
            expires_at,
        )
        .await?;
    Ok(Json(json!({ "token": token })))
}

#[derive(Deserialize)]
pub struct IdForm {
    id: i64,
}

pub async fn delete_token(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<IdForm>,
) -> JsonResult<serde_json::Value> {
    state.sys.delete_api_token(user.id, f.id).await?;
    Ok(ok())
}

#[derive(Deserialize)]
pub struct AppForm {
    app_id: Uuid,
}

pub async fn disconnect_app(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<AppForm>,
) -> JsonResult<serde_json::Value> {
    state.sys.disconnect_app(user.id, f.app_id).await?;
    Ok(ok())
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<IdForm>,
) -> JsonResult<serde_json::Value> {
    state.sys.delete_passkey(user.id, f.id).await?;
    Ok(ok())
}

// ---- admin ----

#[derive(Serialize)]
pub struct InviteView {
    id: i64,
    note: String,
    grants_admin: bool,
    created: i64,
    expires: i64,
    used_at: Option<i64>,
    used_by: Option<String>,
    /// Not used and not expired.
    active: bool,
}

#[derive(Serialize)]
pub struct UserView {
    id: Uuid,
    username: String,
    is_admin: bool,
    is_self: bool,
    created: i64,
}

#[derive(Serialize)]
pub struct Admin {
    signup_mode: &'static str,
    invites: Vec<InviteView>,
    users: Vec<UserView>,
}

pub async fn admin(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
) -> JsonResult<Admin> {
    let t = now();
    let invites = state
        .sys
        .list_invites()
        .await?
        .into_iter()
        .map(|i| InviteView {
            active: i.used_at.is_none() && i.expires_at > t,
            id: i.id,
            note: i.note,
            grants_admin: i.grants_admin,
            created: i.created_at,
            expires: i.expires_at,
            used_at: i.used_at,
            used_by: i.used_by,
        })
        .collect();
    let users = state
        .sys
        .list_users()
        .await?
        .into_iter()
        .map(|u| UserView {
            is_self: u.id == admin.id,
            id: u.id,
            username: u.username,
            is_admin: u.is_admin,
            created: u.created_at,
        })
        .collect();
    Ok(Json(Admin {
        signup_mode: state.sys.signup_mode().await?.as_str(),
        invites,
        users,
    }))
}

#[derive(Deserialize)]
pub struct SignupForm {
    mode: String,
}

pub async fn set_signup_mode(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(f): Json<SignupForm>,
) -> JsonResult<serde_json::Value> {
    let mode = SignupMode::parse(&f.mode).ok_or_else(|| AppError::bad("invalid signup mode"))?;
    state.sys.set_signup_mode(mode).await?;
    Ok(ok())
}

#[derive(Deserialize)]
pub struct InviteForm {
    #[serde(default)]
    note: String,
    days: i64,
    #[serde(default)]
    grants_admin: bool,
}

/// Create an invite. Its link is only ever shown in this response.
pub async fn create_invite(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(f): Json<InviteForm>,
) -> JsonResult<serde_json::Value> {
    if !(1..=365).contains(&f.days) {
        return Err(AppError::bad("expiry must be 1-365 days"));
    }
    let token = state
        .sys
        .create_invite(
            Some(user.id),
            f.grants_admin,
            f.note.trim().chars().take(200).collect(),
            f.days * 86400,
        )
        .await?;
    let url = format!("{}/signup?invite={token}", state.cfg.origin);
    Ok(Json(json!({ "url": url })))
}

pub async fn delete_invite(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(f): Json<IdForm>,
) -> JsonResult<serde_json::Value> {
    state.sys.delete_invite(f.id).await?;
    Ok(ok())
}

#[derive(Deserialize)]
pub struct UserAdminForm {
    id: Uuid,
    admin: bool,
}

pub async fn set_user_admin(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(f): Json<UserAdminForm>,
) -> JsonResult<serde_json::Value> {
    if f.id == user.id {
        return Err(AppError::bad("you cannot change your own admin status"));
    }
    state.sys.set_admin(f.id, f.admin).await?;
    Ok(ok())
}

#[derive(Deserialize)]
pub struct UserIdForm {
    id: Uuid,
}

async fn user_by_id(state: &AppState, id: Uuid) -> AppResult<crate::system::User> {
    state
        .sys
        .user_by_id(id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))
}

/// Issue a one-time link that lets a user who lost their passkeys add a new one.
pub async fn create_recovery(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(f): Json<UserIdForm>,
) -> JsonResult<serde_json::Value> {
    let user = user_by_id(&state, f.id).await?;
    let token = state
        .sys
        .create_recovery(Some(&admin), &user, 7 * 86400)
        .await?;
    let url = format!("{}/recover?token={token}", state.cfg.origin);
    Ok(Json(json!({ "url": url, "username": user.username })))
}

#[derive(Deserialize)]
pub struct DeleteUserForm {
    id: Uuid,
    /// The username, typed again to confirm.
    confirm: String,
}

/// Delete a user's account and all their files and databases.
pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(f): Json<DeleteUserForm>,
) -> JsonResult<serde_json::Value> {
    if f.id == admin.id {
        return Err(AppError::bad("you cannot delete your own account"));
    }
    let user = user_by_id(&state, f.id).await?;
    if !f.confirm.trim().eq_ignore_ascii_case(&user.username) {
        return Err(AppError::bad(
            "type the username to confirm deleting the account",
        ));
    }
    state.sys.delete_user(&admin, &user).await?;
    state.store(user.id).remove_all().await?;
    state.locks.remove(user.id);
    tracing::info!(username = %user.username, by = %admin.username, "user deleted");
    Ok(ok())
}
