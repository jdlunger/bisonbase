//! Registered apps in the UI: the apps a user can see (with their own storage), and the admin
//! endpoints that register apps and choose their owners.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{JsonResult, ok};
use crate::{
    api::apps::{check_name, check_origin},
    auth::{AdminUser, SessionUser},
    error::AppError,
    oauth::app_hue,
    state::AppState,
    system::AppOwner,
};

#[derive(Serialize)]
pub struct AppItem {
    id: Uuid,
    name: String,
    origin: String,
    hue: u16,
    created: i64,
    /// The viewer may change the app's storage.
    manage: bool,
    /// Only for admins.
    #[serde(skip_serializing_if = "Option::is_none")]
    owners: Option<Vec<AppOwner>>,
    /// Bytes used by the app's storage; only for those who manage it.
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<u64>,
    quota: u64,
}

#[derive(Serialize)]
pub struct AppList {
    apps: Vec<AppItem>,
}

/// Registered apps: every one, for admins; for others, the ones they own or have signed in to.
pub async fn list(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
) -> JsonResult<AppList> {
    let rows = if user.is_admin {
        state
            .sys
            .registered_apps()
            .await?
            .into_iter()
            .map(|a| (a, true))
            .collect()
    } else {
        state.sys.registered_apps_for(user.id).await?
    };
    let quota = state.cfg.limits.app_quota_bytes;
    let mut apps = Vec::with_capacity(rows.len());
    for (a, manage) in rows {
        let owners = if user.is_admin {
            Some(state.sys.app_owners(a.id).await?)
        } else {
            None
        };
        let usage = if manage {
            Some(state.app_store(a.id).usage().await?)
        } else {
            None
        };
        apps.push(AppItem {
            hue: app_hue(a.id),
            id: a.id,
            name: a.name,
            origin: a.origin,
            created: a.created_at,
            manage,
            owners,
            usage,
            quota,
        });
    }
    Ok(Json(AppList { apps }))
}

#[derive(Deserialize)]
pub struct CreateForm {
    name: String,
    origin: String,
    /// Leave out to make a new one.
    #[serde(default)]
    id: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(f): Json<CreateForm>,
) -> JsonResult<serde_json::Value> {
    let id = match f.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Uuid::parse_str(s)
            .ok()
            .filter(|u| !u.is_nil())
            .ok_or_else(|| AppError::bad("the app id must be a UUID"))?,
        None => Uuid::new_v4(),
    };
    let app = state
        .sys
        .create_registered_app(&admin, id, check_name(&f.name)?, check_origin(&f.origin)?)
        .await?;
    Ok(Json(serde_json::json!({ "id": app.id })))
}

#[derive(Deserialize)]
pub struct DeleteForm {
    id: Uuid,
    /// The app's name, typed again to confirm.
    confirm: String,
}

/// Unregister an app and delete its storage, with every user's rows in it.
pub async fn delete(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(f): Json<DeleteForm>,
) -> JsonResult<serde_json::Value> {
    let app = state
        .sys
        .registered_app(f.id)
        .await?
        .ok_or_else(|| AppError::not_found("no such app"))?;
    if f.confirm.trim() != app.name {
        return Err(AppError::bad("type the app's name to confirm deleting it"));
    }
    state.sys.delete_registered_app(&admin, app.id).await?;
    state.app_store(app.id).remove_all().await?;
    state.app_locks.remove(app.id);
    tracing::info!(app = %app.name, by = %admin.username, "app deleted");
    Ok(ok())
}

#[derive(Deserialize)]
pub struct OwnerForm {
    id: Uuid,
    username: String,
    owner: bool,
}

/// Make a user an owner of an app, or stop them being one.
pub async fn set_owner(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(f): Json<OwnerForm>,
) -> JsonResult<serde_json::Value> {
    let user = state
        .sys
        .user_by_name(f.username.trim().to_string())
        .await?
        .ok_or_else(|| AppError::not_found(format!("no user named {}", f.username.trim())))?;
    state
        .sys
        .set_app_owner(&admin, f.id, &user, f.owner)
        .await?;
    Ok(ok())
}
