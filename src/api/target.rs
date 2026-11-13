//! What an API request's path names: a file in the user's own tree (`/api/v1/files/<path>`), or
//! one in a registered app's own storage (`/api/v1/apps/<app id>/files/<path>`), which all of the
//! app's users share.
//!
//! In an app's storage, anyone signed in may list and read plain files and use the databases
//! through the relational API, which limits them to rows they own. Only the app's owners (and
//! admins) may create databases, change their tables, or add, change and delete files.

use axum::http::Uri;
use uuid::Uuid;

use crate::{
    auth::ApiAuth,
    error::{AppError, AppResult},
    state::AppState,
    storage::{
        fs::{SafePath, UserStore},
        rel::Access,
    },
    system::RegisteredApp,
};

pub const FILES_PREFIX: &str = "/api/v1/files";
pub const APPS_PREFIX: &str = "/api/v1/apps/";

/// A registered app's storage, as seen by the requesting user.
pub struct AppTarget {
    pub app: RegisteredApp,
    /// The user may manage the app's storage: an owner of the app, or an admin.
    pub manage: bool,
}

pub struct Target {
    pub store: UserStore,
    pub path: SafePath,
    /// Set for paths in an app's own storage.
    pub app: Option<AppTarget>,
    user: Uuid,
}

impl Target {
    /// Resolve the request's path and check the token may reach it.
    pub async fn resolve(state: &AppState, auth: &ApiAuth, uri: &Uri) -> AppResult<Self> {
        let path = uri.path();
        if let Some(rest) = path.strip_prefix(APPS_PREFIX) {
            let (id, rest) = rest.split_once('/').unwrap_or((rest, ""));
            let rest = rest
                .strip_prefix("files")
                .ok_or_else(|| AppError::not_found("not found"))?;
            let app = app_for(state, auth, id).await?;
            return Ok(Target {
                store: state.app_store(app.app.id),
                path: decode(rest)?,
                app: Some(app),
                user: auth.user.id,
            });
        }
        let p = decode(path.strip_prefix(FILES_PREFIX).unwrap_or(""))?;
        auth.check_path(&p)?;
        Ok(Target {
            store: state.store(auth.user.id),
            path: p,
            app: None,
            user: auth.user.id,
        })
    }

    /// Which rows the relational API may reach.
    pub fn access(&self) -> Access {
        match self.app {
            Some(_) => Access::Rows {
                user: self.user.to_string(),
            },
            None => Access::All,
        }
    }

    /// Whether the user may create, change and delete files and databases here.
    pub fn can_manage(&self) -> bool {
        self.app.as_ref().is_none_or(|a| a.manage)
    }

    /// Refuse unless the user may manage this storage; `what` is what they tried to do.
    pub fn require_manage(&self, what: &str) -> AppResult<()> {
        if self.can_manage() {
            return Ok(());
        }
        Err(AppError::forbidden(format!(
            "only the app's owners can {what} in its storage"
        )))
    }
}

/// Percent-decode a path from a URL.
fn decode(raw: &str) -> AppResult<SafePath> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| AppError::bad("path is not valid UTF-8"))?;
    SafePath::parse(&decoded)
}

/// The registered app `id` names, if the token may reach its storage.
pub async fn app_for(state: &AppState, auth: &ApiAuth, id: &str) -> AppResult<AppTarget> {
    let id = Uuid::parse_str(id)
        .ok()
        .filter(|u| u.to_string() == id)
        .ok_or_else(|| AppError::not_found("not found"))?;
    if auth.app.is_some_and(|a| a != id) {
        return Err(AppError::forbidden(
            "an app's token can't reach another app's storage",
        ));
    }
    let app = state.sys.registered_app(id).await?.ok_or_else(|| {
        AppError::AppNotRegistered(format!(
            "app {id} isn't registered, so it has no storage of its own; an admin can register it"
        ))
    })?;
    // A token the app got before it was registered may have come from another origin.
    if let Some(client) = &auth.client_id
        && client_origin(client).as_deref() != Some(app.origin.as_str())
    {
        return Err(AppError::forbidden(
            "this app's id is registered to another origin",
        ));
    }
    let manage = auth.user.is_admin || state.sys.is_app_owner(id, auth.user.id).await?;
    Ok(AppTarget { app, manage })
}

/// `scheme://host[:port]` of an app's URL.
pub fn client_origin(client_id: &str) -> Option<String> {
    url::Url::parse(client_id)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}
