//! WebAuthn (passkey) registration and login endpoints. All JSON; driven by assets/app.js.

use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};

use super::{SESSION_TTL_SECS, SessionUser, clear_session_cookie, session_cookie};
use crate::{
    error::{AppError, AppResult},
    state::{AppState, Ceremony},
    system::SignupMode,
};

fn cred_id_hex(pk: &Passkey) -> String {
    hex::encode(pk.cred_id().as_ref())
}

fn webauthn_err(e: webauthn_rs::prelude::WebauthnError) -> AppError {
    tracing::debug!("webauthn error: {e:?}");
    AppError::bad(format!("passkey verification failed: {e}"))
}

pub fn validate_username(u: &str) -> AppResult<()> {
    let ok = (3..=32).contains(&u.len())
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(AppError::bad(
            "usernames must be 3-32 characters of letters, digits, '_', '-' or '.'",
        ))
    }
}

#[derive(Deserialize)]
pub struct RegisterStart {
    username: String,
    #[serde(default)]
    invite: Option<String>,
}

pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegisterStart>,
) -> AppResult<Json<Value>> {
    let username = req.username.trim().to_string();
    validate_username(&username)?;

    let invite =
        match req.invite.as_deref().filter(|s| !s.is_empty()) {
            Some(t) => {
                Some(state.sys.valid_invite(t).await?.ok_or_else(|| {
                    AppError::forbidden("invite link is invalid, used or expired")
                })?)
            }
            None => None,
        };
    let mode = state.sys.signup_mode().await?;
    let bootstrapping = state.sys.user_count().await? == 0;
    match (mode, &invite) {
        (SignupMode::Closed, _) if !bootstrapping => {
            return Err(AppError::forbidden("signups are closed"));
        }
        (_, None) if bootstrapping => {
            return Err(AppError::forbidden(
                "the first account must be created with the setup link printed in the server log",
            ));
        }
        (SignupMode::Invite, None) => {
            return Err(AppError::forbidden("an invite is required to sign up"));
        }
        _ => {}
    }
    if state.sys.user_by_name(username.clone()).await?.is_some() {
        return Err(AppError::Conflict("username is taken".into()));
    }

    let user_id = Uuid::new_v4();
    let (options, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &username, &username, None)
        .map_err(webauthn_err)?;
    let ceremony = state.ceremonies.insert(Ceremony::Register {
        user_id,
        username,
        invite,
        state: reg_state,
    });
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    ceremony: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn register_finish(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<RegisterFinish>,
) -> AppResult<(CookieJar, Json<Value>)> {
    let Some(Ceremony::Register {
        user_id,
        username,
        invite,
        state: reg_state,
    }) = state.ceremonies.take(&req.ceremony)
    else {
        return Err(AppError::bad("registration expired; please try again"));
    };
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(webauthn_err)?;

    // Re-check policy: it may have changed during the ceremony.
    let mode = state.sys.signup_mode().await?;
    let bootstrapping = state.sys.user_count().await? == 0;
    if invite.is_none() && (bootstrapping || mode != SignupMode::Open) {
        return Err(AppError::forbidden("signups are not open"));
    }
    if mode == SignupMode::Closed && !bootstrapping {
        return Err(AppError::forbidden("signups are closed"));
    }
    let is_admin = bootstrapping || invite.as_ref().is_some_and(|i| i.grants_admin);
    let user = state
        .sys
        .create_user(
            user_id,
            username,
            is_admin,
            invite.map(|i| i.id),
            cred_id_hex(&passkey),
            serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.into()))?,
        )
        .await?;
    state.store(user.id).ensure().await?;
    tracing::info!(username = %user.username, admin = user.is_admin, "user registered");

    let token = state.sys.create_session(user.id, SESSION_TTL_SECS).await?;
    Ok((
        jar.add(session_cookie(&state, token)),
        Json(json!({ "ok": true, "redirect": "/files" })),
    ))
}

#[derive(Deserialize)]
pub struct LoginStart {
    username: String,
}

pub async fn login_start(
    State(state): State<AppState>,
    Json(req): Json<LoginStart>,
) -> AppResult<Json<Value>> {
    let not_found = || AppError::bad("unknown user or no passkeys registered");
    let user = state
        .sys
        .user_by_name(req.username.trim().to_string())
        .await?
        .ok_or_else(not_found)?;
    let passkeys: Vec<Passkey> = state
        .sys
        .passkeys(user.id)
        .await?
        .iter()
        .filter_map(|p| serde_json::from_str(&p.data).ok())
        .collect();
    if passkeys.is_empty() {
        return Err(not_found());
    }
    let (options, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(webauthn_err)?;
    let ceremony = state.ceremonies.insert(Ceremony::Login {
        user_id: user.id,
        state: auth_state,
    });
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[derive(Deserialize)]
pub struct LoginFinish {
    ceremony: String,
    credential: PublicKeyCredential,
}

pub async fn login_finish(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginFinish>,
) -> AppResult<(CookieJar, Json<Value>)> {
    let Some(Ceremony::Login {
        user_id,
        state: auth_state,
    }) = state.ceremonies.take(&req.ceremony)
    else {
        return Err(AppError::bad("login expired; please try again"));
    };
    let result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(webauthn_err)?;

    // Persist updated counters / backup state for the credential that was used.
    let used = hex::encode(result.cred_id().as_ref());
    for row in state.sys.passkeys(user_id).await? {
        let Ok(mut pk) = serde_json::from_str::<Passkey>(&row.data) else {
            continue;
        };
        if cred_id_hex(&pk) == used {
            pk.update_credential(&result);
            let data = serde_json::to_string(&pk).map_err(|e| AppError::Internal(e.into()))?;
            state.sys.update_passkey(used.clone(), data).await?;
            break;
        }
    }

    let token = state.sys.create_session(user_id, SESSION_TTL_SECS).await?;
    Ok((
        jar.add(session_cookie(&state, token)),
        Json(json!({ "ok": true })),
    ))
}

#[derive(Deserialize)]
pub struct AddStart {
    #[serde(default)]
    name: String,
}

/// Register an additional passkey for the logged-in user.
pub async fn add_start(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<AddStart>,
) -> AppResult<Json<Value>> {
    let existing: Vec<_> = state
        .sys
        .passkeys(user.id)
        .await?
        .iter()
        .filter_map(|p| serde_json::from_str::<Passkey>(&p.data).ok())
        .map(|p| p.cred_id().clone())
        .collect();
    let (options, reg_state) = state
        .webauthn
        .start_passkey_registration(user.id, &user.username, &user.username, Some(existing))
        .map_err(webauthn_err)?;
    let name = match req.name.trim() {
        "" => "Passkey".to_string(),
        n => n.chars().take(64).collect(),
    };
    let ceremony = state.ceremonies.insert(Ceremony::AddPasskey {
        user_id: user.id,
        name,
        state: reg_state,
    });
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

pub async fn add_finish(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(req): Json<RegisterFinish>,
) -> AppResult<Json<Value>> {
    let Some(Ceremony::AddPasskey {
        user_id,
        name,
        state: reg_state,
    }) = state.ceremonies.take(&req.ceremony)
    else {
        return Err(AppError::bad("registration expired; please try again"));
    };
    if user_id != user.id {
        return Err(AppError::forbidden("ceremony belongs to another session"));
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(webauthn_err)?;
    state
        .sys
        .add_passkey(
            user.id,
            name,
            cred_id_hex(&passkey),
            serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.into()))?,
        )
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct RecoverStart {
    token: String,
}

/// Start registering a new passkey for the user a recovery link was issued for.
pub async fn recover_start(
    State(state): State<AppState>,
    Json(req): Json<RecoverStart>,
) -> AppResult<Json<Value>> {
    let (invite_id, user) = state
        .sys
        .valid_recovery(&req.token)
        .await?
        .ok_or_else(|| AppError::forbidden("recovery link is invalid, used or expired"))?;
    let existing: Vec<_> = state
        .sys
        .passkeys(user.id)
        .await?
        .iter()
        .filter_map(|p| serde_json::from_str::<Passkey>(&p.data).ok())
        .map(|p| p.cred_id().clone())
        .collect();
    let (options, reg_state) = state
        .webauthn
        .start_passkey_registration(user.id, &user.username, &user.username, Some(existing))
        .map_err(webauthn_err)?;
    let ceremony = state.ceremonies.insert(Ceremony::Recover {
        user_id: user.id,
        invite_id,
        state: reg_state,
    });
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

pub async fn recover_finish(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<RegisterFinish>,
) -> AppResult<(CookieJar, Json<Value>)> {
    let Some(Ceremony::Recover {
        user_id,
        invite_id,
        state: reg_state,
    }) = state.ceremonies.take(&req.ceremony)
    else {
        return Err(AppError::bad("recovery expired; please try again"));
    };
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(webauthn_err)?;
    state
        .sys
        .recover_account(
            invite_id,
            user_id,
            cred_id_hex(&passkey),
            serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.into()))?,
        )
        .await?;
    tracing::info!(%user_id, "account recovered with a new passkey");
    let token = state.sys.create_session(user_id, SESSION_TTL_SECS).await?;
    Ok((
        jar.add(session_cookie(&state, token)),
        Json(
            json!({ "ok": true, "redirect": "/settings?msg=Passkey%20added.%20Remove%20any%20you%20lost%20below." }),
        ),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<(CookieJar, axum::response::Redirect)> {
    if let Some(c) = jar.get(super::SESSION_COOKIE) {
        state.sys.delete_session(c.value()).await?;
    }
    Ok((
        jar.remove(clear_session_cookie()),
        axum::response::Redirect::to("/login"),
    ))
}
