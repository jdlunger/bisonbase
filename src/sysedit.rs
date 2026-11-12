//! Admin editing of `system.db` through the database editor.
//!
//! Admins can browse every table, but writes are limited to an allowlist of columns and tables
//! below, validated with the same rules the rest of the server applies, and recorded in
//! `audit_log` in the same transaction.

use rusqlite::{Connection, types::Value};
use serde_json::{Map, Value as Json, json};

use crate::{
    auth::passkey::validate_username,
    error::{AppError, AppResult},
    storage::{
        rows::{self, RowKey},
        sql::{TableSchema, schema, sql_to_json},
    },
    system::{SignupMode, User, now},
};

/// Columns admins may edit, per table.
const EDITABLE: &[(&str, &[&str])] = &[
    ("users", &["username", "is_admin"]),
    ("passkeys", &["name"]),
    ("api_tokens", &["name", "expires_at"]),
    ("invites", &["note", "expires_at"]),
    ("settings", &["value"]),
];

/// Tables whose rows admins may delete. Deleting a session logs it out; deleting a token or
/// invite revokes it.
const DELETABLE: &[&str] = &["sessions", "api_tokens", "invites", "passkeys"];

pub fn column_editable(table: &str, col: &str) -> bool {
    EDITABLE
        .iter()
        .any(|(t, cols)| *t == table && cols.contains(&col))
}

pub fn table_editable(table: &str) -> bool {
    EDITABLE.iter().any(|(t, _)| *t == table)
}

pub fn row_deletable(table: &str) -> bool {
    DELETABLE.contains(&table)
}

/// Columns shown masked: credential hashes and serialized passkeys are noise to look at and must
/// never be edited.
pub fn mask(table: &str, col: &str, v: &Value) -> Option<String> {
    match (table, col, v) {
        (_, "token_hash", Value::Text(h)) => Some(format!(
            "sha256:{}…",
            h.chars().take(12).collect::<String>()
        )),
        ("passkeys", "data", Value::Text(d)) => Some(format!("<passkey, {} bytes>", d.len())),
        _ => None,
    }
}

fn masked_json(table: &str, t: &TableSchema, vals: &[Value]) -> Json {
    let mut m = Map::new();
    for (c, v) in t.columns.iter().zip(vals) {
        let j = match mask(table, &c.name, v) {
            Some(s) => Json::String(s),
            None => sql_to_json(v.into()),
        };
        m.insert(c.name.clone(), j);
    }
    Json::Object(m)
}

fn check_value(table: &str, col: &str, row: &[(String, Value)], v: &Value) -> AppResult<()> {
    let bad = |m: &str| Err(AppError::bad(format!("{table}.{col}: {m}")));
    match (table, col, v) {
        ("users", "username", Value::Text(s)) => validate_username(s),
        ("users", "is_admin", Value::Integer(0 | 1)) => Ok(()),
        ("users", "is_admin", _) => bad("must be 0 or 1"),
        (_, "name" | "note", Value::Text(s)) if s.chars().count() <= 200 => {
            if col == "name" && s.trim().is_empty() {
                bad("must not be empty")
            } else {
                Ok(())
            }
        }
        ("api_tokens", "expires_at", Value::Null | Value::Integer(_)) => Ok(()),
        ("invites", "expires_at", Value::Integer(_)) => Ok(()),
        (_, "expires_at", _) => bad("must be a unix timestamp (integer)"),
        ("settings", "value", Value::Text(s)) => {
            let key = row.iter().find(|(c, _)| c == "key").map(|(_, v)| v);
            match key {
                Some(Value::Text(k)) if k == "signup_mode" => SignupMode::parse(s)
                    .map(|_| ())
                    .ok_or_else(|| AppError::bad("signup_mode must be open, invite or closed")),
                _ => bad("this setting isn't editable"),
            }
        }
        _ => bad("invalid value"),
    }
}

/// An edit submitted through the editor.
pub enum Edit {
    Update {
        key: RowKey,
        version: String,
        values: Vec<(String, Value)>,
    },
    Delete {
        key: RowKey,
        version: String,
    },
}

/// Apply an admin's edit to system.db: allowlist, validation, invariants and audit log, all in
/// one transaction. Returns a summary for the UI.
pub fn apply(conn: &Connection, admin: &User, table: &str, edit: Edit) -> AppResult<String> {
    let tables = schema(conn)?;
    let t = rows::table(&tables, table)?;
    let tx = conn.unchecked_transaction()?;
    let (action, key, detail, summary) = match edit {
        Edit::Update {
            key,
            version,
            values,
        } => {
            let current =
                rows::get(&tx, t, &key)?.ok_or_else(|| AppError::not_found("row not found"))?;
            let row: Vec<(String, Value)> = t
                .columns
                .iter()
                .map(|c| c.name.clone())
                .zip(current)
                .collect();
            for (c, v) in &values {
                if !column_editable(table, c) {
                    return Err(AppError::forbidden(format!("{table}.{c} isn't editable")));
                }
                check_value(table, c, &row, v)?;
            }
            let changes = rows::update(&tx, t, &key, &version, values)?;
            if changes.is_empty() {
                return Ok("No changes".into());
            }
            if table == "users" && changes.iter().any(|c| c.column == "is_admin") {
                let id = row.iter().find(|(c, _)| c == "id").map(|(_, v)| v);
                if id == Some(&Value::Text(admin.id.to_string())) {
                    return Err(AppError::forbidden(
                        "you cannot change your own admin status",
                    ));
                }
                let admins: i64 =
                    tx.query_row("SELECT count(*) FROM users WHERE is_admin", [], |r| {
                        r.get(0)
                    })?;
                if admins == 0 {
                    return Err(AppError::forbidden("there must be at least one admin"));
                }
            }
            let mut d = Map::new();
            for c in &changes {
                d.insert(
                    c.column.clone(),
                    json!({"from": sql_to_json((&c.old).into()), "to": sql_to_json((&c.new).into())}),
                );
            }
            let n = changes.len();
            (
                "update",
                key,
                Json::Object(d),
                format!("Updated {n} column(s)"),
            )
        }
        Edit::Delete { key, version } => {
            if !row_deletable(table) {
                return Err(AppError::forbidden(format!(
                    "rows of {table} can't be deleted here"
                )));
            }
            let old = rows::delete(&tx, t, &key, &version)?;
            if table == "passkeys" {
                let user = t
                    .columns
                    .iter()
                    .position(|c| c.name == "user_id")
                    .map(|i| old[i].clone());
                let left: i64 = tx.query_row(
                    "SELECT count(*) FROM passkeys WHERE user_id = ?1",
                    [user],
                    |r| r.get(0),
                )?;
                if left == 0 {
                    return Err(AppError::Conflict(
                        "cannot delete a user's last passkey".into(),
                    ));
                }
            }
            (
                "delete",
                key,
                masked_json(table, t, &old),
                "Row deleted".to_string(),
            )
        }
    };
    tx.execute(
        "INSERT INTO audit_log(at, user_id, username, action, table_name, row_key, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            now(),
            admin.id.to_string(),
            admin.username,
            action,
            table,
            key.encode(),
            detail.to_string()
        ],
    )?;
    tx.commit()?;
    tracing::info!(admin = %admin.username, table, action, "system.db edited");
    Ok(summary)
}
