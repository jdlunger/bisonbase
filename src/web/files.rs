//! Browsing and changing a user's file tree, and downloads.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Multipart, Query, State},
    http::{HeaderMap, Uri},
    response::Response,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncReadExt;

use super::{JsonResult, ok};
use crate::{
    api::{
        db::{create_db, snapshot_response},
        files::{serve_file, wild_path},
    },
    auth::{AdminUser, SessionUser},
    error::{AppError, AppResult},
    state::AppState,
    storage::fs::{SafePath, UserStore, etag, is_sqlite},
    system::User,
};

/// Text files up to this size open in the editor; larger ones get a read-only preview.
const TEXT_EDIT_BYTES: u64 = 256 * 1024;

/// How an app's folder (`apps/<id>`) is shown: the app's name on a colored label.
#[derive(Clone, Serialize)]
pub struct AppLabel {
    pub name: String,
    pub hue: u16,
}

/// Labels for the owner's app folders, keyed by app id, but only when `p` is in `apps/`, the
/// one place they show up.
async fn app_labels(
    state: &AppState,
    owner: uuid::Uuid,
    p: &SafePath,
) -> AppResult<HashMap<uuid::Uuid, AppLabel>> {
    if p.components().first().map(String::as_str) != Some("apps") {
        return Ok(HashMap::new());
    }
    Ok(state
        .sys
        .apps(owner)
        .await?
        .into_iter()
        .map(|a| {
            let label = AppLabel {
                name: a.name,
                hue: crate::oauth::app_hue(a.id),
            };
            (a.id, label)
        })
        .collect())
}

/// Whose file tree a request is about. Users see their own; admins can look at anyone's,
/// read-only. A registered app's own storage (`app`) is editable by the app's owners and admins;
/// everyone else sees only plain files and the database rows they own, read-only.
pub struct Tree {
    pub owner: User,
    pub store: UserStore,
    pub editable: bool,
    /// Set for an app's storage.
    pub app: Option<AppView>,
    /// Viewers who don't manage the app's storage see only rows they own (this user id), can't
    /// download databases, and can't run SQL.
    pub rows_of: Option<String>,
}

/// An app's storage, as shown in the UI.
#[derive(Clone, Serialize)]
pub struct AppView {
    pub id: uuid::Uuid,
    pub name: String,
    pub hue: u16,
    /// The viewer may change the app's storage.
    pub manage: bool,
}

/// Which tree: `owner` (admins: another user's) or `app` (a registered app's own storage).
#[derive(Deserialize, Default, Clone, Copy)]
pub struct TreeRef {
    pub owner: Option<uuid::Uuid>,
    pub app: Option<uuid::Uuid>,
}

impl Tree {
    pub async fn resolve(state: &AppState, viewer: User, r: TreeRef) -> AppResult<Self> {
        if let Some(id) = r.app {
            let app = state
                .sys
                .registered_app(id)
                .await?
                .ok_or_else(|| AppError::not_found("no such app"))?;
            let manage = viewer.is_admin || state.sys.is_app_owner(id, viewer.id).await?;
            return Ok(Tree {
                store: state.app_store(id),
                editable: manage,
                rows_of: (!manage).then(|| viewer.id.to_string()),
                app: Some(AppView {
                    id,
                    name: app.name,
                    hue: crate::oauth::app_hue(id),
                    manage,
                }),
                owner: viewer,
            });
        }
        match r.owner {
            Some(id) if id != viewer.id => {
                if !viewer.is_admin {
                    return Err(AppError::forbidden("admins only"));
                }
                let owner = state
                    .sys
                    .user_by_id(id)
                    .await?
                    .ok_or_else(|| AppError::not_found("no such user"))?;
                Ok(Tree {
                    store: state.store(owner.id),
                    owner,
                    editable: false,
                    app: None,
                    rows_of: None,
                })
            }
            _ => Ok(Tree {
                store: state.store(viewer.id),
                owner: viewer,
                editable: true,
                app: None,
                rows_of: None,
            }),
        }
    }

    /// The viewer's own tree, or an app's storage they manage: somewhere they may change things.
    pub async fn writable(
        state: &AppState,
        viewer: User,
        app: Option<uuid::Uuid>,
    ) -> AppResult<Self> {
        let t = Tree::resolve(state, viewer, TreeRef { owner: None, app }).await?;
        if !t.editable {
            return Err(AppError::forbidden(
                "only the app's owners can change its storage",
            ));
        }
        Ok(t)
    }
}

#[derive(Serialize)]
pub struct Owner {
    id: uuid::Uuid,
    username: String,
}

#[derive(Serialize)]
pub struct ListEntry {
    name: String,
    /// dir, db or file.
    kind: &'static str,
    size: u64,
    modified: i64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Node {
    Dir {
        entries: Vec<ListEntry>,
        usage: u64,
        quota: u64,
    },
    Db {
        size: u64,
        modified: i64,
    },
    File {
        size: u64,
        modified: i64,
        mime: String,
        is_image: bool,
        /// The file's text, if it looks like text; cut short after [`TEXT_EDIT_BYTES`].
        text: Option<String>,
        truncated: bool,
        /// Whether the text may be edited and saved.
        editable: bool,
        etag: String,
        /// The text uses CRLF line endings; saving should keep them.
        crlf: bool,
    },
}

#[derive(Serialize)]
pub struct Browse {
    owner: Owner,
    /// Set when browsing an app's own storage.
    app: Option<AppView>,
    /// The viewer only sees database rows they own here.
    rows_only: bool,
    /// Whether the viewer may change this tree.
    editable: bool,
    path: String,
    /// Names for the app folders (`apps/<id>`) in view, keyed by id.
    apps: HashMap<uuid::Uuid, AppLabel>,
    #[serde(flatten)]
    node: Node,
}

fn is_inline_image(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif"
    )
}

fn is_text(mime: &str, name: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/json" | "application/javascript" | "application/xml" | "application/toml"
        )
        || [
            ".md", ".toml", ".yaml", ".yml", ".rs", ".py", ".sql", ".log", ".ini", ".conf",
        ]
        .iter()
        .any(|e| name.ends_with(e))
}

#[derive(Deserialize)]
pub struct BrowseQuery {
    #[serde(default)]
    path: String,
    /// Whose tree, when not the viewer's own (admins only).
    owner: Option<uuid::Uuid>,
    /// A registered app's own storage.
    app: Option<uuid::Uuid>,
}

/// A folder's entries, or a file's details and text.
pub async fn browse(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Query(q): Query<BrowseQuery>,
) -> JsonResult<Browse> {
    let p = SafePath::parse(&q.path)?;
    let tree = Tree::resolve(
        &state,
        user,
        TreeRef {
            owner: q.owner,
            app: q.app,
        },
    )
    .await?;
    let store = tree.store.clone();
    store.ensure().await?;
    let entry = store.stat(&p).await?;
    let fp = store.resolve(&p).await?;
    let apps = if tree.app.is_some() {
        HashMap::new()
    } else {
        app_labels(&state, tree.owner.id, &p).await?
    };

    let node = if entry.is_dir() {
        let mut entries = Vec::new();
        for e in store.list(&p).await? {
            let kind = if e.is_dir() {
                "dir"
            } else if is_sqlite(&fp.join(&e.name)).await {
                "db"
            } else {
                "file"
            };
            entries.push(ListEntry {
                kind,
                size: if e.is_dir() { 0 } else { e.size },
                modified: e.modified,
                name: e.name,
            });
        }
        Node::Dir {
            entries,
            usage: store.usage().await?,
            quota: store.quota,
        }
    } else if is_sqlite(&fp).await {
        Node::Db {
            size: entry.size,
            modified: entry.modified,
        }
    } else {
        let mime = mime_guess::from_path(p.name())
            .first_or_octet_stream()
            .essence_str()
            .to_string();
        let is_image = is_inline_image(&mime);
        let truncated = entry.size > TEXT_EDIT_BYTES;
        // `exact`: the text is the file's bytes (or a prefix of them), so it can be saved back.
        let (mut text, mut exact) = (None, false);
        if !is_image {
            let mut buf = Vec::new();
            let f = tokio::fs::File::open(&fp).await.map_err(AppError::from)?;
            f.take(TEXT_EDIT_BYTES)
                .read_to_end(&mut buf)
                .await
                .map_err(AppError::from)?;
            (text, exact) = match std::str::from_utf8(&buf) {
                Ok(t) if !t.contains('\0') => (Some(t.to_string()), true),
                // Cut off mid-character by the size limit; still text.
                Err(e) if truncated && e.error_len().is_none() && !buf.contains(&0) => (
                    Some(String::from_utf8_lossy(&buf[..e.valid_up_to()]).into_owned()),
                    true,
                ),
                _ if is_text(&mime, p.name()) => {
                    (Some(String::from_utf8_lossy(&buf).into_owned()), false)
                }
                _ => (None, false),
            };
        }
        Node::File {
            size: entry.size,
            modified: entry.modified,
            is_image,
            mime,
            crlf: text.as_deref().is_some_and(|t| t.contains("\r\n")),
            editable: tree.editable && exact && !truncated,
            text,
            truncated,
            etag: etag(&entry),
        }
    };
    Ok(Json(Browse {
        owner: Owner {
            id: tree.owner.id,
            username: tree.owner.username,
        },
        editable: tree.editable,
        rows_only: tree.rows_of.is_some(),
        app: tree.app,
        path: p.to_string(),
        apps,
        node,
    }))
}

#[derive(Deserialize)]
pub struct RawQuery {
    #[serde(default)]
    inline: Option<String>,
}

/// Download a file. Only plain raster images may be shown inline; everything else is an
/// attachment, and all responses carry a sandboxing CSP.
pub async fn raw(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<RawQuery>,
) -> AppResult<Response> {
    let p = wild_path(&uri, "/raw")?;
    raw_from(&state, state.store(user.id), true, p, &headers, q).await
}

/// Downloading a file from an app's storage: `/apps/<id>/raw/<path>`. Only the app's owners may
/// download its databases, which hold every user's rows.
pub async fn app_raw(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<RawQuery>,
) -> AppResult<Response> {
    let rest = uri.path().strip_prefix("/apps/").unwrap_or_default();
    let (id, rest) = rest.split_once('/').unwrap_or((rest, ""));
    let id = uuid::Uuid::parse_str(id).map_err(|_| AppError::not_found("no such app"))?;
    let tree = Tree::resolve(
        &state,
        user,
        TreeRef {
            owner: None,
            app: Some(id),
        },
    )
    .await?;
    let rest = rest.strip_prefix("raw").unwrap_or_default();
    let decoded = percent_encoding::percent_decode_str(rest)
        .decode_utf8()
        .map_err(|_| AppError::bad("path is not valid UTF-8"))?;
    let p = SafePath::parse(&decoded)?;
    raw_from(&state, tree.store, tree.editable, p, &headers, q).await
}

/// An admin downloading another user's file: `/admin/users/<id>/raw/<path>`.
pub async fn admin_raw(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<RawQuery>,
) -> AppResult<Response> {
    let rest = uri.path().strip_prefix("/admin/users/").unwrap_or_default();
    let (id, rest) = rest.split_once('/').unwrap_or((rest, ""));
    let id = uuid::Uuid::parse_str(id).map_err(|_| AppError::not_found("no such user"))?;
    let owner = state
        .sys
        .user_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("no such user"))?;
    let rest = rest.strip_prefix("raw").unwrap_or_default();
    let decoded = percent_encoding::percent_decode_str(rest)
        .decode_utf8()
        .map_err(|_| AppError::bad("path is not valid UTF-8"))?;
    let store = state.store(owner.id);
    raw_from(&state, store, true, SafePath::parse(&decoded)?, &headers, q).await
}

/// `databases`: whether databases may be downloaded too.
async fn raw_from(
    state: &AppState,
    store: UserStore,
    databases: bool,
    p: SafePath,
    headers: &HeaderMap,
    q: RawQuery,
) -> AppResult<Response> {
    let entry = store.stat(&p).await?;
    if entry.is_dir() {
        return Err(AppError::bad("cannot download a directory"));
    }
    if is_sqlite(&store.resolve(&p).await?).await {
        if !databases {
            return Err(AppError::forbidden(
                "only the app's owners can download its databases",
            ));
        }
        return snapshot_response(state, &store, &p, Some("attachment")).await;
    }
    let mime = mime_guess::from_path(p.name()).first_or_octet_stream();
    let disp = if q.inline.is_some() && is_inline_image(mime.essence_str()) {
        "inline"
    } else {
        "attachment"
    };
    serve_file(&store, &p, &entry, headers, Some(disp)).await
}

/// Upload files (`file` fields) into the folder in the `dir` field, which must come first. An
/// `app` field (before the files) uploads into that app's storage.
pub async fn upload(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    mut mp: Multipart,
) -> JsonResult<serde_json::Value> {
    let mut store = None;
    let mut dir = SafePath::default();
    let mut count = 0;
    let limits = &state.cfg.limits;
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| AppError::bad(format!("bad upload: {e}")))?
    {
        match field.name() {
            Some("dir") => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
                dir = SafePath::parse(&text)?;
            }
            Some("app") if store.is_none() => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad(e.to_string()))?;
                let id =
                    uuid::Uuid::parse_str(text.trim()).map_err(|_| AppError::bad("bad app id"))?;
                store = Some(Tree::writable(&state, user.clone(), Some(id)).await?.store);
            }
            Some("file") => {
                let store = match &mut store {
                    Some(s) => s,
                    None => store.insert(state.store(user.id)),
                };
                store.ensure().await?;
                let Some(fname) = field.file_name().map(str::to_string) else {
                    continue;
                };
                let base = fname.rsplit(['/', '\\']).next().unwrap_or("").to_string();
                if base.is_empty() {
                    continue;
                }
                let target = dir.join(&base)?;
                store
                    .write_stream(&target, field, limits.max_upload_bytes, store.quota)
                    .await?;
                count += 1;
            }
            _ => {}
        }
    }
    Ok(Json(json!({ "count": count })))
}

/// A name for a new or renamed entry in `dir`.
fn child(dir: &SafePath, name: &str) -> AppResult<SafePath> {
    if name.contains('/') {
        return Err(AppError::bad("names may not contain '/'"));
    }
    let target = dir.join(name.trim())?;
    if target == *dir {
        return Err(AppError::bad("name is required"));
    }
    Ok(target)
}

#[derive(Deserialize)]
pub struct NewForm {
    #[serde(default)]
    app: Option<uuid::Uuid>,
    dir: String,
    name: String,
    /// folder, text or sqlite.
    kind: String,
}

/// Create a folder, an empty text file, or an empty SQLite database.
pub async fn create(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<NewForm>,
) -> JsonResult<serde_json::Value> {
    let dir = SafePath::parse(&f.dir)?;
    let target = child(&dir, &f.name)?;
    let store = Tree::writable(&state, user, f.app).await?.store;
    let exists = || AppError::Conflict(format!("{} already exists", target.name()));
    match f.kind.as_str() {
        "folder" => store.mkdir(&target).await?,
        "text" => {
            if store.stat(&target).await.is_ok() {
                return Err(exists());
            }
            let limits = &state.cfg.limits;
            store
                .write_stream(
                    &target,
                    futures_util::stream::empty::<Result<Bytes, std::convert::Infallible>>(),
                    limits.max_upload_bytes,
                    store.quota,
                )
                .await?;
        }
        "sqlite" => {
            if !create_db(&state, &store, &target).await? {
                return Err(exists());
            }
        }
        other => return Err(AppError::bad(format!("unknown kind '{other}'"))),
    }
    Ok(Json(json!({ "path": target.to_string() })))
}

#[derive(Deserialize)]
pub struct SaveForm {
    #[serde(default)]
    app: Option<uuid::Uuid>,
    path: String,
    content: String,
    /// The file's ETag when the editor loaded it.
    etag: String,
}

/// Save a text file from the editor. Refuses if the file changed since the editor loaded it.
pub async fn save(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<SaveForm>,
) -> JsonResult<serde_json::Value> {
    let p = SafePath::parse(&f.path)?;
    let store = Tree::writable(&state, user, f.app).await?.store;
    let cur = store.stat(&p).await?;
    if cur.is_dir() || is_sqlite(&store.resolve(&p).await?).await {
        return Err(AppError::bad("not a text file"));
    }
    if etag(&cur) != f.etag {
        return Err(AppError::Conflict(
            "the file changed since you opened it; copy your edits and reload".into(),
        ));
    }
    let limits = &state.cfg.limits;
    let body =
        futures_util::stream::iter([Ok::<_, std::convert::Infallible>(Bytes::from(f.content))]);
    store
        .write_stream(&p, body, limits.max_upload_bytes, store.quota)
        .await?;
    let now = store.stat(&p).await?;
    Ok(Json(
        json!({ "etag": etag(&now), "size": now.size, "modified": now.modified }),
    ))
}

#[derive(Deserialize)]
pub struct PathForm {
    #[serde(default)]
    app: Option<uuid::Uuid>,
    path: String,
}

pub async fn delete(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<PathForm>,
) -> JsonResult<serde_json::Value> {
    let p = SafePath::parse(&f.path)?;
    let store = Tree::writable(&state, user, f.app).await?.store;
    store.delete(&p, true).await?;
    Ok(ok())
}

#[derive(Deserialize)]
pub struct RenameForm {
    #[serde(default)]
    app: Option<uuid::Uuid>,
    path: String,
    new_name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<RenameForm>,
) -> JsonResult<serde_json::Value> {
    let p = SafePath::parse(&f.path)?;
    let to = child(&p.parent(), &f.new_name)?;
    let store = Tree::writable(&state, user, f.app).await?.store;
    store.rename(&p, &to, false).await?;
    Ok(Json(json!({ "path": to.to_string() })))
}
