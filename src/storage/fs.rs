//! Per-user file storage with path sanitization.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, UNIX_EPOCH},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, broadcast},
};

use crate::error::{AppError, AppResult};

const MAX_DEPTH: usize = 64;
const MAX_COMPONENT: usize = 255;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Files SQLite keeps next to a database. They belong to the database: hidden from listings and
/// moved or deleted along with it.
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Whether the file at `path` is a SQLite database (by its header).
pub async fn is_sqlite(path: &Path) -> bool {
    let Ok(mut f) = tokio::fs::File::open(path).await else {
        return false;
    };
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf).await.is_ok() && &buf == SQLITE_MAGIC
}

/// Synchronous [`is_sqlite`].
pub fn is_sqlite_sync(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
        && &buf == SQLITE_MAGIC
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

async fn remove_sidecars(path: &Path) {
    for s in SQLITE_SIDECARS {
        let _ = tokio::fs::remove_file(sidecar(path, s)).await;
    }
}

/// A validated, relative path inside a user's file tree. Empty means the root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SafePath(Vec<String>);

impl SafePath {
    pub fn parse(raw: &str) -> AppResult<Self> {
        let mut parts = Vec::new();
        for c in raw.split('/') {
            if c.is_empty() {
                continue;
            }
            if c == "." || c == ".." {
                return Err(AppError::bad("path may not contain '.' or '..' segments"));
            }
            if c.len() > MAX_COMPONENT {
                return Err(AppError::bad("path segment too long"));
            }
            if c.chars()
                .any(|ch| ch == '\0' || ch == '\\' || ch.is_control())
            {
                return Err(AppError::bad("path contains invalid characters"));
            }
            parts.push(c.to_string());
        }
        if parts.len() > MAX_DEPTH {
            return Err(AppError::bad("path too deep"));
        }
        Ok(Self(parts))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }

    pub fn name(&self) -> &str {
        self.0.last().map(String::as_str).unwrap_or("")
    }

    pub fn parent(&self) -> SafePath {
        let mut p = self.0.clone();
        p.pop();
        SafePath(p)
    }

    pub fn join(&self, name: &str) -> AppResult<SafePath> {
        SafePath::parse(&format!("{self}/{name}"))
    }

    pub fn starts_with(&self, other: &SafePath) -> bool {
        self.0.starts_with(&other.0)
    }
}

impl fmt::Display for SafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("/"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    pub size: u64,
    pub modified: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

impl Entry {
    fn from_meta(name: String, meta: &std::fs::Metadata) -> Self {
        Self {
            name,
            kind: if meta.is_dir() {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }
}

/// Shared per-user state: the storage lock, the cached disk usage and change notifications.
#[derive(Debug, Clone)]
pub struct UserHandles {
    /// SQL connections hold it shared; file mutations (replace, move, delete) hold it
    /// exclusively, so a database file never changes underneath an open connection.
    pub lock: Arc<RwLock<()>>,
    pub usage: Arc<UsageCache>,
    pub changes: broadcast::Sender<DbChange>,
}

/// How many changes a slow watcher may fall behind before it is told "everything changed".
const CHANGE_BACKLOG: usize = 256;

impl Default for UserHandles {
    fn default() -> Self {
        Self {
            lock: Default::default(),
            usage: Default::default(),
            changes: broadcast::channel(CHANGE_BACKLOG).0,
        }
    }
}

/// Something in a user's tree changed: rows in some tables of the database at `path`, or (when
/// `tables` is `None`) anything at or under `path`.
#[derive(Debug, Clone)]
pub struct DbChange {
    pub path: SafePath,
    pub tables: Option<Arc<[String]>>,
}

impl DbChange {
    /// Whether this change may affect the database at `db`.
    pub fn affects(&self, db: &SafePath) -> bool {
        db.starts_with(&self.path)
    }
}

/// One [`UserHandles`] per user.
#[derive(Default)]
pub struct UserLocks(Mutex<HashMap<uuid::Uuid, UserHandles>>);

impl UserLocks {
    pub fn get(&self, user_id: uuid::Uuid) -> UserHandles {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        m.entry(user_id).or_default().clone()
    }

    /// Forget a user (after their account is deleted).
    pub fn remove(&self, user_id: uuid::Uuid) {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        m.remove(&user_id);
    }
}

/// How long a computed usage total is trusted when nothing in the tree has changed through
/// this server. It bounds drift from changes made outside the server.
const USAGE_TTL: Duration = Duration::from_secs(60);

/// A user's total bytes on disk, computed by walking their directory. Every change made through
/// [`UserStore`] or a write to a database invalidates it, so the walk only happens again after
/// something changed (or after [`USAGE_TTL`]).
#[derive(Debug, Default)]
pub struct UsageCache(Mutex<Option<(u64, Instant)>>);

impl UsageCache {
    fn get(&self) -> Option<u64> {
        let v = self.0.lock().unwrap_or_else(|p| p.into_inner());
        v.filter(|(_, at)| at.elapsed() < USAGE_TTL).map(|(n, _)| n)
    }
    fn set(&self, n: u64) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some((n, Instant::now()));
    }
    pub fn invalidate(&self) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Paths for one storage area: a user's, or a registered app's own.
#[derive(Debug, Clone)]
pub struct UserStore {
    pub root: PathBuf,
    /// How many bytes the area may hold.
    pub quota: u64,
    pub lock: Arc<RwLock<()>>,
    pub usage_cache: Arc<UsageCache>,
    pub changes: broadcast::Sender<DbChange>,
}

/// Invalidates the usage cache when dropped, so it runs however the mutation ends.
struct Invalidate<'a>(&'a UsageCache);

impl Drop for Invalidate<'_> {
    fn drop(&mut self) {
        self.0.invalidate();
    }
}

impl UserStore {
    /// The storage area at `root` (holding `files/` and `tmp/`).
    pub fn new(root: PathBuf, quota: u64, h: UserHandles) -> Self {
        Self {
            root,
            quota,
            lock: h.lock,
            usage_cache: h.usage,
            changes: h.changes,
        }
    }

    /// Tell watchers that `path` changed: rows in `tables` of the database there, or (`None`)
    /// anything at or under it.
    pub fn notify(&self, path: &SafePath, tables: Option<Vec<String>>) {
        // An error only means nobody is watching.
        let _ = self.changes.send(DbChange {
            path: path.clone(),
            tables: tables.map(Into::into),
        });
    }

    /// Mark the usage total stale; call after changing files under this user's root.
    pub fn invalidate_usage(&self) {
        self.usage_cache.invalidate();
    }

    pub fn files_dir(&self) -> PathBuf {
        self.root.join("files")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub async fn ensure(&self) -> AppResult<()> {
        for d in [self.files_dir(), self.tmp_dir()] {
            tokio::fs::create_dir_all(d).await?;
        }
        Ok(())
    }

    /// Map a safe path to a filesystem path, refusing to traverse symlinks.
    pub async fn resolve(&self, p: &SafePath) -> AppResult<PathBuf> {
        let mut cur = self.files_dir();
        let comps = p.components();
        for (i, c) in comps.iter().enumerate() {
            cur.push(c);
            match tokio::fs::symlink_metadata(&cur).await {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(AppError::forbidden("symlinks are not supported"));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Remaining components don't exist yet, so they can't be symlinks.
                    cur.extend(&comps[i + 1..]);
                    return Ok(cur);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(cur)
    }

    pub async fn stat(&self, p: &SafePath) -> AppResult<Entry> {
        let fp = self.resolve(p).await?;
        let meta = tokio::fs::symlink_metadata(&fp).await?;
        Ok(Entry::from_meta(p.name().to_string(), &meta))
    }

    pub async fn list(&self, p: &SafePath) -> AppResult<Vec<Entry>> {
        let fp = self.resolve(p).await?;
        let mut rd = tokio::fs::read_dir(&fp).await?;
        let mut out = Vec::new();
        while let Some(e) = rd.next_entry().await? {
            let meta = match e.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            out.push(Entry::from_meta(
                e.file_name().to_string_lossy().into_owned(),
                &meta,
            ));
        }
        let files: HashSet<String> = out
            .iter()
            .filter(|e| !e.is_dir())
            .map(|e| e.name.clone())
            .collect();
        let mut hidden = HashSet::new();
        for e in &out {
            for s in SQLITE_SIDECARS {
                if let Some(base) = e.name.strip_suffix(s)
                    && files.contains(base)
                    && is_sqlite(&fp.join(base)).await
                {
                    hidden.insert(e.name.clone());
                }
            }
        }
        out.retain(|e| !hidden.contains(&e.name));
        out.sort_by(|a, b| {
            b.is_dir()
                .cmp(&a.is_dir())
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    /// Stream `body` into `p`, creating parent directories. Enforces the per-upload limit and the
    /// user's remaining quota; the target is replaced atomically.
    pub async fn write_stream<S, E>(
        &self,
        p: &SafePath,
        mut body: S,
        max_bytes: u64,
        quota_bytes: u64,
    ) -> AppResult<Entry>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: fmt::Display,
    {
        if p.is_root() {
            return Err(AppError::bad("cannot write to the root directory"));
        }
        let target = self.resolve(p).await?;
        if let Ok(m) = tokio::fs::symlink_metadata(&target).await
            && m.is_dir()
        {
            return Err(AppError::Conflict("a directory exists at this path".into()));
        }
        let existing = tokio::fs::metadata(&target)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let used = self.usage().await?;
        let remaining = quota_bytes.saturating_sub(used.saturating_sub(existing));
        let limit = max_bytes.min(remaining);

        self.ensure().await?;
        let _inv = Invalidate(&self.usage_cache);
        let tmp = self.tmp_dir().join(crate::system::random_token());
        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut written: u64 = 0;
        let result: AppResult<()> = async {
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(|e| AppError::bad(format!("upload failed: {e}")))?;
                written += chunk.len() as u64;
                if written > limit {
                    return Err(if written > max_bytes {
                        AppError::PayloadTooLarge(format!("upload exceeds {max_bytes} bytes"))
                    } else {
                        AppError::QuotaExceeded("storage quota exceeded".into())
                    });
                }
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            file.sync_all().await?;
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let _guard = self.lock.write().await;
            let was_db = is_sqlite(&target).await;
            tokio::fs::rename(&tmp, &target).await?;
            if was_db {
                remove_sidecars(&target).await;
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result?;
        self.notify(p, None);
        self.stat(p).await
    }

    pub async fn mkdir(&self, p: &SafePath) -> AppResult<()> {
        let fp = self.resolve(p).await?;
        tokio::fs::create_dir_all(fp).await?;
        Ok(())
    }

    pub async fn delete(&self, p: &SafePath, recursive: bool) -> AppResult<()> {
        if p.is_root() {
            return Err(AppError::bad("cannot delete the root directory"));
        }
        let fp = self.resolve(p).await?;
        let _guard = self.lock.write().await;
        let _inv = Invalidate(&self.usage_cache);
        let meta = tokio::fs::symlink_metadata(&fp).await?;
        if meta.is_dir() {
            if recursive {
                tokio::fs::remove_dir_all(&fp).await?;
            } else {
                tokio::fs::remove_dir(&fp).await?;
            }
        } else {
            let was_db = is_sqlite(&fp).await;
            tokio::fs::remove_file(&fp).await?;
            if was_db {
                remove_sidecars(&fp).await;
            }
        }
        self.notify(p, None);
        Ok(())
    }

    pub async fn rename(&self, from: &SafePath, to: &SafePath, overwrite: bool) -> AppResult<()> {
        if from.is_root() || to.is_root() {
            return Err(AppError::bad("cannot move the root directory"));
        }
        if to.starts_with(from) {
            return Err(AppError::bad("cannot move a directory into itself"));
        }
        let src = self.resolve(from).await?;
        let dst = self.resolve(to).await?;
        let _guard = self.lock.write().await;
        tokio::fs::symlink_metadata(&src).await?;
        if let Ok(m) = tokio::fs::symlink_metadata(&dst).await {
            if !overwrite {
                return Err(AppError::Conflict("destination exists".into()));
            }
            if m.is_dir() {
                return Err(AppError::Conflict("destination is a directory".into()));
            }
            if is_sqlite(&dst).await {
                remove_sidecars(&dst).await;
            }
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let is_db = is_sqlite(&src).await;
        tokio::fs::rename(&src, &dst).await?;
        if is_db {
            for s in SQLITE_SIDECARS {
                let _ = tokio::fs::rename(sidecar(&src, s), sidecar(&dst, s)).await;
            }
        }
        self.notify(from, None);
        self.notify(to, None);
        Ok(())
    }

    /// Total bytes used by this user (cached; see [`UsageCache`]).
    pub async fn usage(&self) -> AppResult<u64> {
        if let Some(n) = self.usage_cache.get() {
            return Ok(n);
        }
        let root = self.root.clone();
        let n = tokio::task::spawn_blocking(move || dir_size(&root)).await?;
        self.usage_cache.set(n);
        Ok(n)
    }

    /// Delete this user's whole storage area.
    pub async fn remove_all(&self) -> AppResult<()> {
        let _guard = self.lock.write().await;
        let _inv = Invalidate(&self.usage_cache);
        let r = match tokio::fs::remove_dir_all(&self.root).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
        self.notify(&SafePath::default(), None);
        r
    }
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                total += m.len();
            }
        }
    }
    total
}

/// Move databases from the pre-0.2 `users/<id>/databases/` directory into the user's file tree
/// (as `files/databases/`, or `files/databases-N/` if that name is taken).
pub fn migrate_legacy_databases(data_dir: &Path) -> std::io::Result<()> {
    let Ok(users) = std::fs::read_dir(data_dir.join("users")) else {
        return Ok(());
    };
    for u in users.flatten() {
        let old = u.path().join("databases");
        if !old.is_dir() {
            continue;
        }
        if std::fs::read_dir(&old)?.next().is_none() {
            std::fs::remove_dir(&old)?;
            continue;
        }
        let files = u.path().join("files");
        std::fs::create_dir_all(&files)?;
        let mut dest = files.join("databases");
        let mut n = 2;
        while dest.exists() {
            dest = files.join(format!("databases-{n}"));
            n += 1;
        }
        std::fs::rename(&old, &dest)?;
        tracing::info!("moved {} to {}", old.display(), dest.display());
    }
    Ok(())
}

pub fn etag(e: &Entry) -> String {
    format!("\"{:x}-{:x}\"", e.size, e.modified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths() {
        assert_eq!(SafePath::parse("").unwrap().to_string(), "");
        assert_eq!(SafePath::parse("/a//b/").unwrap().to_string(), "a/b");
        assert!(SafePath::parse("a/../b").is_err());
        assert!(SafePath::parse("..").is_err());
        assert!(SafePath::parse("./a").is_err());
        assert!(SafePath::parse("a\\b").is_err());
        assert!(SafePath::parse("a\0b").is_err());
        assert!(SafePath::parse(&"a/".repeat(100)).is_err());
    }

    #[tokio::test]
    async fn sqlite_sidecars_follow_their_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = UserStore::new(dir.path().to_path_buf(), u64::MAX, Default::default());
        store.ensure().await.unwrap();
        let f = store.files_dir();
        let mut db = SQLITE_MAGIC.to_vec();
        db.resize(512, 0);
        std::fs::write(f.join("a.db"), &db).unwrap();
        std::fs::write(f.join("a.db-wal"), b"wal").unwrap();
        // Same naming pattern, but not next to a database: an ordinary file.
        std::fs::write(f.join("notes"), b"text").unwrap();
        std::fs::write(f.join("notes-journal"), b"text").unwrap();
        let names = |v: Vec<Entry>| v.into_iter().map(|e| e.name).collect::<Vec<_>>();
        let root = SafePath::default();
        assert_eq!(
            names(store.list(&root).await.unwrap()),
            ["a.db", "notes", "notes-journal"]
        );

        let p = |s: &str| SafePath::parse(s).unwrap();
        store.rename(&p("a.db"), &p("b.db"), false).await.unwrap();
        assert!(f.join("b.db-wal").is_file() && !f.join("a.db-wal").exists());
        store.rename(&p("notes"), &p("n"), false).await.unwrap();
        assert!(f.join("notes-journal").is_file());
        store.delete(&p("b.db"), false).await.unwrap();
        assert!(!f.join("b.db-wal").exists());
    }
}
