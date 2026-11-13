//! Database view and editor: tables, paged rows, row editing and a SQL console. Serves SQLite
//! files in a user's tree (editable by their owner, read-only for admins viewing them) and, for
//! admins, `system.db` with the allowlist in [`crate::sysedit`].

use axum::{
    Json,
    extract::{Query, State},
};
use rusqlite::{Connection, types::Value};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::{
    JsonResult,
    files::{Tree, TreeRef},
};
use crate::{
    api::db::with_db,
    auth::{AdminUser, SessionUser},
    error::{AppError, AppResult},
    state::AppState,
    storage::{
        fs::{SafePath, UserStore},
        rel,
        rows::{self, KeyKind, RowKey},
        sql::{self, ConsoleOutcome, QueryResult, TableSchema},
    },
    sysedit,
    system::User,
};

const PAGE_SIZE: i64 = 100;
/// Values up to these sizes are editable in the row form; larger ones can only be kept or nulled.
const EDIT_TEXT_BYTES: usize = 256 * 1024;
const EDIT_BLOB_BYTES: usize = 64 * 1024;
/// How much of a database its landing page previews.
const PREVIEW_TABLES: usize = 10;
const PREVIEW_ROWS: i64 = 10;

/// Which database a request is about.
#[derive(Clone)]
pub enum Source {
    /// A database file in a user's tree (only the owner gets `editable`) or an app's storage
    /// (only the app's owners do).
    File {
        store: UserStore,
        path: SafePath,
        editable: bool,
        /// App databases, for viewers who don't manage the app: only tables with an `_owner`
        /// column are shown, and only this user's rows of them.
        rows_of: Option<String>,
    },
    /// The server's own system.db (admins only).
    System,
}

impl Source {
    /// A database in a user's tree or an app's storage, as seen by `viewer`.
    async fn file(state: &AppState, viewer: User, r: TreeRef, path: &str) -> AppResult<Self> {
        let tree = Tree::resolve(state, viewer, r).await?;
        Ok(Source::File {
            store: tree.store,
            path: SafePath::parse(path)?,
            editable: tree.editable,
            rows_of: tree.rows_of,
        })
    }

    /// The user whose rows alone are shown, if limited to one.
    fn rows_of(&self) -> Option<&str> {
        match self {
            Source::File { rows_of, .. } => rows_of.as_deref(),
            Source::System => None,
        }
    }

    /// Whether a table is shown: limited viewers only see tables of owned rows.
    fn shows(&self, t: &TableSchema) -> bool {
        self.rows_of().is_none()
            || (t.kind == "table"
                && !rel::is_internal(&t.name)
                && t.columns
                    .iter()
                    .any(|c| c.name.eq_ignore_ascii_case(rel::OWNER_COLUMN)))
    }

    /// Refuse what limited viewers can't do: `what` names it.
    fn require_all_rows(&self, what: &str) -> AppResult<()> {
        if self.rows_of().is_some() {
            return Err(AppError::forbidden(format!(
                "only the app's owners can {what} in its databases"
            )));
        }
        Ok(())
    }

    fn editable(&self) -> bool {
        matches!(self, Source::File { editable: true, .. })
    }

    fn can_edit_rows(&self, t: &TableSchema) -> bool {
        KeyKind::of(t) != KeyKind::None
            && match self {
                Source::File { editable, .. } => *editable,
                Source::System => sysedit::table_editable(&t.name),
            }
    }

    fn can_insert(&self, t: &TableSchema) -> bool {
        self.editable() && t.kind == "table"
    }

    fn can_delete(&self, t: &TableSchema) -> bool {
        KeyKind::of(t) != KeyKind::None
            && match self {
                Source::File { editable, .. } => *editable,
                Source::System => sysedit::row_deletable(&t.name),
            }
    }

    fn column_editable(&self, t: &TableSchema, col: &sql::ColumnSchema) -> bool {
        !col.generated
            && match self {
                Source::File { editable, .. } => *editable,
                Source::System => sysedit::column_editable(&t.name, &col.name),
            }
    }

    fn mask(&self, table: &str, col: &str, v: &Value) -> Option<String> {
        match self {
            Source::System => sysedit::mask(table, col, v),
            Source::File { .. } => None,
        }
    }
}

/// Run `f` against the source's database on a blocking thread, under the query time limit.
async fn with_conn<T, F>(state: &AppState, src: &Source, f: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, usize) -> AppResult<T> + Send + 'static,
{
    match src {
        Source::File { store, path, .. } => {
            with_db(state, store, path, move |c| {
                let max_rows = c.max_rows();
                c.guarded(|conn| f(conn, max_rows))
            })
            .await
        }
        Source::System => {
            let l = state.sql_limits();
            state
                .sys
                .call(move |c| sql::with_deadline(c, l.timeout, |conn| f(conn, l.max_rows)))
                .await
        }
    }
}

// ---- cells ----

#[derive(Serialize)]
pub struct Cell {
    text: String,
    /// "null" (also for masked values and blobs), "num", or "".
    class: &'static str,
    /// Set when the cell can be edited in place.
    #[serde(skip_serializing_if = "Option::is_none")]
    edit: Option<CellEdit>,
}

/// What the inline editor needs to know about a cell.
#[derive(Serialize)]
pub struct CellEdit {
    /// Index of the column in the table schema.
    col: usize,
    name: String,
    /// The value's current type: null, integer, real or text.
    kind: &'static str,
    /// Type to use when a NULL cell gets a value.
    affinity: &'static str,
    /// The full value, when the cell shows a truncated one.
    full: Option<String>,
}

fn text_cell(s: &str) -> Cell {
    let mut text: String = s.chars().take(500).collect();
    if text.len() < s.len() {
        text.push('…');
    }
    Cell {
        text,
        class: "",
        edit: None,
    }
}

fn null_cell(text: String) -> Cell {
    Cell {
        text,
        class: "null",
        edit: None,
    }
}

fn num_cell(text: String) -> Cell {
    Cell {
        text,
        class: "num",
        edit: None,
    }
}

fn json_cell(v: &JsonValue) -> Cell {
    match v {
        JsonValue::Null => null_cell("NULL".into()),
        JsonValue::String(s) => text_cell(s),
        JsonValue::Number(n) => num_cell(n.to_string()),
        JsonValue::Object(o) => {
            let len = o
                .get("$base64")
                .and_then(|b| b.as_str())
                .map(|b| b.len() * 3 / 4)
                .unwrap_or(0);
            null_cell(format!("<blob ~{len} bytes>"))
        }
        other => text_cell(&other.to_string()),
    }
}

fn value_cell(v: &Value) -> Cell {
    match v {
        Value::Null => null_cell("NULL".into()),
        Value::Integer(i) => num_cell(i.to_string()),
        Value::Real(f) => num_cell(f.to_string()),
        Value::Text(s) => text_cell(s),
        Value::Blob(b) => null_cell(format!("<blob {} bytes>", b.len())),
    }
}

/// A read-only cell of a table: masked if the source says so.
fn masked_cell(src: &Source, table: &str, col: &str, v: &Value) -> Cell {
    match src.mask(table, col, v) {
        Some(m) => null_cell(m),
        None => value_cell(v),
    }
}

/// A cell of a table page: masked if the source says so, and editable in place if `inline`
/// and the column and value allow it.
fn grid_cell(src: &Source, t: &TableSchema, i: usize, v: &Value, inline: bool) -> Cell {
    let c = &t.columns[i];
    if let Some(m) = src.mask(&t.name, &c.name, v) {
        return null_cell(m);
    }
    let mut cell = value_cell(v);
    if !inline || !src.column_editable(t, c) {
        return cell;
    }
    let kind = match v {
        Value::Null => "null",
        Value::Integer(_) => "integer",
        Value::Real(_) => "real",
        Value::Text(s) if s.len() <= EDIT_TEXT_BYTES => "text",
        _ => return cell,
    };
    let full = match v {
        Value::Text(s) if &cell.text != s => Some(s.clone()),
        _ => None,
    };
    cell.edit = Some(CellEdit {
        col: i,
        name: c.name.clone(),
        kind,
        affinity: affinity(&c.decl_type),
        full,
    });
    cell
}

// ---- viewing ----

#[derive(Serialize)]
pub struct GridRow {
    /// Row key, when rows can be edited or deleted.
    key: Option<String>,
    version: String,
    cells: Vec<Cell>,
}

#[derive(Serialize)]
pub struct TableView {
    name: String,
    columns: Vec<String>,
    can_insert: bool,
    can_edit: bool,
    can_delete: bool,
    rows: Vec<GridRow>,
    page: i64,
    /// There is a next page.
    more: bool,
}

/// The first rows of a table, shown on a database's landing page.
#[derive(Serialize)]
pub struct Preview {
    name: String,
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
    /// The table has more rows than are shown.
    more: bool,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct DbView {
    tables: Vec<TableSchema>,
    /// The console may change the database.
    writable: bool,
    /// The requested table's rows.
    table: Option<TableView>,
    error: Option<String>,
    previews: Vec<Preview>,
    /// Tables left out of the previews.
    previews_omitted: usize,
}

fn table_preview(src: &Source, name: String, r: AppResult<rows::Page>) -> Preview {
    match r {
        Ok(r) => Preview {
            rows: r
                .rows
                .iter()
                .map(|(_, vals)| {
                    r.columns
                        .iter()
                        .zip(vals)
                        .map(|(c, v)| masked_cell(src, &name, c, v))
                        .collect()
                })
                .collect(),
            columns: r.columns,
            more: r.more,
            error: None,
            name,
        },
        Err(e) => Preview {
            name,
            columns: Vec::new(),
            rows: Vec::new(),
            more: false,
            error: Some(e.to_string()),
        },
    }
}

#[derive(Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    path: String,
    owner: Option<Uuid>,
    app: Option<Uuid>,
    table: Option<String>,
    #[serde(default)]
    page: i64,
}

/// A database's tables, and either one table's rows or the first rows of every table.
async fn view_source(
    state: &AppState,
    src: Source,
    table: Option<String>,
    page: i64,
) -> JsonResult<DbView> {
    let page = page.max(0);
    struct Data {
        tables: Vec<TableSchema>,
        page: Option<AppResult<rows::Page>>,
        previews: Vec<(String, AppResult<rows::Page>)>,
    }
    let tname = table.clone();
    let s2 = src.clone();
    let data = with_conn(state, &src, move |c, _| {
        let mut tables = sql::schema(c)?;
        tables.retain(|t| s2.shows(t));
        let only = s2
            .rows_of()
            .map(|u| (rel::OWNER_COLUMN, Value::Text(u.to_string())));
        let only = only.as_ref().map(|(c, v)| (*c, v));
        // Views aren't previewed: running one can take arbitrarily long.
        let previews = tables
            .iter()
            .filter(|t| tname.is_none() && t.kind == "table")
            .take(PREVIEW_TABLES)
            .map(|t| (t.name.clone(), rows::page(c, t, 0, PREVIEW_ROWS, only)))
            .collect();
        let page = tname
            .as_ref()
            .and_then(|n| tables.iter().find(|x| &x.name == n))
            .map(|t| rows::page(c, t, page, PAGE_SIZE, only));
        Ok(Data {
            tables,
            page,
            previews,
        })
    })
    .await?;

    let mut v = DbView {
        writable: src.editable(),
        table: None,
        error: None,
        previews: Vec::new(),
        previews_omitted: 0,
        tables: data.tables,
    };
    let Some(tname) = table else {
        let total = v.tables.iter().filter(|t| t.kind == "table").count();
        v.previews_omitted = total - data.previews.len();
        v.previews = data
            .previews
            .into_iter()
            .map(|(name, r)| table_preview(&src, name, r))
            .collect();
        return Ok(Json(v));
    };
    let Some(t) = v.tables.iter().find(|x| x.name == tname).cloned() else {
        v.error = Some(format!("no table named {tname}"));
        return Ok(Json(v));
    };
    match data.page {
        Some(Ok(r)) => {
            let can_edit = src.can_edit_rows(&t);
            let can_delete = src.can_delete(&t);
            let keyed = KeyKind::of(&t) != KeyKind::None;
            let rows = r
                .rows
                .iter()
                .map(|(k, vals)| GridRow {
                    key: k
                        .as_ref()
                        .map(RowKey::encode)
                        .filter(|_| can_edit || can_delete),
                    version: rows::version(vals),
                    cells: vals
                        .iter()
                        .enumerate()
                        .map(|(i, val)| {
                            if keyed {
                                // Keyed pages select the schema's columns, in order.
                                grid_cell(&src, &t, i, val, can_edit)
                            } else {
                                masked_cell(&src, &tname, &r.columns[i], val)
                            }
                        })
                        .collect(),
                })
                .collect();
            v.table = Some(TableView {
                can_insert: src.can_insert(&t),
                can_edit,
                can_delete,
                rows,
                page,
                more: r.more,
                columns: r.columns,
                name: tname,
            });
        }
        Some(Err(e)) => v.error = Some(e.to_string()),
        None => {}
    }
    Ok(Json(v))
}

pub async fn view(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Query(q): Query<ViewQuery>,
) -> JsonResult<DbView> {
    let src = Source::file(
        &state,
        user,
        TreeRef {
            owner: q.owner,
            app: q.app,
        },
        &q.path,
    )
    .await?;
    view_source(&state, src, q.table, q.page).await
}

pub async fn system_view(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Query(q): Query<ViewQuery>,
) -> JsonResult<DbView> {
    view_source(&state, Source::System, q.table, q.page).await
}

// ---- row form ----

/// The value type the row form suggests for a column, from SQLite's affinity rules
/// (https://sqlite.org/datatype3.html#determination_of_column_affinity). BLOB and untyped
/// columns get text, the most common thing to type in.
fn affinity(decl: &str) -> &'static str {
    let d = decl.to_ascii_uppercase();
    let has = |s: &str| d.contains(s);
    if has("INT") {
        "integer"
    } else if has("CHAR") || has("CLOB") || has("TEXT") {
        "text"
    } else if has("REAL") || has("FLOA") || has("DOUB") {
        "real"
    } else {
        "text"
    }
}

fn column_info(c: &sql::ColumnSchema) -> String {
    let mut s = c.decl_type.clone();
    if c.pk {
        s.push_str(" PK");
    }
    if c.not_null {
        s.push_str(" NOT NULL");
    }
    if let Some(d) = &c.default {
        s.push_str(&format!(" DEFAULT {d}"));
    }
    if c.generated {
        s.push_str(" GENERATED");
    }
    s.trim().to_string()
}

/// One input in the row form.
#[derive(Serialize)]
pub struct Field {
    name: String,
    info: String,
    editable: bool,
    /// Selected value type: keep, default, null, text, integer, real, blob.
    kind: &'static str,
    /// Type to switch to when the user types into a field set to default/null.
    affinity: &'static str,
    value: String,
    multiline: bool,
    /// Value too large to edit in the form; only keep or NULL are offered.
    too_large: bool,
    /// The value types to choose from, as (value, label).
    options: Vec<(&'static str, &'static str)>,
}

fn options(insert: bool, too_large: bool) -> Vec<(&'static str, &'static str)> {
    if too_large {
        return vec![("keep", "keep"), ("null", "NULL")];
    }
    let mut o = Vec::new();
    if insert {
        o.push(("default", "default"));
    }
    o.extend([
        ("null", "NULL"),
        ("text", "text"),
        ("integer", "integer"),
        ("real", "real"),
        ("blob", "blob (hex)"),
    ]);
    o
}

fn edit_field(src: &Source, t: &TableSchema, c: &sql::ColumnSchema, v: Option<&Value>) -> Field {
    let aff = affinity(&c.decl_type);
    let mut f = Field {
        name: c.name.clone(),
        info: column_info(c),
        editable: src.column_editable(t, c),
        kind: aff,
        affinity: aff,
        value: String::new(),
        multiline: false,
        too_large: false,
        options: Vec::new(),
    };
    match v {
        None => {
            let rowid_alias = c.pk && c.decl_type.eq_ignore_ascii_case("INTEGER");
            if c.default.is_some() || !c.not_null || rowid_alias {
                f.kind = "default";
            }
        }
        Some(v) => {
            if let Some(m) = src.mask(&t.name, &c.name, v) {
                f.value = m;
                f.editable = false;
                f.kind = "keep";
                return f;
            }
            match v {
                Value::Null => f.kind = "null",
                Value::Integer(i) => {
                    f.kind = "integer";
                    f.value = i.to_string();
                }
                Value::Real(r) => {
                    f.kind = "real";
                    f.value = r.to_string();
                }
                Value::Text(s) if s.len() > EDIT_TEXT_BYTES => {
                    f.kind = "keep";
                    f.too_large = true;
                    f.value = format!("<text, {} bytes>", s.len());
                }
                Value::Text(s) => {
                    f.kind = "text";
                    f.multiline = s.contains('\n') || s.len() > 80;
                    f.value = s.clone();
                }
                Value::Blob(b) if b.len() > EDIT_BLOB_BYTES => {
                    f.kind = "keep";
                    f.too_large = true;
                    f.value = format!("<blob, {} bytes>", b.len());
                }
                Value::Blob(b) => {
                    f.kind = "blob";
                    f.value = hex::encode(b);
                    f.multiline = b.len() > 40;
                }
            }
        }
    }
    f.options = options(v.is_none(), f.too_large);
    f
}

#[derive(Serialize)]
pub struct RowForm {
    /// The row's key; none for a new row.
    key: Option<String>,
    version: String,
    fields: Vec<Field>,
}

#[derive(Deserialize)]
pub struct RowQuery {
    #[serde(default)]
    path: String,
    owner: Option<Uuid>,
    app: Option<Uuid>,
    table: String,
    /// The row to edit; without one, the form inserts a new row.
    key: Option<String>,
}

async fn row_form_source(
    state: &AppState,
    src: Source,
    table: String,
    key: Option<String>,
) -> JsonResult<RowForm> {
    let k = key.as_deref().map(RowKey::decode).transpose()?;
    let s2 = src.clone();
    let form = with_conn(state, &src, move |c, _| {
        let tables = sql::schema(c)?;
        let t = rows::table(&tables, &table)?;
        let Some(k) = k else {
            if !s2.can_insert(t) {
                return Err(AppError::forbidden("rows can't be inserted here"));
            }
            return Ok(RowForm {
                key: None,
                version: String::new(),
                fields: t
                    .columns
                    .iter()
                    .filter(|c| !c.generated)
                    .map(|c| edit_field(&s2, t, c, None))
                    .collect(),
            });
        };
        if !s2.can_edit_rows(t) {
            return Err(AppError::forbidden("rows of this table can't be edited"));
        }
        let vals = rows::get(c, t, &k)?
            .ok_or_else(|| AppError::not_found("row not found (it may have been deleted)"))?;
        Ok(RowForm {
            key: Some(k.encode()),
            version: rows::version(&vals),
            fields: t
                .columns
                .iter()
                .zip(&vals)
                .map(|(c, v)| edit_field(&s2, t, c, Some(v)))
                .collect(),
        })
    })
    .await?;
    Ok(Json(form))
}

/// The fields of the form for editing a row, or inserting one.
pub async fn row_form(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Query(q): Query<RowQuery>,
) -> JsonResult<RowForm> {
    let src = Source::file(
        &state,
        user,
        TreeRef {
            owner: q.owner,
            app: q.app,
        },
        &q.path,
    )
    .await?;
    src.require_all_rows("open rows")?;
    row_form_source(&state, src, q.table, q.key).await
}

pub async fn system_row_form(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Query(q): Query<RowQuery>,
) -> JsonResult<RowForm> {
    row_form_source(&state, Source::System, q.table, q.key).await
}

// ---- console ----

#[derive(Serialize)]
pub struct Grid {
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
    truncated: bool,
}

fn result_grid(r: &QueryResult) -> Grid {
    Grid {
        columns: r.columns.clone(),
        rows: r
            .rows
            .iter()
            .map(|row| row.iter().map(json_cell).collect())
            .collect(),
        truncated: r.truncated,
    }
}

#[derive(Serialize)]
pub struct ConsoleResult {
    /// The schema after the statements ran, so DDL shows up immediately.
    tables: Vec<TableSchema>,
    message: Option<String>,
    error: Option<String>,
    result: Option<Grid>,
}

#[derive(Deserialize)]
pub struct SqlForm {
    #[serde(default)]
    path: String,
    owner: Option<Uuid>,
    app: Option<Uuid>,
    sql: String,
}

/// Run console SQL. Read-only unless the viewer owns the database.
async fn run_sql(state: &AppState, src: Source, sql_text: String) -> JsonResult<ConsoleResult> {
    let read_only = !src.editable();
    let system = matches!(src, Source::System);
    let (tables, outcome) = with_conn(state, &src, move |c, max_rows| {
        let outcome = if system {
            sql::read_only_guard(c, |c| sql::console(c, &sql_text, true, max_rows))
        } else {
            sql::console(c, &sql_text, read_only, max_rows)
        };
        Ok((sql::schema(c)?, outcome))
    })
    .await?;
    let mut r = ConsoleResult {
        tables,
        message: None,
        error: None,
        result: None,
    };
    match outcome {
        Ok(ConsoleOutcome::Result(q)) => {
            if q.columns.is_empty() {
                r.message = Some(format!(
                    "OK — {} row(s) changed, last insert rowid {}",
                    q.changes, q.last_insert_rowid
                ));
            } else {
                r.message = Some(format!("{} row(s)", q.rows.len()));
                r.result = Some(result_grid(&q));
            }
        }
        Ok(ConsoleOutcome::Script {
            statements,
            changes,
        }) => {
            r.message = Some(format!(
                "Executed {statements} statements — {changes} row(s) changed"
            ));
        }
        Err(e) => r.error = Some(e.to_string()),
    }
    Ok(Json(r))
}

pub async fn console(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(f): Json<SqlForm>,
) -> JsonResult<ConsoleResult> {
    let src = Source::file(
        &state,
        user,
        TreeRef {
            owner: f.owner,
            app: f.app,
        },
        &f.path,
    )
    .await?;
    src.require_all_rows("run SQL")?;
    run_sql(&state, src, f.sql).await
}

pub async fn system_console(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(f): Json<SqlForm>,
) -> JsonResult<ConsoleResult> {
    run_sql(&state, Source::System, f.sql).await
}

// ---- row edits ----

/// One column's new value in a row edit.
#[derive(Deserialize)]
pub struct FieldValue {
    name: String,
    /// keep, default, null, text, integer, real or blob (hex).
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize)]
pub struct RowEdit {
    #[serde(default)]
    app: Option<Uuid>,
    #[serde(default)]
    path: String,
    table: String,
    /// insert, update or delete.
    action: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    version: String,
    #[serde(default)]
    values: Vec<FieldValue>,
}

#[derive(Serialize)]
pub struct EditResult {
    message: String,
    /// The row after an update: its new key, version and cells.
    row: Option<GridRow>,
}

fn parse_value(kind: &str, raw: &str) -> AppResult<Option<Value>> {
    Ok(Some(match kind {
        "keep" | "default" => return Ok(None),
        "null" => Value::Null,
        "text" => Value::Text(raw.to_string()),
        "integer" => Value::Integer(
            raw.trim()
                .parse()
                .map_err(|_| AppError::bad(format!("'{raw}' is not an integer")))?,
        ),
        "real" => match raw.trim().parse::<f64>() {
            Ok(f) if f.is_finite() => Value::Real(f),
            _ => return Err(AppError::bad(format!("'{raw}' is not a number"))),
        },
        "blob" => {
            let hex: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            Value::Blob(hex::decode(&hex).map_err(|_| AppError::bad("blob must be hex"))?)
        }
        other => return Err(AppError::bad(format!("unknown value type '{other}'"))),
    }))
}

fn parse_values(values: &[FieldValue]) -> AppResult<Vec<(String, Value)>> {
    values
        .iter()
        .filter_map(|f| {
            parse_value(&f.kind, &f.value)
                .map_err(|e| AppError::bad(format!("{}: {e}", f.name)))
                .transpose()
                .map(|v| v.map(|v| (f.name.clone(), v)))
        })
        .collect()
}

fn row_key(e: &RowEdit) -> AppResult<RowKey> {
    RowKey::decode(
        e.key
            .as_deref()
            .ok_or_else(|| AppError::bad("missing row key"))?,
    )
}

/// The row's key, version and cells after an edit.
fn grid_row(c: &Connection, src: &Source, t: &TableSchema, key: RowKey) -> AppResult<GridRow> {
    let vals = rows::get(c, t, &key)?.ok_or_else(|| AppError::not_found("row not found"))?;
    Ok(GridRow {
        key: Some(key.encode()),
        version: rows::version(&vals),
        cells: vals
            .iter()
            .enumerate()
            .map(|(i, v)| grid_cell(src, t, i, v, true))
            .collect(),
    })
}

/// Insert, update or delete a row in one of the user's own databases, or in an app's database
/// the user manages.
pub async fn edit_row(
    State(state): State<AppState>,
    SessionUser(user): SessionUser,
    Json(e): Json<RowEdit>,
) -> JsonResult<EditResult> {
    let tree = Tree::writable(&state, user, e.app).await?;
    let src = Source::File {
        store: tree.store,
        path: SafePath::parse(&e.path)?,
        editable: true,
        rows_of: None,
    };
    let values = parse_values(&e.values)?;
    let s2 = src.clone();
    let r = with_conn(&state, &src, move |c, _| {
        let tables = sql::schema(c)?;
        let t = rows::table(&tables, &e.table)?;
        let tx = c.unchecked_transaction()?;
        let mut new_key = None;
        let message = match e.action.as_str() {
            "insert" => {
                let id = rows::insert(&tx, t, &values)?;
                format!("Row inserted (rowid {id})")
            }
            "update" => {
                let k = row_key(&e)?;
                let changes = rows::update(&tx, t, &k, &e.version, values)?;
                new_key = Some(rows::key_after(t, &k, &changes));
                match changes.len() {
                    0 => "No changes".into(),
                    n => format!("Updated {n} column(s)"),
                }
            }
            "delete" => {
                rows::delete(&tx, t, &row_key(&e)?, &e.version)?;
                "Row deleted".into()
            }
            other => return Err(AppError::bad(format!("unknown action '{other}'"))),
        };
        tx.commit()?;
        let row = new_key.map(|k| grid_row(c, &s2, t, k)).transpose()?;
        Ok(EditResult { message, row })
    })
    .await?;
    Ok(Json(r))
}

/// Update or delete a row of system.db, within [`sysedit`]'s allowlist.
pub async fn system_edit_row(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(e): Json<RowEdit>,
) -> JsonResult<EditResult> {
    let key = row_key(&e)?;
    let update = e.action == "update";
    let edit = match e.action.as_str() {
        "update" => sysedit::Edit::Update {
            key: key.clone(),
            version: e.version.clone(),
            values: parse_values(&e.values)?,
        },
        "delete" => sysedit::Edit::Delete {
            key: key.clone(),
            version: e.version.clone(),
        },
        _ => {
            return Err(AppError::forbidden(
                "rows can't be inserted into system.db here",
            ));
        }
    };
    let table = e.table;
    let r = state
        .sys
        .call(move |c| {
            let message = sysedit::apply(c, &user, &table, edit)?;
            // Editable system columns are never key columns, so the key is unchanged.
            let row = if update {
                let tables = sql::schema(c)?;
                let t = rows::table(&tables, &table)?;
                Some(grid_row(c, &Source::System, t, key)?)
            } else {
                None
            };
            Ok(EditResult { message, row })
        })
        .await?;
    Ok(Json(r))
}
