//! Row-level editing of a table: paging with row keys, fetching, inserting, updating and
//! deleting single rows. Used by the web UI's database editor for user databases and system.db.
//!
//! All SQL is built from identifiers checked against the table's schema (and quoted) plus bound
//! parameters. Nothing here opens a transaction; callers wrap edits in one.

use rusqlite::{
    Connection,
    types::{Value, ValueRef},
};
use serde_json::Value as Json;

use super::sql::{TableSchema, json_to_sql, sql_err, sql_to_json};
use crate::error::{AppError, AppResult};

pub fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// How a row of a table is identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    /// Ordinary tables: by rowid, under the first of its aliases not shadowed by a column.
    RowId(&'static str),
    /// WITHOUT ROWID tables: by primary key columns, in key order.
    Pk(Vec<String>),
    /// Views, or tables whose rows can't be addressed: read-only.
    None,
}

impl KeyKind {
    pub fn of(t: &TableSchema) -> KeyKind {
        if t.kind != "table" {
            return KeyKind::None;
        }
        if t.without_rowid {
            let mut pk: Vec<_> = t.columns.iter().filter(|c| c.pk).collect();
            pk.sort_by_key(|c| c.pk_order);
            return if pk.is_empty() {
                KeyKind::None
            } else {
                KeyKind::Pk(pk.into_iter().map(|c| c.name.clone()).collect())
            };
        }
        ["rowid", "_rowid_", "oid"]
            .into_iter()
            .find(|a| !t.columns.iter().any(|c| c.name.eq_ignore_ascii_case(a)))
            .map(KeyKind::RowId)
            .unwrap_or(KeyKind::None)
    }

    fn select_list(&self) -> String {
        match self {
            KeyKind::RowId(a) => a.to_string(),
            KeyKind::Pk(cols) => cols
                .iter()
                .map(|c| quote_ident(c))
                .collect::<Vec<_>>()
                .join(", "),
            KeyKind::None => String::new(),
        }
    }

    fn len(&self) -> usize {
        match self {
            KeyKind::RowId(_) => 1,
            KeyKind::Pk(c) => c.len(),
            KeyKind::None => 0,
        }
    }

    /// `WHERE` clause matching one row; parameters `?1..?n` are the key values.
    fn where_clause(&self) -> String {
        match self {
            KeyKind::RowId(a) => format!("{a} = ?1"),
            KeyKind::Pk(cols) => cols
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{} IS ?{}", quote_ident(c), i + 1))
                .collect::<Vec<_>>()
                .join(" AND "),
            KeyKind::None => "0".into(),
        }
    }
}

/// A row's key values, as stored in forms and URLs (a JSON array; blobs as `{"$base64"}`).
#[derive(Debug, Clone, PartialEq)]
pub struct RowKey(pub Vec<Value>);

impl RowKey {
    pub fn encode(&self) -> String {
        Json::Array(
            self.0
                .iter()
                .map(|v| sql_to_json(ValueRef::from(v)))
                .collect(),
        )
        .to_string()
    }

    pub fn decode(s: &str) -> AppResult<Self> {
        let Ok(Json::Array(items)) = serde_json::from_str::<Json>(s) else {
            return Err(AppError::bad("invalid row key"));
        };
        Ok(RowKey(
            items.iter().map(json_to_sql).collect::<AppResult<_>>()?,
        ))
    }
}

pub fn table<'a>(tables: &'a [TableSchema], name: &str) -> AppResult<&'a TableSchema> {
    tables
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| AppError::not_found(format!("no table named {name}")))
}

fn column_list(t: &TableSchema) -> String {
    t.columns
        .iter()
        .map(|c| quote_ident(&c.name))
        .collect::<Vec<_>>()
        .join(", ")
}

pub struct Page {
    pub columns: Vec<String>,
    /// Each row's key (None for views) and values, in `columns` order.
    pub rows: Vec<(Option<RowKey>, Vec<Value>)>,
    pub more: bool,
}

/// One page of a table or view, ordered by row key so paging is stable. With `only`, just the
/// rows whose column has that value.
pub fn page(
    conn: &Connection,
    t: &TableSchema,
    page: i64,
    size: i64,
    only: Option<(&str, &Value)>,
) -> AppResult<Page> {
    let key = KeyKind::of(t);
    let filter = match only {
        Some((col, _)) => format!(" WHERE {} = ?1", quote_ident(col)),
        None => String::new(),
    };
    let (sql, nkey) = if key == KeyKind::None {
        (
            format!(
                "SELECT * FROM {}{filter} LIMIT {} OFFSET {}",
                quote_ident(&t.name),
                size + 1,
                page * size
            ),
            0,
        )
    } else {
        let k = key.select_list();
        (
            format!(
                "SELECT {k}, {} FROM {}{filter} ORDER BY {k} LIMIT {} OFFSET {}",
                column_list(t),
                quote_ident(&t.name),
                size + 1,
                page * size
            ),
            key.len(),
        )
    };
    let mut st = conn.prepare(&sql).map_err(sql_err)?;
    if let Some((_, v)) = only {
        st.raw_bind_parameter(1, v).map_err(sql_err)?;
    }
    let columns: Vec<String> = st
        .column_names()
        .into_iter()
        .skip(nkey)
        .map(String::from)
        .collect();
    let ncols = st.column_count();
    let mut rows = Vec::new();
    let mut q = st.raw_query();
    let mut more = false;
    while let Some(r) = q.next().map_err(sql_err)? {
        if rows.len() as i64 >= size {
            more = true;
            break;
        }
        let vals: Vec<Value> = (0..ncols)
            .map(|i| r.get::<_, Value>(i))
            .collect::<Result<_, _>>()
            .map_err(sql_err)?;
        let (k, v) = vals.split_at(nkey);
        let k = (nkey > 0).then(|| RowKey(k.to_vec()));
        rows.push((k, v.to_vec()));
    }
    Ok(Page {
        columns,
        rows,
        more,
    })
}

/// A row's values in schema column order, or None if no row has this key.
pub fn get(conn: &Connection, t: &TableSchema, key: &RowKey) -> AppResult<Option<Vec<Value>>> {
    let kind = KeyKind::of(t);
    if kind == KeyKind::None || kind.len() != key.0.len() {
        return Err(AppError::bad("this table's rows can't be addressed"));
    }
    let sql = format!(
        "SELECT {} FROM {} WHERE {}",
        column_list(t),
        quote_ident(&t.name),
        kind.where_clause()
    );
    let mut st = conn.prepare(&sql).map_err(sql_err)?;
    let mut q = st
        .query(rusqlite::params_from_iter(key.0.iter()))
        .map_err(sql_err)?;
    let Some(r) = q.next().map_err(sql_err)? else {
        return Ok(None);
    };
    let row = (0..t.columns.len())
        .map(|i| r.get::<_, Value>(i))
        .collect::<Result<_, _>>()
        .map_err(sql_err)?;
    Ok(Some(row))
}

/// A fingerprint of a row's values, so an edit can detect that the row changed since the form
/// was rendered.
pub fn version(values: &[Value]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for v in values {
        match v {
            Value::Null => h.update([0]),
            Value::Integer(i) => {
                h.update([1]);
                h.update(i.to_le_bytes());
            }
            Value::Real(f) => {
                h.update([2]);
                h.update(f.to_le_bytes());
            }
            Value::Text(s) => {
                h.update([3]);
                h.update((s.len() as u64).to_le_bytes());
                h.update(s.as_bytes());
            }
            Value::Blob(b) => {
                h.update([4]);
                h.update((b.len() as u64).to_le_bytes());
                h.update(b);
            }
        }
    }
    hex::encode(&h.finalize()[..12])
}

fn check_writable(t: &TableSchema, col: &str) -> AppResult<()> {
    match t.columns.iter().find(|c| c.name == col) {
        None => Err(AppError::bad(format!("no column named {col}"))),
        Some(c) if c.generated => Err(AppError::bad(format!("{col} is a generated column"))),
        Some(_) => Ok(()),
    }
}

/// Insert a row. Columns left out get their default. Returns the new rowid.
pub fn insert(conn: &Connection, t: &TableSchema, values: &[(String, Value)]) -> AppResult<i64> {
    if t.kind != "table" {
        return Err(AppError::bad("only tables can be edited"));
    }
    for (c, _) in values {
        check_writable(t, c)?;
    }
    let sql = if values.is_empty() {
        format!("INSERT INTO {} DEFAULT VALUES", quote_ident(&t.name))
    } else {
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_ident(&t.name),
            values
                .iter()
                .map(|(c, _)| quote_ident(c))
                .collect::<Vec<_>>()
                .join(", "),
            (1..=values.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    conn.execute(
        &sql,
        rusqlite::params_from_iter(values.iter().map(|(_, v)| v)),
    )
    .map_err(sql_err)?;
    Ok(conn.last_insert_rowid())
}

/// A column's value before and after an update.
#[derive(Debug)]
pub struct Change {
    pub column: String,
    pub old: Value,
    pub new: Value,
}

/// Update the row with `key` if it still has `version`. Only columns whose value actually
/// differs are written. Returns the changes made (empty if nothing differed).
pub fn update(
    conn: &Connection,
    t: &TableSchema,
    key: &RowKey,
    version_seen: &str,
    values: Vec<(String, Value)>,
) -> AppResult<Vec<Change>> {
    let current = get(conn, t, key)?.ok_or_else(|| AppError::not_found("row not found"))?;
    if version(&current) != version_seen {
        return Err(AppError::Conflict(
            "the row changed since you opened it; reload and try again".into(),
        ));
    }
    let mut changes = Vec::new();
    for (col, new) in values {
        check_writable(t, &col)?;
        let i = t.columns.iter().position(|c| c.name == col).unwrap_or(0);
        let old = &current[i];
        // Browsers submit text fields with CRLF line endings; keep LF if the value had it.
        let new = match (new, old) {
            (Value::Text(n), Value::Text(o)) if !o.contains('\r') => {
                Value::Text(n.replace("\r\n", "\n"))
            }
            (n, _) => n,
        };
        if &new != old {
            changes.push(Change {
                column: col,
                old: old.clone(),
                new,
            });
        }
    }
    if changes.is_empty() {
        return Ok(changes);
    }
    let kind = KeyKind::of(t);
    let nkey = key.0.len();
    let set = changes
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{} = ?{}", quote_ident(&c.column), nkey + i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE {} SET {set} WHERE {}",
        quote_ident(&t.name),
        kind.where_clause()
    );
    let params = key.0.iter().chain(changes.iter().map(|c| &c.new));
    let n = conn
        .execute(&sql, rusqlite::params_from_iter(params))
        .map_err(sql_err)?;
    if n != 1 {
        return Err(AppError::Conflict(format!(
            "expected 1 changed row, got {n}"
        )));
    }
    Ok(changes)
}

/// The key of a row after `changes` were applied to it (an update may change key columns).
pub fn key_after(t: &TableSchema, key: &RowKey, changes: &[Change]) -> RowKey {
    let new_of = |col: &str| {
        changes
            .iter()
            .find(|c| c.column == col)
            .map(|c| c.new.clone())
    };
    match KeyKind::of(t) {
        KeyKind::Pk(cols) => RowKey(
            cols.iter()
                .zip(&key.0)
                .map(|(c, old)| new_of(c).unwrap_or_else(|| old.clone()))
                .collect(),
        ),
        KeyKind::RowId(_) => {
            // An INTEGER PRIMARY KEY column is an alias for the rowid.
            let pk: Vec<_> = t.columns.iter().filter(|c| c.pk).collect();
            match pk.as_slice() {
                [c] if c.decl_type.eq_ignore_ascii_case("INTEGER") => match new_of(&c.name) {
                    Some(v) => RowKey(vec![v]),
                    None => key.clone(),
                },
                _ => key.clone(),
            }
        }
        KeyKind::None => key.clone(),
    }
}

/// Delete the row with `key` if it still has `version`. Returns the deleted values.
pub fn delete(
    conn: &Connection,
    t: &TableSchema,
    key: &RowKey,
    version_seen: &str,
) -> AppResult<Vec<Value>> {
    let current = get(conn, t, key)?.ok_or_else(|| AppError::not_found("row not found"))?;
    if version(&current) != version_seen {
        return Err(AppError::Conflict(
            "the row changed since you opened it; reload and try again".into(),
        ));
    }
    let sql = format!(
        "DELETE FROM {} WHERE {}",
        quote_ident(&t.name),
        KeyKind::of(t).where_clause()
    );
    let n = conn
        .execute(&sql, rusqlite::params_from_iter(key.0.iter()))
        .map_err(sql_err)?;
    if n != 1 {
        return Err(AppError::Conflict(format!(
            "expected 1 deleted row, got {n}"
        )));
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sql::schema;

    fn db(sql: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(sql).unwrap();
        c
    }

    fn t(c: &Connection, name: &str) -> TableSchema {
        schema(c)
            .unwrap()
            .into_iter()
            .find(|t| t.name == name)
            .unwrap()
    }

    #[test]
    fn key_kinds() {
        let c = db("CREATE TABLE a(x);
             CREATE TABLE b(rowid TEXT, y);
             CREATE TABLE c(rowid, _rowid_, oid);
             CREATE TABLE d(k1, k2, v, PRIMARY KEY (k2, k1)) WITHOUT ROWID;
             CREATE VIEW v AS SELECT 1;");
        assert_eq!(KeyKind::of(&t(&c, "a")), KeyKind::RowId("rowid"));
        assert_eq!(KeyKind::of(&t(&c, "b")), KeyKind::RowId("_rowid_"));
        assert_eq!(KeyKind::of(&t(&c, "c")), KeyKind::None);
        assert_eq!(
            KeyKind::of(&t(&c, "d")),
            KeyKind::Pk(vec!["k2".into(), "k1".into()])
        );
        assert_eq!(KeyKind::of(&t(&c, "v")), KeyKind::None);
    }

    #[test]
    fn edit_roundtrip() {
        let c = db(
            "CREATE TABLE \"we\"\"ird\"(rowid TEXT, n INTEGER DEFAULT 7, b BLOB,
                 g GENERATED ALWAYS AS (n * 2));",
        );
        let tb = t(&c, "we\"ird");
        assert!(tb.columns.iter().any(|c| c.name == "g" && c.generated));
        let id = insert(
            &c,
            &tb,
            &[
                ("rowid".into(), Value::Text("a\nb".into())),
                ("b".into(), Value::Blob(vec![0, 1])),
            ],
        )
        .unwrap();
        assert!(insert(&c, &tb, &[("g".into(), Value::Integer(1))]).is_err());
        assert!(insert(&c, &tb, &[("nope".into(), Value::Integer(1))]).is_err());

        let p = page(&c, &tb, 0, 10, None).unwrap();
        assert_eq!(p.columns, vec!["rowid", "n", "b", "g"]);
        let (key, vals) = &p.rows[0];
        let key = key.clone().unwrap();
        assert_eq!(key, RowKey(vec![Value::Integer(id)]));
        assert_eq!(RowKey::decode(&key.encode()).unwrap(), key);
        assert_eq!(vals[1], Value::Integer(7));
        assert_eq!(vals[3], Value::Integer(14));

        let v = version(vals);
        // CRLF from a browser doesn't count as a change to an LF value.
        let ch = update(
            &c,
            &tb,
            &key,
            &v,
            vec![
                ("rowid".into(), Value::Text("a\r\nb".into())),
                ("n".into(), Value::Integer(8)),
            ],
        )
        .unwrap();
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0].column, "n");
        // The old version is now stale.
        let e = update(&c, &tb, &key, &v, vec![("n".into(), Value::Null)]).unwrap_err();
        assert!(matches!(e, AppError::Conflict(_)));
        assert!(delete(&c, &tb, &key, &v).is_err());

        let cur = get(&c, &tb, &key).unwrap().unwrap();
        assert_eq!(cur[1], Value::Integer(8));
        delete(&c, &tb, &key, &version(&cur)).unwrap();
        assert!(get(&c, &tb, &key).unwrap().is_none());
    }

    #[test]
    fn without_rowid_keys() {
        let c = db("CREATE TABLE kv(k BLOB PRIMARY KEY, v) WITHOUT ROWID;
             INSERT INTO kv VALUES (x'00ff', 'a'), (x'01', 'b');");
        let tb = t(&c, "kv");
        let p = page(&c, &tb, 0, 1, None).unwrap();
        assert!(p.more);
        assert_eq!(p.columns, vec!["k", "v"]);
        let key = p.rows[0].0.clone().unwrap();
        assert_eq!(key.encode(), r#"[{"$base64":"AP8="}]"#);
        let v = version(&p.rows[0].1);
        update(
            &c,
            &tb,
            &key,
            &v,
            vec![("v".into(), Value::Text("z".into()))],
        )
        .unwrap();
        assert_eq!(
            get(&c, &tb, &key).unwrap().unwrap()[1],
            Value::Text("z".into())
        );
    }
}
