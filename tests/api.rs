use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use bisonbase::{AppState, config::Config, system::SystemDb};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

struct Env {
    app: Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    cfg.resolve(8080).unwrap();
    cfg.limits.user_quota_bytes = 1 << 20;
    cfg.limits.max_upload_bytes = 512 << 10;
    std::fs::create_dir_all(dir.path().join("users")).unwrap();
    let sys = SystemDb::open(&dir.path().join("system.db")).unwrap();
    let state = AppState::new(cfg, sys).unwrap();
    Env {
        app: bisonbase::app(state.clone()),
        state,
        _dir: dir,
    }
}

async fn user(e: &Env, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    e.state
        .sys
        .create_user(
            id,
            name.into(),
            false,
            None,
            format!("cred-{name}"),
            "{}".into(),
        )
        .await
        .unwrap();
    id
}

async fn token(e: &Env, user: Uuid, scopes: &str) -> String {
    e.state
        .sys
        .create_api_token(user, "t".into(), scopes.into(), None)
        .await
        .unwrap()
}

async fn call(e: &Env, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let res = e.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn req(method: &str, uri: &str, tok: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .body(body.into())
        .unwrap()
}

fn json_req(method: &str, uri: &str, tok: &str, v: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(v.to_string()))
        .unwrap()
}

fn j(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or_else(|_| panic!("not json: {}", String::from_utf8_lossy(b)))
}

/// Open a user's database file directly. The API takes no SQL, so tests set up and check
/// databases this way.
fn open_db(e: &Env, user: Uuid, file: &str) -> rusqlite::Connection {
    rusqlite::Connection::open(e.state.store(user).files_dir().join(file)).unwrap()
}

fn seed(e: &Env, user: Uuid, file: &str, sql: &str) {
    open_db(e, user, file).execute_batch(sql).unwrap();
}

/// Run a query straight on a user's database: `{"rows": [[...], ...]}`.
fn peek(e: &Env, user: Uuid, file: &str, sql: &str) -> Value {
    let c = open_db(e, user, file);
    let mut st = c.prepare(sql).unwrap();
    let n = st.column_count();
    let rows: Vec<Vec<Value>> = st
        .query_map([], |r| {
            (0..n)
                .map(|i| Ok(bisonbase::storage::sql::sql_to_json(r.get_ref(i)?)))
                .collect()
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    json!({ "rows": rows })
}

fn db_op(db: &str, op: &str, tok: &str, body: Value) -> Request<Body> {
    json_req("POST", &format!("/api/v1/files/{db}?op={op}"), tok, body)
}

#[tokio::test]
async fn requires_auth() {
    let e = env();
    let (s, _, b) = call(
        &e,
        Request::get("/api/v1/files/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j(&b)["error"]["code"], "unauthorized");
    let (s, _, _) = call(&e, req("GET", "/api/v1/files/", "wfs_bogus", Body::empty())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn file_crud() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write").await;

    let (s, h, _) = call(
        &e,
        req(
            "PUT",
            "/api/v1/files/docs/hello%20world.txt",
            &t,
            "hi there",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let etag = h[header::ETAG].to_str().unwrap().to_string();

    let (s, h, b) = call(
        &e,
        req(
            "GET",
            "/api/v1/files/docs/hello%20world.txt",
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, b"hi there");
    assert_eq!(h[header::CONTENT_TYPE], "text/plain");
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );

    let r = Request::get("/api/v1/files/docs/hello%20world.txt")
        .header(header::AUTHORIZATION, format!("Bearer {t}"))
        .header(header::IF_NONE_MATCH, &etag)
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&e, r).await.0, StatusCode::NOT_MODIFIED);

    let (s, _, b) = call(&e, req("GET", "/api/v1/files/docs", &t, Body::empty())).await;
    assert_eq!(s, StatusCode::OK);
    let v = j(&b);
    assert_eq!(v["entries"][0]["name"], "hello world.txt");
    assert_eq!(v["entries"][0]["type"], "file");
    assert_eq!(v["entries"][0]["size"], 8);

    // If-None-Match: * refuses overwrite
    let r = Request::put("/api/v1/files/docs/hello%20world.txt")
        .header(header::AUTHORIZATION, format!("Bearer {t}"))
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from("x"))
        .unwrap();
    assert_eq!(call(&e, r).await.0, StatusCode::CONFLICT);

    let (s, _, _) = call(
        &e,
        req("POST", "/api/v1/files/a/b?op=mkdir", &t, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            "/api/v1/files/docs/hello%20world.txt?op=move&to=a/b/moved.txt",
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, b) = call(
        &e,
        req("GET", "/api/v1/files/a/b/moved.txt", &t, Body::empty()),
    )
    .await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &b"hi there"[..]));

    let (s, _, _) = call(&e, req("DELETE", "/api/v1/files/a", &t, Body::empty())).await;
    assert_eq!(s, StatusCode::CONFLICT, "non-empty dir needs recursive");
    let (s, _, _) = call(
        &e,
        req(
            "DELETE",
            "/api/v1/files/a?recursive=true",
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = call(&e, req("GET", "/api/v1/files/a", &t, Body::empty())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn path_traversal_rejected() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write").await;
    for p in [
        "/api/v1/files/..%2F..%2Fsystem.db",
        "/api/v1/files/%2E%2E/%2E%2E/system.db",
        "/api/v1/files/a/../../x",
        "/api/v1/files/a%5C..%5Cx",
    ] {
        let (s, _, _) = call(&e, req("GET", p, &t, Body::empty())).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::NOT_FOUND,
            "{p}: {s}"
        );
        let (s, _, _) = call(&e, req("PUT", p, &t, "x")).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::NOT_FOUND,
            "{p}: {s}"
        );
    }
    assert!(!e._dir.path().join("x").exists());
}

#[tokio::test]
async fn users_are_isolated() {
    let e = env();
    let a = user(&e, "alice").await;
    let b = user(&e, "bob").await;
    let ta = token(&e, a, "files:write db:write").await;
    let tb = token(&e, b, "files:write db:write").await;
    call(&e, req("PUT", "/api/v1/files/secret.txt", &ta, "alice's")).await;
    call(
        &e,
        req(
            "POST",
            "/api/v1/files/private.db?op=mkdb",
            &ta,
            Body::empty(),
        ),
    )
    .await;

    let (s, _, _) = call(
        &e,
        req("GET", "/api/v1/files/secret.txt", &tb, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, _, body) = call(&e, req("GET", "/api/v1/files/", &tb, Body::empty())).await;
    assert_eq!(j(&body)["entries"], json!([]));
    seed(
        &e,
        a,
        "private.db",
        "CREATE TABLE t(id INTEGER PRIMARY KEY, x)",
    );
    let (s, _, _) = call(
        &e,
        db_op("private.db", "select", &tb, json!({"table": "t"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = call(
        &e,
        req(
            "GET",
            "/api/v1/files/private.db?op=schema",
            &tb,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Bob can't reach Alice's database through his own: names are checked against his schema,
    // never spliced into SQL, and there is no SQL op to ATTACH with.
    call(
        &e,
        req("POST", "/api/v1/files/mine.db?op=mkdb", &tb, Body::empty()),
    )
    .await;
    let alice_db = e.state.store(a).files_dir().join("private.db");
    for table in ["main.t".to_string(), format!("'{}'.t", alice_db.display())] {
        let (s, _, _) = call(&e, db_op("mine.db", "select", &tb, json!({"table": table}))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    let attach = format!("ATTACH DATABASE '{}' AS a", alice_db.display());
    for op in ["query", "batch"] {
        let (s, _, _) = call(&e, db_op("mine.db", op, &tb, json!({"sql": attach}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn scopes_enforced() {
    let e = env();
    let u = user(&e, "alice").await;
    let w = token(&e, u, "files:write db:write").await;
    let r = token(&e, u, "files:read db:read").await;
    let none = token(&e, u, "db:read").await;

    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/x", &r, "x")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&e, req("GET", "/api/v1/files/", &none, Body::empty()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &e,
            req("POST", "/api/v1/files/d.db?op=mkdb", &r, Body::empty())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &e,
            req("POST", "/api/v1/files/d.db?op=mkdb", &w, Body::empty())
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let spec = json!({"tables": [{"name": "t", "columns": [{"name": "x", "type": "integer"}]}]});
    // Read-only tokens can check the tables match, but not create them.
    assert_eq!(
        call(&e, db_op("d.db", "migrate", &r, spec.clone())).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&e, db_op("d.db", "migrate", &w, spec.clone())).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&e, db_op("d.db", "migrate", &r, spec)).await.0,
        StatusCode::OK
    );

    for (op, body) in [
        ("insert", json!({"table": "t", "rows": [{"x": 1}]})),
        (
            "update",
            json!({"table": "t", "where": {}, "set": {"x": 2}}),
        ),
        ("delete", json!({"table": "t", "where": {}})),
        ("transact", json!({"ops": []})),
    ] {
        let (s, _, _) = call(&e, db_op("d.db", op, &r, body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{op}");
    }
    let (s, _, _) = call(&e, db_op("d.db", "select", &r, json!({"table": "t"}))).await;
    assert_eq!(s, StatusCode::OK);
    // `none` has db:read but not files:read: it can query but not download the file.
    let (s, _, _) = call(&e, db_op("d.db", "select", &none, json!({"table": "t"}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        call(&e, req("GET", "/api/v1/files/d.db", &none, Body::empty()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn database_api() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write db:write").await;
    let db = "/api/v1/files/apps/todo.db";

    let (s, _, b) = call(&e, req("POST", &format!("{db}?op=mkdb"), &t, Body::empty())).await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    assert_eq!(j(&b)["created"], true);
    assert_eq!(
        call(&e, req("POST", &format!("{db}?op=mkdb"), &t, Body::empty()))
            .await
            .0,
        StatusCode::OK
    );

    let d = "apps/todo.db";
    let (s, _, b) = call(
        &e,
        db_op(
            d,
            "migrate",
            &t,
            json!({"tables": [{"name": "items", "columns": [
                {"name": "title", "type": "text"},
                {"name": "done", "type": "boolean", "default": 0},
            ]}]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(j(&b)["applied"].as_array().unwrap().len(), 1);

    let (s, _, b) = call(
        &e,
        db_op(
            d,
            "insert",
            &t,
            json!({"table": "items", "rows": [
                {"title": "write design"},
                {"title": "build it", "done": 1},
            ]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(
        j(&b),
        json!({"columns": ["id", "title", "done"], "rows": [[1, "write design", 0], [2, "build it", 1]]})
    );

    let (s, _, b) = call(
        &e,
        db_op(
            d,
            "select",
            &t,
            json!({"table": "items", "order_by": ["id desc"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j(&b)["rows"],
        json!([[2, "build it", 1], [1, "write design", 0]])
    );

    let (s, _, b) = call(
        &e,
        db_op(
            d,
            "update",
            &t,
            json!({"table": "items", "where": {"done": 0}, "set": {"done": 1}}),
        ),
    )
    .await;
    assert_eq!((s, j(&b)), (StatusCode::OK, json!({"changes": 1})));

    let (s, _, b) = call(
        &e,
        db_op(
            d,
            "transact",
            &t,
            json!({"ops": [
                {"op": "insert", "table": "items", "rows": [{"title": "ship it"}]},
                {"op": "delete", "table": "items", "where": {"id": 1}},
            ]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(j(&b)["results"][1], json!({"changes": 1}));

    // Mistakes are reported, not guessed at: unknown tables, columns and keys.
    for (op, body, status) in [
        ("select", json!({"table": "nope"}), StatusCode::NOT_FOUND),
        (
            "select",
            json!({"table": "items", "where": {"nope": 1}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "delete",
            json!({"table": "items", "were": {"id": 2}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "insert",
            json!({"table": "items", "rows": [{"title": null}]}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (s, _, b) = call(&e, db_op(d, op, &t, body)).await;
        assert_eq!(s, status, "{}", String::from_utf8_lossy(&b));
    }
    let (s, _, b) = call(
        &e,
        db_op(d, "migrate", &t, json!({"tables": [{"name": "items", "columns": [{"name": "title", "type": "integer"}]}]})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(j(&b)["error"]["code"], "schema_mismatch");

    let (s, _, b) = call(
        &e,
        req("GET", &format!("{db}?op=schema"), &t, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let v = j(&b);
    assert_eq!(v["tables"][0]["name"], "items");
    assert_eq!(v["tables"][0]["columns"][0]["pk"], true);

    // The database is an ordinary entry in the file tree; no WAL/SHM sidecars are listed.
    let (_, _, b) = call(&e, req("GET", "/api/v1/files/apps", &t, Body::empty())).await;
    let names: Vec<_> = j(&b)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["todo.db"]);

    // GET downloads a consistent snapshot.
    let (s, h, b) = call(&e, req("GET", db, &t, Body::empty())).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "application/vnd.sqlite3");
    assert!(b.starts_with(b"SQLite format 3\0"));

    // Moving keeps it queryable.
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            &format!("{db}?op=move&to=todo2.db"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, b) = call(
        &e,
        db_op("todo2.db", "select", &t, json!({"table": "items"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j(&b)["rows"].as_array().unwrap().len(), 2);

    // An uploaded database file is queryable too.
    let (_, _, snap) = call(&e, req("GET", "/api/v1/files/todo2.db", &t, Body::empty())).await;
    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/copy.sqlite", &t, snap))
            .await
            .0,
        StatusCode::CREATED
    );
    let (s, _, b) = call(
        &e,
        db_op(
            "copy.sqlite",
            "select",
            &t,
            json!({"table": "items", "where": {"id": 2}}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(j(&b)["rows"][0][1], "build it");

    // Non-database files can't be queried (and aren't turned into databases).
    call(&e, req("PUT", "/api/v1/files/notes.txt", &t, "")).await;
    let (s, _, _) = call(
        &e,
        db_op(
            "notes.txt",
            "migrate",
            &t,
            json!({"tables": [{"name": "x", "columns": []}]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, b) = call(&e, req("GET", "/api/v1/files/notes.txt", &t, Body::empty())).await;
    assert_eq!((s, b.len()), (StatusCode::OK, 0));
    assert_eq!(
        call(
            &e,
            req("POST", "/api/v1/files/notes.txt?op=mkdb", &t, Body::empty())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    assert_eq!(
        call(
            &e,
            req("DELETE", "/api/v1/files/todo2.db", &t, Body::empty())
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (s, _, _) = call(
        &e,
        db_op("todo2.db", "select", &t, json!({"table": "items"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn database_growth_counts_toward_quota() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write db:write").await;
    // Quota is 1 MiB; leave ~600 KiB for the database.
    call(
        &e,
        req("PUT", "/api/v1/files/filler", &t, vec![0u8; 400 << 10]),
    )
    .await;
    call(
        &e,
        req("POST", "/api/v1/files/d.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    let spec = json!({"tables": [{"name": "b", "columns": [{"name": "x", "type": "blob"}]}]});
    assert_eq!(
        call(&e, db_op("d.db", "migrate", &t, spec)).await.0,
        StatusCode::OK
    );
    let blob = |n: usize| {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]);
        db_op(
            "d.db",
            "insert",
            &t,
            json!({"table": "b", "rows": [{"x": {"$base64": b64}}]}),
        )
    };
    assert_eq!(call(&e, blob(200_000)).await.0, StatusCode::OK);
    assert_eq!(
        call(&e, blob(700_000)).await.0,
        StatusCode::INSUFFICIENT_STORAGE
    );
}

#[tokio::test]
async fn legacy_databases_migrate() {
    let dir = tempfile::tempdir().unwrap();
    let u = dir.path().join("users").join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(u.join("databases")).unwrap();
    std::fs::write(u.join("databases/app.db"), b"x").unwrap();
    std::fs::create_dir_all(u.join("files/databases")).unwrap();
    bisonbase::storage::fs::migrate_legacy_databases(dir.path()).unwrap();
    assert!(!u.join("databases").exists());
    assert!(u.join("files/databases-2/app.db").is_file());
}

#[tokio::test]
async fn upload_limits() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write").await;
    let big = vec![0u8; 600 << 10]; // over 512 KiB upload limit
    let (s, _, _) = call(&e, req("PUT", "/api/v1/files/big", &t, big)).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let chunk = vec![0u8; 400 << 10];
    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/a", &t, chunk.clone()))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/b", &t, chunk.clone()))
            .await
            .0,
        StatusCode::CREATED
    );
    // 1 MiB quota: a third 400 KiB file doesn't fit, but overwriting an existing one does.
    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/c", &t, chunk.clone()))
            .await
            .0,
        StatusCode::INSUFFICIENT_STORAGE
    );
    assert_eq!(
        call(&e, req("PUT", "/api/v1/files/a", &t, chunk)).await.0,
        StatusCode::OK
    );
    let tmp = e.state.store(u).root.join("tmp");
    assert_eq!(
        std::fs::read_dir(tmp).unwrap().count(),
        0,
        "temp files cleaned up"
    );
}

#[tokio::test]
async fn cors_preflight() {
    let e = env();
    let r = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/files/x.db?op=select")
        .header(header::ORIGIN, "https://some-app.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = call(&e, r).await;
    assert!(s.is_success());
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

// ---- web UI ----

async fn session(e: &Env, user: Uuid) -> String {
    let tok = e.state.sys.create_session(user, 3600).await.unwrap();
    format!("wfs_session={tok}")
}

/// `s` percent-encoded for a query string.
fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        s.append_pair(k, v);
    }
    s.finish()
}

/// GET a page (HTML) or anything else that isn't the app's JSON.
async fn get_page(e: &Env, cookie: &str, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let r = Request::get(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let (s, h, b) = call(e, r).await;
    (s, h, String::from_utf8_lossy(&b).into_owned())
}

/// GET one of the app's JSON endpoints.
async fn ui_get(e: &Env, cookie: &str, uri: &str) -> (StatusCode, Value) {
    let r = Request::get(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let (s, _, b) = call(e, r).await;
    (s, j(&b))
}

/// POST JSON to one of the app's endpoints, as the app does (same-origin).
async fn ui_post(e: &Env, cookie: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let r = Request::post(uri)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (s, _, b) = call(e, r).await;
    (s, j(&b))
}

fn is_app_page(html: &str) -> bool {
    html.contains("<div id=\"root\">")
}

#[tokio::test]
async fn ui_requires_login() {
    let e = env();
    // Pages send logged-out users to the login page; the app's JSON answers 401.
    let (s, h, _) = get_page(&e, "", "/files/docs").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/login?next=%2Ffiles%2Fdocs");
    let (s, b) = ui_get(&e, "", "/ui/files?path=docs").await;
    assert_eq!(
        (s, &b["error"]["code"]),
        (StatusCode::UNAUTHORIZED, &json!("unauthorized"))
    );
    let (s, b) = ui_get(&e, "", "/ui/session").await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["user"].is_null());
    assert_eq!(b["signup_open"], false);

    let (s, h, html) = get_page(&e, "", "/login").await;
    assert_eq!(s, StatusCode::OK);
    assert!(is_app_page(&html), "{html}");
    assert_eq!(h[header::CACHE_CONTROL], "no-cache");

    // The app's scripts and styles are served, cached for good.
    let script = html
        .split("src=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    assert!(script.starts_with("/assets/"), "{script}");
    let (s, h, _) = get_page(&e, "", &script).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        h[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    assert!(
        h[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    assert_eq!(
        get_page(&e, "", "/assets/nope.js").await.0,
        StatusCode::NOT_FOUND
    );

    // Unknown pages get the app (which says so), with a 404; unknown endpoints get JSON.
    let (s, _, html) = get_page(&e, "", "/nowhere").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(is_app_page(&html));
    let (s, b) = ui_get(&e, "", "/ui/nowhere").await;
    assert_eq!(
        (s, &b["error"]["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );
}

#[tokio::test]
async fn ui_browse() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let t = token(&e, u, "files:write db:write").await;
    call(
        &e,
        req(
            "PUT",
            "/api/v1/files/notes/readme.md",
            &t,
            "# hello <script>",
        ),
    )
    .await;
    call(
        &e,
        req("POST", "/api/v1/files/app.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    seed(&e, u, "app.db", "CREATE TABLE \"we\"\"ird\"(x)");

    let (s, _, html) = get_page(&e, &cookie, "/files/notes/readme.md").await;
    assert_eq!(s, StatusCode::OK);
    assert!(is_app_page(&html));

    let (s, b) = ui_get(&e, &cookie, "/ui/session").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["user"]["username"], "alice");
    assert_eq!(b["user"]["is_admin"], false);

    let (s, b) = ui_get(&e, &cookie, "/ui/files").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (&b["kind"], &b["editable"], &b["path"]),
        (&json!("dir"), &json!(true), &json!(""))
    );
    assert_eq!(b["owner"]["username"], "alice");
    assert_eq!(b["quota"], 1 << 20);
    let kinds: Vec<(&str, &str)> = b["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap(), e["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("notes", "dir"), ("app.db", "db")]);

    let (_, b) = ui_get(&e, &cookie, "/ui/files?path=notes").await;
    assert_eq!(b["entries"][0]["name"], "readme.md");
    assert_eq!(b["entries"][0]["size"], 16);

    let (_, b) = ui_get(&e, &cookie, "/ui/files?path=notes/readme.md").await;
    assert_eq!(b["kind"], "file");
    assert_eq!(b["text"], "# hello <script>");
    assert_eq!(
        (&b["editable"], &b["crlf"], &b["truncated"]),
        (&json!(true), &json!(false), &json!(false))
    );
    assert!(b["etag"].as_str().unwrap().starts_with('"'));

    let (_, b) = ui_get(&e, &cookie, "/ui/files?path=app.db").await;
    assert_eq!(b["kind"], "db");
    let (s, b) = ui_get(&e, &cookie, "/ui/files?path=nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
    let (s, _) = ui_get(&e, &cookie, "/ui/files?path=../x").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (_, b) = ui_get(&e, &cookie, "/ui/db?path=app.db").await;
    assert_eq!(b["tables"][0]["name"], "we\"ird");
    assert_eq!(b["writable"], true);
    let (_, b) = ui_get(
        &e,
        &cookie,
        &format!("/ui/db?path=app.db&table={}", enc("we\"ird")),
    )
    .await;
    assert_eq!(b["table"]["rows"], json!([]));
    let (_, b) = ui_get(&e, &cookie, "/ui/db?path=app.db&table=nope").await;
    assert_eq!(b["error"], "no table named nope");

    let (s, b) = ui_get(&e, &cookie, "/ui/settings").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["tokens"][0]["scopes"], "files:write db:write");
    assert_eq!(b["origin"], "http://localhost:8080");

    // Non-admins can't see admin data.
    let (s, _) = ui_get(&e, &cookie, "/ui/admin").await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // raw download is an attachment with sandbox CSP
    let (s, h, _) = get_page(&e, &cookie, "/raw/notes/readme.md").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        h[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );

    // SQL console
    let (s, b) = ui_post(
        &e,
        &cookie,
        "/ui/db/sql",
        json!({"path": "app.db", "sql": "CREATE TABLE t(a); INSERT INTO t VALUES(1),(2)"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(
        b["message"].as_str().unwrap().contains("2 row(s) changed"),
        "{b}"
    );
    assert_eq!(
        b["tables"].as_array().unwrap().len(),
        2,
        "the schema is re-read"
    );
    let (_, b) = ui_post(
        &e,
        &cookie,
        "/ui/db/sql",
        json!({"path": "app.db", "sql": "SELECT a FROM t"}),
    )
    .await;
    assert_eq!(b["message"], "2 row(s)");
    assert_eq!(
        b["result"]["rows"][1][0],
        json!({"text": "2", "class": "num"})
    );
    let (_, b) = ui_post(
        &e,
        &cookie,
        "/ui/db/sql",
        json!({"path": "app.db", "sql": "SELEC"}),
    )
    .await;
    assert!(b["error"].is_string(), "{b}");

    // raw download of a database is a snapshot attachment
    let r = Request::get("/raw/app.db")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let (s, h, b) = call(&e, r).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.starts_with(b"SQLite format 3\0"));
    assert!(
        h[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
}

#[tokio::test]
async fn ui_create_and_edit() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let files = e.state.store(u).files_dir();

    let (s, b) = ui_post(
        &e,
        &cookie,
        "/ui/new",
        json!({"dir": "", "name": "docs", "kind": "folder"}),
    )
    .await;
    assert_eq!((s, &b["path"]), (StatusCode::OK, &json!("docs")));
    assert!(files.join("docs").is_dir());

    let new_text = json!({"dir": "docs", "name": "a.txt", "kind": "text"});
    let (s, b) = ui_post(&e, &cookie, "/ui/new", new_text.clone()).await;
    assert_eq!((s, &b["path"]), (StatusCode::OK, &json!("docs/a.txt")));
    assert_eq!(std::fs::read(files.join("docs/a.txt")).unwrap(), b"");
    // creating it again doesn't clobber it
    let (s, _) = ui_post(&e, &cookie, "/ui/new", new_text).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = ui_post(
        &e,
        &cookie,
        "/ui/new",
        json!({"dir": "docs", "name": "a/b", "kind": "folder"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // The editor round-trips the etag, and gets the new one back.
    let (_, b) = ui_get(&e, &cookie, "/ui/files?path=docs/a.txt").await;
    let save =
        |etag: &Value| json!({"path": "docs/a.txt", "etag": etag, "content": "line 1\r\nline 2"});
    let (s, saved) = ui_post(&e, &cookie, "/ui/save", save(&b["etag"])).await;
    assert_eq!(s, StatusCode::OK, "{saved}");
    assert_eq!(
        std::fs::read(files.join("docs/a.txt")).unwrap(),
        b"line 1\r\nline 2",
        "saved as sent"
    );
    let (_, b2) = ui_get(&e, &cookie, "/ui/files?path=docs/a.txt").await;
    assert_eq!(saved["etag"], b2["etag"]);
    assert_eq!(b2["crlf"], true);
    // A stale etag is refused.
    let (s, _) = ui_post(&e, &cookie, "/ui/save", save(&b["etag"])).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Rename and delete.
    let (s, b) = ui_post(
        &e,
        &cookie,
        "/ui/rename",
        json!({"path": "docs/a.txt", "new_name": "b.txt"}),
    )
    .await;
    assert_eq!((s, &b["path"]), (StatusCode::OK, &json!("docs/b.txt")));
    assert!(files.join("docs/b.txt").is_file());
    let (s, _) = ui_post(&e, &cookie, "/ui/delete", json!({"path": "docs/b.txt"})).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!files.join("docs/b.txt").exists());

    let (s, b) = ui_post(
        &e,
        &cookie,
        "/ui/new",
        json!({"dir": "docs", "name": "app.db", "kind": "sqlite"}),
    )
    .await;
    assert_eq!((s, &b["path"]), (StatusCode::OK, &json!("docs/app.db")));
    let (s, b) = ui_get(&e, &cookie, "/ui/db?path=docs/app.db").await;
    assert_eq!((s, &b["tables"]), (StatusCode::OK, &json!([])));

    // Upload: the folder comes first, then the files.
    let body = "--X\r\nContent-Disposition: form-data; name=\"dir\"\r\n\r\ndocs\r\n\
                --X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"up.txt\"\r\n\r\nuploaded\r\n\
                --X--\r\n";
    let r = Request::post("/ui/upload")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=X")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body))
        .unwrap();
    let (s, _, b) = call(&e, r).await;
    assert_eq!((s, j(&b)["count"].clone()), (StatusCode::OK, json!(1)));
    assert_eq!(
        std::fs::read(files.join("docs/up.txt")).unwrap(),
        b"uploaded"
    );
}

#[tokio::test]
async fn ui_csrf_guard() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let form = |site: Option<&str>, origin: Option<&str>| {
        let mut b = Request::post("/ui/new")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(s) = site {
            b = b.header("sec-fetch-site", s);
        }
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(Body::from(r#"{"dir":"","name":"x","kind":"folder"}"#))
            .unwrap()
    };
    assert_eq!(
        call(&e, form(Some("cross-site"), Some("https://evil.example")))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&e, form(None, Some("https://evil.example"))).await.0,
        StatusCode::FORBIDDEN
    );
    assert!(!e.state.store(u).files_dir().join("x").exists());
    assert_eq!(
        call(&e, form(Some("same-origin"), Some("http://localhost:8080")))
            .await
            .0,
        StatusCode::OK
    );
    assert!(e.state.store(u).files_dir().join("x").is_dir());
}

/// What the signup page is told about an invite.
async fn signup_info(e: &Env, invite: &str) -> Value {
    ui_get(e, "", &format!("/ui/signup?invite={}", enc(invite)))
        .await
        .1
}

#[tokio::test]
async fn signup_policy() {
    let e = env();
    let start = |body: Value| {
        Request::post("/auth/register/start")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    // Bootstrap: no users, no invite -> refused.
    assert_eq!(
        call(&e, start(json!({"username": "root"}))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(signup_info(&e, "").await["allowed"], false);
    let invite = bisonbase::bootstrap_invite(&e.state)
        .await
        .unwrap()
        .unwrap();
    let tok = invite.split("invite=").nth(1).unwrap();
    let i = signup_info(&e, tok).await;
    assert_eq!(i["allowed"], true);
    assert!(
        i["notice"].as_str().unwrap().contains("administrator"),
        "{i}"
    );
    let (s, _, b) = call(&e, start(json!({"username": "root", "invite": tok}))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(j(&b)["options"]["publicKey"]["challenge"].is_string());

    user(&e, "alice").await;
    // default mode is invite-only
    assert_eq!(
        call(&e, start(json!({"username": "bob"}))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        signup_info(&e, "").await,
        json!({"allowed": false, "notice": "Signups are invite-only."})
    );
    e.state
        .sys
        .set_signup_mode(bisonbase::system::SignupMode::Open)
        .await
        .unwrap();
    assert_eq!(
        signup_info(&e, "").await,
        json!({"allowed": true, "notice": ""})
    );
    assert_eq!(ui_get(&e, "", "/ui/session").await.1["signup_open"], true);
    assert_eq!(
        call(&e, start(json!({"username": "bob"}))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&e, start(json!({"username": "alice"}))).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(&e, start(json!({"username": "x"}))).await.0,
        StatusCode::BAD_REQUEST
    );
    e.state
        .sys
        .set_signup_mode(bisonbase::system::SignupMode::Closed)
        .await
        .unwrap();
    assert_eq!(
        call(&e, start(json!({"username": "bob"}))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(signup_info(&e, "nope").await["allowed"], false);
}

// ---- database editor ----

#[tokio::test]
async fn ui_row_editing() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let t = token(&e, u, "db:write").await;
    call(
        &e,
        req("POST", "/api/v1/files/app.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    seed(
        &e,
        u,
        "app.db",
        "CREATE TABLE items(id INTEGER PRIMARY KEY, title TEXT NOT NULL, n REAL, b BLOB);
         INSERT INTO items(title, n) VALUES ('first', 1.5);
         CREATE VIEW v AS SELECT title FROM items;",
    );
    let q = |sql: &str| peek(&e, u, "app.db", sql);

    // The landing page previews tables, read-only; views aren't previewed.
    let (s, b) = ui_get(&e, &cookie, "/ui/db?path=app.db").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b["table"].is_null());
    assert_eq!(b["previews"].as_array().unwrap().len(), 1, "{b}");
    assert_eq!(b["previews"][0]["name"], "items");
    assert_eq!(
        b["previews"][0]["rows"][0][1],
        json!({"text": "first", "class": ""})
    );
    assert_eq!(b["previews"][0]["more"], false);
    assert_eq!(b["previews_omitted"], 0);

    // A table's rows carry keys and versions for editing; a view's don't.
    let (s, b) = ui_get(&e, &cookie, "/ui/db?path=app.db&table=items").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let tv = &b["table"];
    assert_eq!(
        (&tv["can_edit"], &tv["can_delete"], &tv["can_insert"]),
        (&json!(true), &json!(true), &json!(true))
    );
    assert_eq!(tv["rows"][0]["key"], "[1]");
    assert_eq!(tv["columns"], json!(["id", "title", "n", "b"]));
    let (_, b) = ui_get(&e, &cookie, "/ui/db?path=app.db&table=v").await;
    assert_eq!(
        (&b["table"]["can_edit"], &b["table"]["can_insert"]),
        (&json!(false), &json!(false))
    );
    assert!(b["table"]["rows"][0]["key"].is_null());
    let (s, _) = ui_get(&e, &cookie, "/ui/db/row?path=app.db&table=v").await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The insert form starts with defaults where the column has one.
    let (s, f) = ui_get(&e, &cookie, "/ui/db/row?path=app.db&table=items").await;
    assert_eq!(s, StatusCode::OK, "{f}");
    assert!(f["key"].is_null());
    let kinds: Vec<&str> = f["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["default", "text", "default", "default"]);
    assert_eq!(f["fields"][0]["options"][0], json!(["default", "default"]));

    // Insert: defaults for unset columns, typed values for the rest.
    let insert = |n: &str| {
        json!({"path": "app.db", "table": "items", "action": "insert", "values": [
            {"name": "id", "type": "default"},
            {"name": "title", "type": "text", "value": "two\nlines"},
            {"name": "n", "type": "integer", "value": n},
            {"name": "b", "type": "blob", "value": "00 ff"},
        ]})
    };
    let (s, b) = ui_post(&e, &cookie, "/ui/db/row", insert("42")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(
        b["message"].as_str().unwrap().starts_with("Row inserted"),
        "{b}"
    );
    let r = q("SELECT title, n, typeof(n), hex(b) FROM items WHERE id = 2");
    // REAL affinity stores 42 as 42.0.
    assert_eq!(r["rows"][0], json!(["two\nlines", 42.0, "real", "00FF"]));

    // Bad values are rejected with a message and nothing changes.
    let (s, b) = ui_post(&e, &cookie, "/ui/db/row", insert("abc")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"]["message"], "n: 'abc' is not an integer");

    // Edit: the form carries the row's version; only changed columns are written.
    let (_, f) = ui_get(
        &e,
        &cookie,
        &format!("/ui/db/row?path=app.db&table=items&key={}", enc("[1]")),
    )
    .await;
    assert_eq!(f["key"], "[1]");
    assert_eq!(f["fields"][1]["value"], "first");
    assert_eq!(f["fields"][2]["kind"], "real");
    let version = f["version"].as_str().unwrap().to_string();
    let update = |title: &str| {
        json!({"path": "app.db", "table": "items", "action": "update", "key": "[1]", "version": version, "values": [
            {"name": "title", "type": "text", "value": title},
            {"name": "n", "type": "real", "value": "1.5"},
        ]})
    };
    let (s, b) = ui_post(&e, &cookie, "/ui/db/row", update("renamed")).await;
    assert_eq!(
        (s, &b["message"]),
        (StatusCode::OK, &json!("Updated 1 column(s)")),
        "{b}"
    );
    // The same (now stale) version is refused.
    let (s, _) = ui_post(&e, &cookie, "/ui/db/row", update("again")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        q("SELECT title FROM items WHERE id = 1")["rows"][0][0],
        "renamed"
    );
    let (s, _) = ui_get(
        &e,
        &cookie,
        &format!("/ui/db/row?path=app.db&table=items&key={}", enc("[9]")),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Delete, using the version from the grid.
    let (_, b) = ui_get(&e, &cookie, "/ui/db?path=app.db&table=items").await;
    let row = &b["table"]["rows"][0];
    let (s, b) = ui_post(
        &e,
        &cookie,
        "/ui/db/row",
        json!({"path": "app.db", "table": "items", "action": "delete", "key": row["key"], "version": row["version"]}),
    )
    .await;
    assert_eq!((s, &b["message"]), (StatusCode::OK, &json!("Row deleted")));
    assert_eq!(q("SELECT count(*) FROM items")["rows"][0][0], 1);
}

async fn admin(e: &Env, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    e.state
        .sys
        .create_user(
            id,
            name.into(),
            true,
            None,
            format!("cred-{name}"),
            "{}".into(),
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn admin_browses_user_data_read_only() {
    let e = env();
    let root = admin(&e, "root").await;
    let alice = user(&e, "alice").await;
    let rc = session(&e, root).await;
    let ac = session(&e, alice).await;
    let t = token(&e, alice, "files:write db:write").await;
    call(
        &e,
        req("PUT", "/api/v1/files/notes/a.txt", &t, "secret notes"),
    )
    .await;
    call(
        &e,
        req("POST", "/api/v1/files/app.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    seed(
        &e,
        alice,
        "app.db",
        "CREATE TABLE t(x); INSERT INTO t VALUES ('hello');",
    );

    let (s, _, html) = get_page(&e, &rc, &format!("/admin/users/{alice}/files/notes")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(is_app_page(&html));

    let (s, b) = ui_get(&e, &rc, &format!("/ui/files?owner={alice}")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (&b["owner"]["username"], &b["editable"]),
        (&json!("alice"), &json!(false))
    );
    let (_, b) = ui_get(
        &e,
        &rc,
        &format!("/ui/files?owner={alice}&path=notes/a.txt"),
    )
    .await;
    assert_eq!(
        (&b["text"], &b["editable"]),
        (&json!("secret notes"), &json!(false))
    );
    let (_, b) = ui_get(
        &e,
        &rc,
        &format!("/ui/db?owner={alice}&path=app.db&table=t"),
    )
    .await;
    let tv = &b["table"];
    assert_eq!(tv["rows"][0]["cells"][0]["text"], "hello");
    assert!(tv["rows"][0]["key"].is_null());
    assert!(tv["rows"][0]["cells"][0]["edit"].is_null());
    assert_eq!(
        (&tv["can_edit"], &tv["can_insert"], &b["writable"]),
        (&json!(false), &json!(false), &json!(false))
    );
    let (s, _) = ui_get(
        &e,
        &rc,
        &format!("/ui/db/row?owner={alice}&path=app.db&table=t"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let r = Request::get(format!("/admin/users/{alice}/raw/notes/a.txt"))
        .header(header::COOKIE, &rc)
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&e, r).await.2, b"secret notes");

    // The console is read-only for admins viewing someone else's database.
    let sql = |s: &str| json!({"owner": alice, "path": "app.db", "sql": s});
    let (_, b) = ui_post(&e, &rc, "/ui/db/sql", sql("DELETE FROM t")).await;
    assert!(
        b["error"]
            .as_str()
            .unwrap()
            .contains("only read-only statements"),
        "{b}"
    );
    let (_, b) = ui_post(&e, &rc, "/ui/db/sql", sql("SELECT count(*) FROM t")).await;
    assert_eq!(b["message"], "1 row(s)");

    // Non-admins can't look at others' trees or system.db.
    let (s, _) = ui_get(&e, &ac, &format!("/ui/files?owner={root}")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = ui_post(
        &e,
        &ac,
        "/ui/db/sql",
        json!({"owner": root, "path": "x.db", "sql": "SELECT 1"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = ui_get(&e, &ac, "/ui/sysdb").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = get_page(&e, &ac, &format!("/admin/users/{root}/raw/x")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = ui_get(&e, &rc, &format!("/ui/files?owner={}", Uuid::new_v4())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// The first row of a grid whose cells include `text`.
fn row_with<'a>(view: &'a Value, text: &str) -> &'a Value {
    view["table"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["cells"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["text"] == text)
        })
        .unwrap_or_else(|| panic!("no row with {text}: {view}"))
}

#[tokio::test]
async fn admin_system_db_allowlist() {
    let e = env();
    let root = admin(&e, "root").await;
    let alice = user(&e, "alice").await;
    let rc = session(&e, root).await;
    session(&e, alice).await;
    token(&e, alice, "files:read").await;

    // Every table is browsable; hashes and passkey data are masked.
    let (s, b) = ui_get(&e, &rc, "/ui/sysdb?table=api_tokens").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.to_string().contains("sha256:"), "{b}");
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=passkeys").await;
    assert!(b.to_string().contains("<passkey, 2 bytes>"), "{b}");
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=settings").await;
    assert_eq!(
        (&b["table"]["can_insert"], &b["writable"]),
        (&json!(false), &json!(false))
    );
    let (s, _) = ui_get(&e, &rc, "/ui/sysdb/row?table=settings").await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Landing page previews mask them too.
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb").await;
    let text = b.to_string();
    assert!(text.contains("sha256:"), "{text}");
    assert!(text.contains("<passkey, 2 bytes>"), "{text}");
    let hash: String = e
        .state
        .sys
        .call(|c| {
            Ok(
                c.query_row("SELECT token_hash FROM api_tokens LIMIT 1", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert!(!text.contains(&hash), "{text}");

    // Edit alice's username through the form.
    let (_, f) = ui_get(
        &e,
        &rc,
        &format!("/ui/sysdb/row?table=users&key={}", enc("[2]")),
    )
    .await;
    assert_eq!(f["fields"][1]["value"], "alice", "{f}");
    assert_eq!(f["fields"][0]["editable"], false);
    let version = f["version"].as_str().unwrap().to_string();
    let post = |values: Value| {
        let body = json!({"table": "users", "action": "update", "key": "[2]", "version": version, "values": values});
        ui_post(&e, &rc, "/ui/sysdb/row", body)
    };
    // Not allowlisted / invalid values are refused.
    let (s, _) = post(json!([{"name": "id", "type": "text", "value": "x"}])).await;
    assert!(s.is_client_error(), "{s}");
    let (s, _) = post(json!([{"name": "username", "type": "text", "value": "a b"}])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, b) = post(json!([
        {"name": "username", "type": "text", "value": "alicia"},
        {"name": "is_admin", "type": "integer", "value": "1"},
    ]))
    .await;
    assert_eq!(
        (s, &b["message"]),
        (StatusCode::OK, &json!("Updated 2 column(s)")),
        "{b}"
    );
    let u = e.state.sys.user_by_id(alice).await.unwrap().unwrap();
    assert_eq!((u.username.as_str(), u.is_admin), ("alicia", true));

    // Admins can't demote themselves.
    let (_, f) = ui_get(
        &e,
        &rc,
        &format!("/ui/sysdb/row?table=users&key={}", enc("[1]")),
    )
    .await;
    let body = json!({"table": "users", "action": "update", "key": "[1]", "version": f["version"],
        "values": [{"name": "is_admin", "type": "integer", "value": "0"}]});
    let (s, b) = ui_post(&e, &rc, "/ui/sysdb/row", body).await;
    assert!(s.is_client_error());
    assert!(
        b["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("you cannot"),
        "{b}"
    );

    // Signup mode is validated.
    e.state
        .sys
        .set_signup_mode(bisonbase::system::SignupMode::Invite)
        .await
        .unwrap();
    let (_, f) = ui_get(
        &e,
        &rc,
        &format!("/ui/sysdb/row?table=settings&key={}", enc("[1]")),
    )
    .await;
    let set = |mode: &str| {
        json!({"table": "settings", "action": "update", "key": "[1]", "version": f["version"],
            "values": [{"name": "value", "type": "text", "value": mode}]})
    };
    let (s, _) = ui_post(&e, &rc, "/ui/sysdb/row", set("everyone")).await;
    assert!(s.is_client_error());
    let (s, _) = ui_post(&e, &rc, "/ui/sysdb/row", set("open")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        e.state.sys.signup_mode().await.unwrap(),
        bisonbase::system::SignupMode::Open
    );

    // Deleting alice's only passkey is refused; deleting her token works.
    let delete = |table: &str, row: &Value| json!({"table": table, "action": "delete", "key": row["key"], "version": row["version"]});
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=passkeys").await;
    let (s, r) = ui_post(
        &e,
        &rc,
        "/ui/sysdb/row",
        delete("passkeys", row_with(&b, "cred-alice")),
    )
    .await;
    assert!(s.is_client_error());
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("cannot delete"),
        "{r}"
    );
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=api_tokens").await;
    let (s, r) = ui_post(
        &e,
        &rc,
        "/ui/sysdb/row",
        delete("api_tokens", &b["table"]["rows"][0]),
    )
    .await;
    assert_eq!(
        (s, &r["message"]),
        (StatusCode::OK, &json!("Row deleted")),
        "{r}"
    );
    assert!(e.state.sys.api_tokens(alice).await.unwrap().is_empty());

    // Rows can't be deleted from users, nor inserted anywhere.
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=users").await;
    assert_eq!(b["table"]["can_delete"], false);
    let (s, _) = ui_post(
        &e,
        &rc,
        "/ui/sysdb/row",
        delete("users", row_with(&b, "alicia")),
    )
    .await;
    assert!(s.is_client_error());
    let (s, _) = ui_post(
        &e,
        &rc,
        "/ui/sysdb/row",
        json!({"table": "settings", "action": "insert", "values": [{"name": "key", "type": "text", "value": "x"}]}),
    )
    .await;
    assert!(s.is_client_error());

    // Everything that changed is in the audit log.
    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=audit_log").await;
    let by_root = b["table"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["cells"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["text"] == "root")
        })
        .count();
    assert_eq!(by_root, 3, "{b}");
    assert!(b.to_string().contains("alicia"), "{b}");

    // The console is read-only, even for admins.
    for sql in [
        "DELETE FROM sessions",
        "PRAGMA foreign_keys = OFF",
        "ATTACH 'x.db' AS x",
        "UPDATE users SET is_admin = 1",
    ] {
        let (s, b) = ui_post(&e, &rc, "/ui/sysdb/sql", json!({ "sql": sql })).await;
        assert_eq!(s, StatusCode::OK);
        assert!(b["error"].is_string(), "{sql}: {b}");
    }
    let (_, b) = ui_post(
        &e,
        &rc,
        "/ui/sysdb/sql",
        json!({"sql": "SELECT username FROM users ORDER BY 1"}),
    )
    .await;
    assert_eq!(b["message"], "2 row(s)");
    assert_eq!(b["result"]["rows"][0][0]["text"], "alicia");
}

#[tokio::test]
async fn ui_inline_cell_editing() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let t = token(&e, u, "db:write").await;
    call(
        &e,
        req("POST", "/api/v1/files/app.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    seed(
        &e,
        u,
        "app.db",
        &format!(
            "CREATE TABLE items(id INTEGER PRIMARY KEY, title TEXT, n INTEGER, b BLOB);
             INSERT INTO items(title, n, b) VALUES ('{}', 1, x'00');",
            "x".repeat(600)
        ),
    );

    // Editable cells carry what the editor needs; long text carries its full value; blobs
    // aren't editable in place.
    let (_, b) = ui_get(&e, &cookie, "/ui/db?path=app.db&table=items").await;
    let row = &b["table"]["rows"][0];
    assert_eq!(row["key"], "[1]");
    let title = &row["cells"][1];
    assert_eq!(
        (
            &title["edit"]["col"],
            &title["edit"]["name"],
            &title["edit"]["kind"]
        ),
        (&json!(1), &json!("title"), &json!("text"))
    );
    assert_eq!(title["edit"]["full"], "x".repeat(600));
    assert!(title["text"].as_str().unwrap().ends_with('…'));
    assert_eq!(row["cells"][2]["edit"]["affinity"], "integer");
    assert!(row["cells"][3]["edit"].is_null(), "{row}");
    let version = row["version"].as_str().unwrap().to_string();

    // A multi-line edit returns the row's new version and cells.
    let edit = |version: &str, name: &str, ty: &str, value: &str| {
        json!({"path": "app.db", "table": "items", "action": "update", "key": "[1]", "version": version,
            "values": [{"name": name, "type": ty, "value": value}]})
    };
    let body = edit(&version, "title", "text", "line 1\nline 2");
    let (s, r) = ui_post(&e, &cookie, "/ui/db/row", body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["message"], "Updated 1 column(s)");
    assert_eq!(r["row"]["key"], "[1]");
    assert_ne!(r["row"]["version"], version.as_str());
    assert_eq!(r["row"]["cells"][1]["text"], "line 1\nline 2");
    assert_eq!(r["row"]["cells"][1]["edit"]["kind"], "text");
    assert!(r["row"]["cells"][3]["edit"].is_null());

    // Reusing the old version is a 409 with a JSON error.
    let (s, b) = ui_post(&e, &cookie, "/ui/db/row", body).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(b["error"]["message"].as_str().unwrap().contains("changed"));

    // Changing the INTEGER PRIMARY KEY changes the row's key.
    let v = r["row"]["version"].as_str().unwrap();
    let (s, b) = ui_post(&e, &cookie, "/ui/db/row", edit(v, "id", "integer", "7")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["row"]["key"], "[7]");
}

#[tokio::test]
async fn admin_inline_system_edit() {
    let e = env();
    let root = admin(&e, "root").await;
    let alice = user(&e, "alice").await;
    let rc = session(&e, root).await;

    let (_, b) = ui_get(&e, &rc, "/ui/sysdb?table=users").await;
    // Only allowlisted columns are editable in place.
    let row = row_with(&b, "alice");
    let editable: Vec<&str> = row["cells"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["edit"]["name"].as_str())
        .collect();
    assert!(editable.contains(&"username"), "{row}");
    assert!(
        !editable.contains(&"id") && !editable.contains(&"created_at"),
        "{row}"
    );
    let body = |name: &str| {
        json!({"table": "users", "action": "update", "key": row["key"], "version": row["version"],
            "values": [{"name": "username", "type": "text", "value": name}]})
    };
    let (s, b) = ui_post(&e, &rc, "/ui/sysdb/row", body("no spaces")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    let (s, b) = ui_post(&e, &rc, "/ui/sysdb/row", body("alicia")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["row"]["cells"][1]["text"], "alicia");
    let u = e.state.sys.user_by_id(alice).await.unwrap().unwrap();
    assert_eq!(u.username, "alicia");
}

// ---- OAuth ----

// The PKCE example from RFC 7636, appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const APP: &str = "http://localhost:3000";
const APP_REDIRECT: &str = "http://localhost:3000/callback";
const APP_ID: &str = "6fe50464-031a-44f9-aa9c-44d2ad8ac5e7";
const APP_NAME: &str = "Todo";

fn authorize_params(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut p: Vec<(String, String)> = [
        ("response_type", "code"),
        ("client_id", APP),
        ("redirect_uri", APP_REDIRECT),
        ("scope", "db:write"),
        ("state", "xyz"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("app_id", APP_ID),
        ("app_name", APP_NAME),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in overrides {
        p.retain(|(pk, _)| pk != k);
        if !v.is_empty() {
            p.push((k.to_string(), v.to_string()));
        }
    }
    p
}

fn encode(params: &[(String, String)]) -> String {
    let pairs: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    form_body(&pairs)
}

/// What the consent page asks the server: the details to show, or where to send the user.
async fn consent(e: &Env, cookie: &str, overrides: &[(&str, &str)]) -> (StatusCode, Value) {
    let uri = format!(
        "/ui/oauth/authorize?{}",
        encode(&authorize_params(overrides))
    );
    ui_get(e, cookie, &uri).await
}

/// Submit the consent form; returns the redirect target.
async fn authorize_post(
    e: &Env,
    cookie: &str,
    decision: &str,
    overrides: &[(&str, &str)],
) -> String {
    let mut p = authorize_params(overrides);
    p.retain(|(k, _)| k != "response_type" && k != "code_challenge_method");
    p.push(("decision".into(), decision.into()));
    let r = Request::post("/oauth/authorize")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(encode(&p)))
        .unwrap();
    let (s, h, b) = call(e, r).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{}", String::from_utf8_lossy(&b));
    h[header::LOCATION].to_str().unwrap().to_string()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let url = url::Url::parse(url).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

async fn token_post(e: &Env, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let r = Request::post("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ORIGIN, APP)
        .body(Body::from(form_body(fields)))
        .unwrap();
    let (s, h, b) = call(e, r).await;
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    (s, j(&b))
}

async fn exchange(e: &Env, code: &str, verifier: &str) -> (StatusCode, Value) {
    token_post(
        e,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", APP),
            ("redirect_uri", APP_REDIRECT),
            ("code_verifier", verifier),
        ],
    )
    .await
}

#[tokio::test]
async fn oauth_metadata() {
    let e = env();
    let (s, h, b) = call(
        &e,
        Request::get("/.well-known/oauth-authorization-server")
            .header(header::ORIGIN, APP)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    let m = j(&b);
    assert_eq!(m["issuer"], "http://localhost:8080");
    assert_eq!(
        m["authorization_endpoint"],
        "http://localhost:8080/oauth/authorize"
    );
    assert_eq!(m["token_endpoint"], "http://localhost:8080/oauth/token");
    assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(oauth_s256(VERIFIER), CHALLENGE);
}

fn oauth_s256(v: &str) -> String {
    bisonbase::oauth::s256(v)
}

#[tokio::test]
async fn oauth_flow() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;

    // Signed out: off to the login page, which comes back here afterwards.
    let page = format!("/oauth/authorize?{}", encode(&authorize_params(&[])));
    let (s, h, _) = get_page(&e, "", &page).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let to = h[header::LOCATION].to_str().unwrap();
    assert!(
        to.starts_with("/login?next=%2Foauth%2Fauthorize%3F"),
        "{to}"
    );

    // Signed in: the consent page (which can't be framed) names the app and what it may do.
    let (s, h, html) = get_page(&e, &cookie, &page).await;
    assert_eq!(s, StatusCode::OK, "{html}");
    assert!(is_app_page(&html));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    let (s, c) = consent(&e, &cookie, &[]).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(
        (&c["app_name"], &c["origin"], &c["username"], &c["local"]),
        (
            &json!("Todo"),
            &json!("http://localhost:3000"),
            &json!("alice"),
            &json!(true)
        )
    );
    assert_eq!(c["folder"], format!("/apps/{APP_ID}"));
    assert_eq!(
        c["permissions"],
        json!(["Create databases in its folder, and read and change them"]),
        "no file access was requested"
    );
    assert_eq!(
        (&c["scope"], &c["state"], &c["code_challenge"]),
        (&json!("db:write"), &json!("xyz"), &json!(CHALLENGE))
    );

    // Declining sends the app an error.
    let to = authorize_post(&e, &cookie, "deny", &[]).await;
    assert!(
        to.starts_with(&format!("{APP_REDIRECT}?error=access_denied&")),
        "{to}"
    );
    assert_eq!(query_param(&to, "state").as_deref(), Some("xyz"));
    assert_eq!(
        query_param(&to, "iss").as_deref(),
        Some("http://localhost:8080")
    );

    // Allowing sends a code, which only works with the right verifier, and only once.
    let to = authorize_post(&e, &cookie, "allow", &[]).await;
    assert!(to.starts_with(&format!("{APP_REDIRECT}?code=")), "{to}");
    assert_eq!(query_param(&to, "state").as_deref(), Some("xyz"));
    assert_eq!(
        query_param(&to, "iss").as_deref(),
        Some("http://localhost:8080")
    );
    let code = query_param(&to, "code").unwrap();
    let (s, b) = exchange(&e, &code, "wrong-verifier-wrong-verifier-wrong-verifier-x").await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (s, b) = exchange(&e, &code, VERIFIER).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "a failed exchange burns the code"
    );

    let to = authorize_post(&e, &cookie, "allow", &[]).await;
    let code = query_param(&to, "code").unwrap();
    let (s, b) = exchange(&e, &code, VERIFIER).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["token_type"], "Bearer");
    assert_eq!(b["scope"], "db:write");
    assert_eq!(b["expires_in"], 30 * 24 * 3600);
    assert_eq!(b["folder"], format!("apps/{APP_ID}"));
    let t = b["access_token"].as_str().unwrap().to_string();
    let (s, b) = exchange(&e, &code, VERIFIER).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // The token has exactly the scopes that were granted, in the app's folder only.
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            &format!("/api/v1/files/apps/{APP_ID}/todo.db?op=mkdb"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            "/api/v1/files/apps/todo.db?op=mkdb",
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &e,
        req(
            "PUT",
            &format!("/api/v1/files/apps/{APP_ID}/a.txt"),
            &t,
            "hi",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // It shows up as a connected app rather than an API token.
    let (_, b) = ui_get(&e, &cookie, "/ui/settings").await;
    let app = &b["apps"][0];
    assert_eq!(
        (&app["client_id"], &app["name"]),
        (&json!(APP), &json!("Todo")),
        "{b}"
    );
    assert_eq!(app["folder"], format!("/apps/{APP_ID}"));
    assert_eq!(b["tokens"], json!([]));

    // Revoking it works without any other credentials.
    let r = Request::post("/oauth/revoke")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form_body(&[("token", &t)])))
        .unwrap();
    let (s, _, _) = call(&e, r).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &e,
        req(
            "GET",
            &format!("/api/v1/files/apps/{APP_ID}"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oauth_disconnect_app() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let mut tokens = vec![];
    for _ in 0..2 {
        let to = authorize_post(&e, &cookie, "allow", &[("scope", "files:read db:read")]).await;
        let (_, b) = exchange(&e, &query_param(&to, "code").unwrap(), VERIFIER).await;
        assert_eq!(b["scope"], "files:read db:read");
        tokens.push(b["access_token"].as_str().unwrap().to_string());
    }
    let apps = e.state.sys.connected_apps(u).await.unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].tokens, 2);

    let (s, _) = ui_post(
        &e,
        &cookie,
        "/ui/apps/disconnect",
        json!({ "app_id": APP_ID }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    for t in &tokens {
        let (s, _, _) = call(&e, req("GET", "/api/v1/files/", t, Body::empty())).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert!(e.state.sys.connected_apps(u).await.unwrap().is_empty());
}

#[tokio::test]
async fn oauth_rejects_bad_authorization_requests() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;

    // Problems with the client or redirect URI are shown, never redirected to.
    for overrides in [
        &[("redirect_uri", "https://evil.example/callback")][..],
        &[
            ("client_id", "http://app.example.com"),
            ("redirect_uri", "http://app.example.com/cb"),
        ],
        &[("client_id", "javascript:alert(1)")],
        &[("redirect_uri", "http://localhost:3000/cb#frag")],
        &[("redirect_uri", "")],
        &[("client_id", "")],
    ] {
        let (s, b) = consent(&e, &cookie, overrides).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{overrides:?}: {b}");
        assert!(b["redirect"].is_null());
    }
    // https apps on any host are fine.
    let (s, _) = consent(
        &e,
        &cookie,
        &[
            ("client_id", "https://app.example.com"),
            ("redirect_uri", "https://app.example.com/cb"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Other problems go back to the app.
    for (overrides, error) in [
        (&[("code_challenge", "")][..], "invalid_request"),
        (&[("code_challenge", "short")], "invalid_request"),
        (&[("code_challenge_method", "plain")], "invalid_request"),
        (&[("code_challenge_method", "")], "invalid_request"),
        (&[("scope", "")], "invalid_scope"),
        (&[("scope", "db:write admin")], "invalid_scope"),
        (&[("response_type", "token")], "unsupported_response_type"),
        (&[("app_id", "")], "invalid_request"),
        (&[("app_id", "todo")], "invalid_request"),
        (
            &[("app_id", "00000000-0000-0000-0000-000000000000")],
            "invalid_request",
        ),
        (&[("app_name", "")], "invalid_request"),
        (&[("app_name", "  ")], "invalid_request"),
        (&[("app_name", "a\nb")], "invalid_request"),
        (&[("app_name", &"x".repeat(61))], "invalid_request"),
    ] {
        let (s, b) = consent(&e, &cookie, overrides).await;
        assert_eq!(s, StatusCode::OK, "{overrides:?}: {b}");
        let to = b["redirect"].as_str().unwrap();
        assert!(to.starts_with(APP_REDIRECT), "{to}");
        assert_eq!(
            query_param(to, "error").as_deref(),
            Some(error),
            "{overrides:?}"
        );
        assert_eq!(query_param(to, "state").as_deref(), Some("xyz"));
    }

    // The consent form can't be submitted from another site.
    let r = Request::post("/oauth/authorize")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header(header::ORIGIN, APP)
        .body(Body::from(encode(&authorize_params(&[(
            "decision", "allow",
        )]))))
        .unwrap();
    let (s, _, _) = call(&e, r).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn oauth_rejects_bad_token_requests() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let code = || async {
        let to = authorize_post(&e, &cookie, "allow", &[]).await;
        query_param(&to, "code").unwrap()
    };

    let c = code().await;
    let (s, b) = token_post(&e, &[("grant_type", "password"), ("code", &c)]).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("unsupported_grant_type"))
    );
    let (s, b) = token_post(&e, &[("grant_type", "authorization_code"), ("code", &c)]).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );

    let c = code().await;
    let (s, b) = token_post(
        &e,
        &[
            ("grant_type", "authorization_code"),
            ("code", &c),
            ("client_id", "http://localhost:4000"),
            ("redirect_uri", APP_REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    let c = code().await;
    let (s, b) = token_post(
        &e,
        &[
            ("grant_type", "authorization_code"),
            ("code", &c),
            ("client_id", APP),
            ("redirect_uri", "http://localhost:3000/other"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    let (s, b) = exchange(&e, "not-a-code", VERIFIER).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // Expired codes don't work.
    let c = e
        .state
        .sys
        .create_oauth_code(
            u,
            APP_ID.parse().unwrap(),
            APP.into(),
            APP_REDIRECT.into(),
            "db:read".into(),
            CHALLENGE.into(),
            0,
        )
        .await
        .unwrap();
    let (s, b) = exchange(&e, &c, VERIFIER).await;
    assert_eq!(
        (s, b["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // JSON isn't the token endpoint's format.
    let r = Request::post("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"grant_type":"authorization_code"}"#))
        .unwrap();
    let (s, _, b) = call(&e, r).await;
    assert_eq!(
        (s, j(&b)["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
}

/// Sign in to an app and return its token.
async fn app_token(e: &Env, cookie: &str, overrides: &[(&str, &str)]) -> String {
    let to = authorize_post(e, cookie, "allow", overrides).await;
    let code = query_param(&to, "code").unwrap_or_else(|| panic!("{to}"));
    let redirect = overrides
        .iter()
        .find(|(k, _)| *k == "redirect_uri")
        .map_or(APP_REDIRECT, |(_, v)| v);
    let client = overrides
        .iter()
        .find(|(k, _)| *k == "client_id")
        .map_or(APP, |(_, v)| v);
    let (s, b) = token_post(
        e,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", client),
            ("redirect_uri", redirect),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn oauth_apps_only_reach_their_folder() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let personal = token(&e, u, "files:write db:write").await;
    let (s, _, _) = call(
        &e,
        req("PUT", "/api/v1/files/notes.txt", &personal, "secret"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    let t = app_token(&e, &cookie, &[("scope", "files:write db:write")]).await;
    let mine = format!("/api/v1/files/apps/{APP_ID}");
    let other = "/api/v1/files/apps/b04d2f10-f757-448c-be5c-d965ff675597";

    // Inside its folder, anything the scopes allow.
    let (s, _, _) = call(&e, req("PUT", &format!("{mine}/a.txt"), &t, "hi")).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, b) = call(&e, req("GET", &mine, &t, Body::empty())).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j(&b)["entries"][0]["name"], "a.txt");
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            &format!("{mine}/a.txt?op=move&to=apps/{APP_ID}/b.txt"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Everywhere else, nothing: not the root, other files, other apps' folders, or odd spellings.
    for (method, uri) in [
        ("GET", "/api/v1/files/".to_string()),
        ("GET", "/api/v1/files/apps".to_string()),
        ("GET", "/api/v1/files/notes.txt".to_string()),
        ("PUT", "/api/v1/files/notes.txt".to_string()),
        ("DELETE", "/api/v1/files/notes.txt".to_string()),
        ("GET", format!("{other}/x.db?op=schema")),
        ("POST", format!("{other}/x.db?op=mkdb")),
        ("POST", "/api/v1/files/notes.db?op=select".to_string()),
        (
            "GET",
            format!("/api/v1/files/apps/{}", APP_ID.to_uppercase()),
        ),
        (
            "GET",
            format!("/api/v1/files/apps/{}", APP_ID.replace('-', "")),
        ),
        ("POST", format!("{mine}/b.txt?op=move&to=stolen.txt")),
        (
            "POST",
            format!("/api/v1/files/notes.txt?op=move&to=apps/{APP_ID}/n.txt"),
        ),
    ] {
        let (s, _, b) = call(&e, req(method, &uri, &t, "x")).await;
        assert_eq!(
            s,
            StatusCode::FORBIDDEN,
            "{method} {uri}: {}",
            String::from_utf8_lossy(&b)
        );
    }
    let (_, _, b) = call(
        &e,
        req("GET", "/api/v1/files/notes.txt", &personal, Body::empty()),
    )
    .await;
    assert_eq!(b, b"secret");

    // Personal tokens still reach everything, app folders included.
    let (s, _, _) = call(
        &e,
        req("GET", &format!("{mine}/b.txt"), &personal, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn oauth_app_ids_belong_to_one_origin() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    app_token(&e, &cookie, &[]).await;

    // Another app can't claim the id, so it can't get into that folder.
    let evil = [
        ("client_id", "http://evil.localhost:3000"),
        ("redirect_uri", "http://evil.localhost:3000/cb"),
    ];
    let (s, b) = consent(&e, &cookie, &evil).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let to = b["redirect"].as_str().unwrap();
    assert!(
        to.starts_with("http://evil.localhost:3000/cb?error=invalid_request"),
        "{to}"
    );
    let to = authorize_post(&e, &cookie, "allow", &evil).await;
    assert!(query_param(&to, "code").is_none(), "{to}");

    // The same app may rename itself; its folder label follows.
    app_token(&e, &cookie, &[("app_name", "Todo list")]).await;
    let apps = e.state.sys.apps(u).await.unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].name, "Todo list");
    assert_eq!(apps[0].origin, APP);

    // Another user has their own apps, so the id is free for them.
    let bob = user(&e, "bob").await;
    let bob_cookie = session(&e, bob).await;
    app_token(&e, &bob_cookie, &evil).await;
}

#[tokio::test]
async fn ui_labels_app_folders() {
    let e = env();
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let t = app_token(&e, &cookie, &[]).await;
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            &format!("/api/v1/files/apps/{APP_ID}/todo.db?op=mkdb"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Listings in apps/ come with the names of the apps whose folders these are.
    let (s, b) = ui_get(&e, &cookie, "/ui/files?path=apps").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["entries"][0]["name"], APP_ID);
    assert_eq!(b["apps"][APP_ID]["name"], "Todo", "{b}");
    assert!(b["apps"][APP_ID]["hue"].is_u64());
    // So do pages inside them, for the breadcrumbs.
    let (_, b) = ui_get(
        &e,
        &cookie,
        &format!("/ui/files?path=apps/{APP_ID}/todo.db"),
    )
    .await;
    assert_eq!(
        (&b["kind"], &b["apps"][APP_ID]["name"]),
        (&json!("db"), &json!("Todo"))
    );
    // Elsewhere, no names are looked up.
    let (_, b) = ui_get(&e, &cookie, "/ui/files").await;
    assert_eq!(b["apps"], json!({}));
}

#[tokio::test]
async fn rate_limits() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    cfg.resolve(8080).unwrap();
    cfg.rate_limit.auth_per_minute = 3;
    cfg.rate_limit.api_per_minute = 5;
    cfg.rate_limit.trust_proxy_headers = true;
    std::fs::create_dir_all(dir.path().join("users")).unwrap();
    let sys = SystemDb::open(&dir.path().join("system.db")).unwrap();
    let state = AppState::new(cfg, sys).unwrap();
    let e = Env {
        app: bisonbase::app(state.clone()),
        state,
        _dir: dir,
    };

    let login = |ip: &str| {
        Request::post("/auth/login/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", "same-origin")
            .header("x-forwarded-for", format!("1.2.3.4, {ip}"))
            .body(Body::from(r#"{"username":"nobody"}"#))
            .unwrap()
    };
    for _ in 0..3 {
        let (s, _, _) = call(&e, login("10.0.0.1")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST); // unknown user, but not limited
    }
    let (s, h, b) = call(&e, login("10.0.0.1")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(h.contains_key(header::RETRY_AFTER));
    assert_eq!(j(&b)["error"]["code"], "rate_limited");
    // Another client still gets through; only the last X-Forwarded-For entry counts.
    let (s, _, _) = call(&e, login("10.0.0.2")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // The API is limited per token.
    let u = user(&e, "alice").await;
    let (t1, t2) = (
        token(&e, u, "files:read").await,
        token(&e, u, "files:read").await,
    );
    for _ in 0..5 {
        let (s, _, _) = call(&e, req("GET", "/api/v1/files/", &t1, Body::empty())).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, h, _) = call(&e, req("GET", "/api/v1/files/", &t1, Body::empty())).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    let (s, _, _) = call(&e, req("GET", "/api/v1/files/", &t2, Body::empty())).await;
    assert_eq!(s, StatusCode::OK);
    // Pages aren't limited.
    let (s, _, _) = call(&e, Request::get("/login").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn admin_deletes_user() {
    let e = env();
    let a = admin(&e, "root").await;
    let u = user(&e, "bob").await;
    let t = token(&e, u, "files:write").await;
    let (s, _, _) = call(&e, req("PUT", "/api/v1/files/a.txt", &t, "hi")).await;
    assert_eq!(s, StatusCode::CREATED);
    let cookie = session(&e, a).await;

    // The username must be typed to confirm.
    let del = |id: Uuid, confirm: &str| json!({ "id": id, "confirm": confirm });
    let (s, _) = ui_post(&e, &cookie, "/ui/admin/users/delete", del(u, "bobby")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(e.state.sys.user_by_id(u).await.unwrap().is_some());

    // Admins can't delete themselves.
    let (s, _) = ui_post(&e, &cookie, "/ui/admin/users/delete", del(a, "root")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, b) = ui_post(&e, &cookie, "/ui/admin/users/delete", del(u, "Bob")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(e.state.sys.user_by_id(u).await.unwrap().is_none());
    assert!(!e._dir.path().join("users").join(u.to_string()).exists());
    let (s, _, _) = call(&e, req("GET", "/api/v1/files/a.txt", &t, Body::empty())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, b) = ui_get(&e, &cookie, "/ui/sysdb?table=audit_log").await;
    assert!(b.to_string().contains("delete_user"));
    let (_, b) = ui_get(&e, &cookie, "/ui/admin").await;
    assert_eq!(b["users"].as_array().unwrap().len(), 1, "{b}");

    // Non-admins can't.
    let v = user(&e, "carol").await;
    let c2 = session(&e, v).await;
    let (s, _) = ui_post(&e, &c2, "/ui/admin/users/delete", del(a, "root")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_recovery_links() {
    let e = env();
    let a = admin(&e, "root").await;
    let u = user(&e, "bob").await;
    let cookie = session(&e, a).await;
    let (s, b) = ui_post(&e, &cookie, "/ui/admin/users/recover", json!({ "id": u })).await;
    assert_eq!((s, &b["username"]), (StatusCode::OK, &json!("bob")), "{b}");
    let url = b["url"].as_str().unwrap();
    let path = url.strip_prefix(&e.state.cfg.origin).unwrap().to_string();
    assert!(path.starts_with("/recover?token="), "{path}");
    let tok = path.split('=').nth(1).unwrap().to_string();

    let (s, _, html) = get_page(&e, "", &path).await;
    assert_eq!(s, StatusCode::OK);
    assert!(is_app_page(&html));
    let (_, b) = ui_get(&e, "", &format!("/ui/recover?token={tok}")).await;
    assert_eq!(b["username"], "bob");
    let (_, b) = ui_get(&e, "", "/ui/recover?token=nope").await;
    assert!(b["username"].is_null());

    // A recovery link isn't a signup invite.
    assert!(e.state.sys.valid_invite(&tok).await.unwrap().is_none());
    let (_, b) = ui_get(&e, "", &format!("/ui/signup?invite={tok}")).await;
    assert_eq!(b["allowed"], false);
    assert!(
        b["notice"]
            .as_str()
            .unwrap()
            .contains("invalid, already used, or expired")
    );

    // Starting the ceremony works with the link and not without.
    let start = |t: &str| {
        Request::post("/auth/recover/start")
            .header(header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(json!({ "token": t }).to_string()))
            .unwrap()
    };
    let (s, _, b) = call(&e, start(&tok)).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert!(j(&b)["ceremony"].is_string());
    let (s, _, _) = call(&e, start("nope")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Deleting the user deletes their recovery links.
    e.state
        .sys
        .delete_user(
            &e.state.sys.user_by_id(a).await.unwrap().unwrap(),
            &e.state.sys.user_by_id(u).await.unwrap().unwrap(),
        )
        .await
        .unwrap();
    assert!(e.state.sys.valid_recovery(&tok).await.unwrap().is_none());
}

#[tokio::test]
async fn usage_cache_tracks_changes() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write db:write").await;
    // Quota is 1 MiB: two 400 KiB files fit, a third doesn't, and fits again after a delete.
    let blob = vec![b'x'; 400 << 10];
    for name in ["a", "b"] {
        let (s, _, _) = call(
            &e,
            req("PUT", &format!("/api/v1/files/{name}"), &t, blob.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
    }
    let (s, _, _) = call(&e, req("PUT", "/api/v1/files/c", &t, blob.clone())).await;
    assert_eq!(s, StatusCode::INSUFFICIENT_STORAGE);
    let (s, _, _) = call(&e, req("DELETE", "/api/v1/files/a", &t, Body::empty())).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = call(&e, req("PUT", "/api/v1/files/c", &t, blob.clone())).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn cli_recovery_link() {
    let e = env();
    user(&e, "alice").await;
    let link = bisonbase::recovery_link((*e.state.cfg).clone(), "ALICE")
        .await
        .unwrap();
    let path = link.strip_prefix("http://localhost:8080").unwrap();
    let tok = path.strip_prefix("/recover?token=").unwrap();
    let (_, b) = ui_get(&e, "", &format!("/ui/recover?token={tok}")).await;
    assert_eq!(b["username"], "alice");
    assert!(
        bisonbase::recovery_link((*e.state.cfg).clone(), "nobody")
            .await
            .is_err()
    );
    let (_, b) = ui_get(
        &e,
        &session(&e, admin(&e, "root").await).await,
        "/ui/sysdb?table=audit_log",
    )
    .await;
    assert!(b.to_string().contains("(command line)"));
}

/// Read SSE events from a streaming body until `n` arrive (or a timeout), as (event, data).
async fn sse_events(body: &mut Body, n: usize) -> Vec<(String, Value)> {
    use http_body_util::BodyExt;
    let mut buf = String::new();
    let mut out = Vec::new();
    while out.len() < n {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
            .await
            .expect("timed out waiting for an event")
            .expect("stream ended")
            .unwrap();
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.push_str(std::str::from_utf8(&data).unwrap());
        while let Some(end) = buf.find("\n\n") {
            let block: String = buf.drain(..end + 2).collect();
            let (mut event, mut data) = (String::new(), String::new());
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    event = v.trim().into();
                } else if let Some(v) = line.strip_prefix("data:") {
                    data += v.trim();
                }
            }
            if !event.is_empty() {
                out.push((event, serde_json::from_str(&data).unwrap()));
            }
        }
    }
    out
}

#[tokio::test]
async fn watch_streams_changes() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write db:write").await;
    let r = token(&e, u, "db:read").await;
    call(
        &e,
        req("POST", "/api/v1/files/a.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    call(
        &e,
        req("POST", "/api/v1/files/b.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    let spec = json!({"tables": [
        {"name": "items", "columns": [{"name": "x", "type": "integer"}]},
        {"name": "other", "columns": [{"name": "x", "type": "integer"}]},
    ]});
    for db in ["a.db", "b.db"] {
        call(&e, db_op(db, "migrate", &t, spec.clone())).await;
    }

    // A read-only token may watch.
    let res = e
        .app
        .clone()
        .oneshot(req("GET", "/api/v1/files/a.db?op=watch", &r, Body::empty()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut body = res.into_body();
    assert_eq!(sse_events(&mut body, 1).await[0].0, "ready");

    // Writes through the API name the tables they touched; writes to other databases, and
    // writes that change nothing, aren't sent.
    call(
        &e,
        db_op(
            "b.db",
            "insert",
            &t,
            json!({"table": "items", "rows": [{"x": 1}]}),
        ),
    )
    .await;
    call(
        &e,
        db_op(
            "a.db",
            "delete",
            &t,
            json!({"table": "items", "where": {"x": 5}}),
        ),
    )
    .await;
    call(
        &e,
        db_op(
            "a.db",
            "insert",
            &t,
            json!({"table": "items", "rows": [{"x": 1}]}),
        ),
    )
    .await;
    call(
        &e,
        db_op(
            "a.db",
            "transact",
            &t,
            json!({"ops": [
                {"op": "update", "table": "items", "where": {}, "set": {"x": 2}},
                {"op": "insert", "table": "other", "rows": [{"x": 1}]},
            ]}),
        ),
    )
    .await;
    // Replacing the file says anything may have changed.
    let (_, _, snap) = call(&e, req("GET", "/api/v1/files/b.db", &t, Body::empty())).await;
    call(&e, req("PUT", "/api/v1/files/a.db", &t, snap)).await;
    let events = sse_events(&mut body, 3).await;
    assert_eq!(
        events,
        vec![
            ("change".into(), json!({"tables": ["items"]})),
            ("change".into(), json!({"tables": ["items", "other"]})),
            ("change".into(), json!({"tables": null})),
        ]
    );

    // Watching a database needs db:read; anything else is watched as files, which needs files:read.
    let none = token(&e, u, "files:read").await;
    let (s, _, _) = call(
        &e,
        req("GET", "/api/v1/files/a.db?op=watch", &none, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &e,
        req("GET", "/api/v1/files/nope.db?op=watch", &r, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Shutting down ends open streams.
    e.state.closing.cancel();
    use http_body_util::BodyExt;
    let end = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(f) = body.frame().await {
            f.unwrap();
        }
    })
    .await;
    assert!(end.is_ok(), "stream didn't end on shutdown");
}

// ---- app-owned storage ----

/// Register an app (as an admin's personal token) and return its storage's API base.
async fn register(e: &Env, admin_tok: &str, id: &str, origin: &str) -> String {
    let (s, _, b) = call(
        e,
        json_req(
            "POST",
            &format!("/api/v1/apps/{id}?op=register"),
            admin_tok,
            json!({"name": "Shared Todo", "origin": origin}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    format!("/api/v1/apps/{id}/files")
}

fn app_op(base: &str, db: &str, op: &str, tok: &str, body: Value) -> Request<Body> {
    json_req("POST", &format!("{base}/{db}?op={op}"), tok, body)
}

fn todo_spec(extra: Option<Value>) -> Value {
    let mut cols = vec![json!({"name": "content", "type": "text"})];
    cols.extend(extra);
    json!({"tables": [
        {"name": "todos", "columns": cols},
        {"name": "posts", "sharing": "shared", "columns": [{"name": "body", "type": "text"}]},
    ]})
}

#[tokio::test]
async fn app_storage_needs_registration_by_an_admin() {
    let e = env();
    let a = admin(&e, "root").await;
    let u = user(&e, "alice").await;
    let at = token(&e, a, "files:write db:write").await;
    let ut = token(&e, u, "files:write db:write").await;
    let id = "6f3c3c55-6a51-4d55-9a8e-1b8f1d0b7a01";

    let (s, _, b) = call(
        &e,
        req("GET", &format!("/api/v1/apps/{id}"), &ut, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(j(&b)["error"]["code"], "app_not_registered");
    let (s, _, b) = call(
        &e,
        app_op(
            &format!("/api/v1/apps/{id}/files"),
            "t.db",
            "mkdb",
            &ut,
            json!({}),
        ),
    )
    .await;
    assert_eq!(j(&b)["error"]["code"], "app_not_registered", "{s}");

    // Only admins can register, with a proper origin.
    let reg = |tok: &str, body: Value| {
        json_req("POST", &format!("/api/v1/apps/{id}?op=register"), tok, body)
    };
    let (s, _, _) = call(
        &e,
        reg(&ut, json!({"name": "X", "origin": "https://x.example"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &e,
        reg(&at, json!({"name": "X", "origin": "http://x.example"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = call(&e, reg(&at, json!({"name": "X"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    register(&e, &at, id, "https://x.example").await;
    // Registering again from the same origin is fine; from another, it's taken.
    let (s, _, _) = call(
        &e,
        reg(&at, json!({"name": "X", "origin": "https://x.example"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &e,
        reg(&at, json!({"name": "X", "origin": "https://y.example"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, _, b) = call(
        &e,
        req("GET", &format!("/api/v1/apps/{id}"), &ut, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let b = j(&b);
    assert_eq!(b["name"], "Shared Todo");
    assert_eq!(b["owner"], false);
    assert_eq!(b["user"]["username"], "alice");
}

#[tokio::test]
async fn app_rows_belong_to_users() {
    let e = env();
    let root = admin(&e, "root").await;
    let alice = user(&e, "alice").await;
    let bob = user(&e, "bob").await;
    let rt = token(&e, root, "files:write db:write").await;
    let at = token(&e, alice, "files:write db:write").await;
    let bt = token(&e, bob, "files:write db:write").await;
    let id = "6f3c3c55-6a51-4d55-9a8e-1b8f1d0b7a02";
    let base = register(&e, &rt, id, "https://x.example").await;
    let root_user = e.state.sys.user_by_id(root).await.unwrap().unwrap();
    let alice_user = e.state.sys.user_by_id(alice).await.unwrap().unwrap();
    e.state
        .sys
        .set_app_owner(&root_user, id.parse().unwrap(), &alice_user, true)
        .await
        .unwrap();

    // Only owners create databases and change tables; others may check them.
    let (s, _, _) = call(&e, app_op(&base, "t.db", "mkdb", &bt, json!({}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&e, app_op(&base, "t.db", "mkdb", &at, json!({}))).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, b) = call(&e, app_op(&base, "t.db", "mkdb", &bt, json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j(&b)["created"], false);
    let (s, _, b) = call(&e, app_op(&base, "t.db", "migrate", &bt, todo_spec(None))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&b));
    let (s, _, b) = call(&e, app_op(&base, "t.db", "migrate", &at, todo_spec(None))).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let (s, _, b) = call(&e, app_op(&base, "t.db", "migrate", &bt, todo_spec(None))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j(&b)["applied"], json!([]));
    let more = Some(json!({"name": "done", "type": "boolean", "default": false}));
    let (s, _, _) = call(
        &e,
        app_op(&base, "t.db", "migrate", &bt, todo_spec(more.clone())),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // `_owner` can't be declared, and internal tables can't be named.
    let bad = json!({"tables": [{"name": "x", "columns": [{"name": "_owner", "type": "text"}]}]});
    let (s, _, _) = call(&e, app_op(&base, "t.db", "migrate", &at, bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let bad = json!({"tables": [{"name": "_bisonbase_x", "columns": []}]});
    let (s, _, _) = call(&e, app_op(&base, "t.db", "migrate", &at, bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Sharing is only for app databases.
    let (s, _, _) = call(
        &e,
        req("POST", "/api/v1/files/u.db?op=mkdb", &at, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = call(&e, db_op("u.db", "migrate", &at, todo_spec(None))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Each user inserts rows; the server sets `_owner`.
    for (tok, who) in [(&at, "alice"), (&bt, "bob")] {
        let (s, _, b) = call(
            &e,
            app_op(
                &base,
                "t.db",
                "insert",
                tok,
                json!({"table": "todos", "rows": [{"content": who}]}),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let b = j(&b);
        assert_eq!(b["columns"], json!(["id", "_owner", "content"]));
        let (s, _, _) = call(
            &e,
            app_op(
                &base,
                "t.db",
                "insert",
                tok,
                json!({"table": "posts", "rows": [{"body": who}]}),
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }
    let rows = |b: &[u8]| -> Vec<Value> {
        j(b)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[2].clone())
            .collect()
    };
    // Private tables: your own rows only. Shared: everyone's.
    let (_, _, b) = call(
        &e,
        app_op(&base, "t.db", "select", &bt, json!({"table": "todos"})),
    )
    .await;
    assert_eq!(rows(&b), [json!("bob")]);
    let (_, _, b) = call(
        &e,
        app_op(
            &base,
            "t.db",
            "select",
            &bt,
            json!({"table": "todos", "where": {"_owner": alice.to_string()}}),
        ),
    )
    .await;
    assert!(rows(&b).is_empty());
    let (_, _, b) = call(
        &e,
        app_op(
            &base,
            "t.db",
            "select",
            &bt,
            json!({"table": "posts", "order_by": ["id"]}),
        ),
    )
    .await;
    assert_eq!(rows(&b), [json!("alice"), json!("bob")]);
    // Even owners only reach their own rows through the API.
    let (_, _, b) = call(
        &e,
        app_op(&base, "t.db", "select", &at, json!({"table": "todos"})),
    )
    .await;
    assert_eq!(rows(&b), [json!("alice")]);

    // Nobody changes or deletes another user's rows, even in shared tables.
    for (table, col) in [("todos", "content"), ("posts", "body")] {
        let set = json!({"table": table, "where": {}, "set": {col: "x"}});
        let (s, _, b) = call(&e, app_op(&base, "t.db", "update", &bt, set)).await;
        assert_eq!(j(&b)["changes"], 1, "{s}");
        let (_, _, b) = call(
            &e,
            app_op(
                &base,
                "t.db",
                "delete",
                &bt,
                json!({"table": table, "where": {}}),
            ),
        )
        .await;
        assert_eq!(j(&b)["changes"], 1);
    }
    let (_, _, b) = call(
        &e,
        app_op(&base, "t.db", "select", &at, json!({"table": "posts"})),
    )
    .await;
    assert_eq!(rows(&b), [json!("alice")]);

    // `_owner` is the server's to set.
    let (s, _, _) = call(
        &e,
        app_op(
            &base,
            "t.db",
            "insert",
            &bt,
            json!({"table": "todos", "rows": [{"content": "x", "_owner": alice.to_string()}]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = call(
        &e,
        app_op(
            &base,
            "t.db",
            "update",
            &bt,
            json!({"table": "todos", "where": {}, "set": {"_owner": alice.to_string()}}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The same goes inside transactions.
    let (s, _, _) = call(
        &e,
        app_op(&base, "t.db", "transact", &bt, json!({"ops": [{"op": "delete", "table": "todos", "where": {"_owner": alice.to_string()}}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, _, b) = call(
        &e,
        app_op(&base, "t.db", "select", &at, json!({"table": "todos"})),
    )
    .await;
    assert_eq!(rows(&b), [json!("alice")]);

    // The policy table is hidden.
    let (_, _, b) = call(
        &e,
        req("GET", &format!("{base}/t.db?op=schema"), &bt, Body::empty()),
    )
    .await;
    let names: Vec<_> = j(&b)["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("posts"), json!("todos")]);
    let (s, _, _) = call(
        &e,
        app_op(
            &base,
            "t.db",
            "select",
            &bt,
            json!({"table": "_bisonbase_tables"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Plain files: everyone reads, owners write. Whole databases: owners only.
    let (s, _, _) = call(&e, req("PUT", &format!("{base}/logo.txt"), &bt, "x")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&e, req("PUT", &format!("{base}/logo.txt"), &at, "logo")).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, b) = call(
        &e,
        req("GET", &format!("{base}/logo.txt"), &bt, Body::empty()),
    )
    .await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, b"logo".as_slice()));
    let (s, _, _) = call(
        &e,
        req("DELETE", &format!("{base}/logo.txt"), &bt, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&e, req("GET", &format!("{base}/t.db"), &bt, Body::empty())).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(&e, req("GET", &format!("{base}/t.db"), &at, Body::empty())).await;
    assert_eq!(s, StatusCode::OK);

    // Deleting a user removes their rows from app databases.
    let (s, _) = ui_post(
        &e,
        &session(&e, root).await,
        "/ui/admin/users/delete",
        json!({"id": bob, "confirm": "bob"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let db = e
        .state
        .app_store(id.parse().unwrap())
        .files_dir()
        .join("t.db");
    let c = rusqlite::Connection::open(db).unwrap();
    let n: i64 = c
        .query_row(
            "SELECT count(*) FROM todos WHERE _owner = ?1",
            [bob.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
    let n: i64 = c
        .query_row("SELECT count(*) FROM todos", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn app_tokens_reach_only_their_own_app_storage() {
    let e = env();
    let root = admin(&e, "root").await;
    let rt = token(&e, root, "files:write db:write").await;
    let u = user(&e, "alice").await;
    let cookie = session(&e, u).await;
    let other = "6f3c3c55-6a51-4d55-9a8e-1b8f1d0b7a03";
    register(&e, &rt, other, "https://other.example").await;

    // Before the app is registered, its token can't use app storage; an admin's can register it.
    let t = app_token(&e, &cookie, &[("scope", "db:write")]).await;
    let (s, _, b) = call(
        &e,
        req("GET", &format!("/api/v1/apps/{APP_ID}"), &t, Body::empty()),
    )
    .await;
    assert_eq!(
        (s, j(&b)["error"]["code"].clone()),
        (StatusCode::NOT_FOUND, json!("app_not_registered"))
    );
    let (s, _, _) = call(
        &e,
        req(
            "POST",
            &format!("/api/v1/apps/{APP_ID}?op=register"),
            &t,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let admin_cookie = session(&e, root).await;
    let admin_app = app_token(&e, &admin_cookie, &[("scope", "db:write")]).await;
    let (s, _, b) = call(
        &e,
        req(
            "POST",
            &format!("/api/v1/apps/{APP_ID}?op=register"),
            &admin_app,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&b));
    let b = j(&b);
    assert_eq!(b["origin"], APP);
    assert_eq!(b["name"], APP_NAME);

    let (s, _, _) = call(
        &e,
        req("GET", &format!("/api/v1/apps/{APP_ID}"), &t, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &e,
        req("GET", &format!("/api/v1/apps/{other}"), &t, Body::empty()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call(
        &e,
        app_op(
            &format!("/api/v1/apps/{other}/files"),
            "t.db",
            "select",
            &t,
            json!({"table": "x"}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Once registered, only the registered origin can sign in with the id.
    let (s, b) = consent(&e, &cookie, &[("app_id", other)]).await;
    assert_eq!(s, StatusCode::OK);
    let to = b["redirect"].as_str().unwrap_or_else(|| panic!("{b}"));
    assert_eq!(query_param(to, "error").as_deref(), Some("invalid_request"));
}

#[tokio::test]
async fn ui_app_storage() {
    let e = env();
    let root = admin(&e, "root").await;
    let alice = user(&e, "alice").await;
    let bob = user(&e, "bob").await;
    let rc = session(&e, root).await;
    let ac = session(&e, alice).await;
    let bc = session(&e, bob).await;

    // Admins register apps and pick owners.
    let (s, b) = ui_post(
        &e,
        &ac,
        "/ui/admin/apps/create",
        json!({"name": "T", "origin": "https://t.example"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    let (s, b) = ui_post(
        &e,
        &rc,
        "/ui/admin/apps/create",
        json!({"name": "T", "origin": "https://t.example/"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let id = b["id"].as_str().unwrap().to_string();
    let (s, _) = ui_post(
        &e,
        &rc,
        "/ui/admin/apps/owner",
        json!({"id": id, "username": "alice", "owner": true}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, b) = ui_get(&e, &rc, "/ui/apps").await;
    assert_eq!(b["apps"][0]["origin"], "https://t.example");
    assert_eq!(b["apps"][0]["owners"][0]["username"], "alice");
    let (_, b) = ui_get(&e, &ac, "/ui/apps").await;
    assert_eq!(b["apps"][0]["manage"], true);
    assert!(b["apps"][0].get("owners").is_none());
    // Bob hasn't signed in to it, so it isn't listed for him (but he can still open it).
    let (_, b) = ui_get(&e, &bc, "/ui/apps").await;
    assert_eq!(b["apps"], json!([]));

    // The owner creates a database and fills it through the API.
    let at = token(&e, alice, "db:write").await;
    let bt = token(&e, bob, "db:write").await;
    let base = format!("/api/v1/apps/{id}/files");
    call(&e, app_op(&base, "t.db", "mkdb", &at, json!({}))).await;
    let (s, _, _) = call(&e, app_op(&base, "t.db", "migrate", &at, todo_spec(None))).await;
    assert_eq!(s, StatusCode::OK);
    for (tok, who) in [(&at, "alice"), (&bt, "bob")] {
        call(
            &e,
            app_op(
                &base,
                "t.db",
                "insert",
                tok,
                json!({"table": "todos", "rows": [{"content": who}]}),
            ),
        )
        .await;
    }

    // Others see their own rows, read-only, and only tables of owned rows.
    let (s, b) = ui_get(&e, &bc, &format!("/ui/files?app={id}")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["editable"], false);
    assert_eq!(b["rows_only"], true);
    assert_eq!(b["app"]["name"], "T");
    let (s, b) = ui_get(&e, &bc, &format!("/ui/db?app={id}&path=t.db&table=todos")).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let tables: Vec<_> = b["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(tables, [json!("posts"), json!("todos")]);
    let cells: Vec<_> = b["table"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["cells"][2]["text"].clone())
        .collect();
    assert_eq!(cells, [json!("bob")]);
    assert_eq!(b["writable"], false);
    let (s, _) = ui_post(
        &e,
        &bc,
        "/ui/db/sql",
        json!({"app": id, "path": "t.db", "sql": "SELECT * FROM todos"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = ui_get(
        &e,
        &bc,
        &format!("/ui/db/row?app={id}&path=t.db&table=todos&key=%5B1%5D"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = get_page(&e, &bc, &format!("/apps/{id}/raw/t.db")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = ui_post(
        &e,
        &bc,
        "/ui/new",
        json!({"app": id, "dir": "", "name": "x", "kind": "folder"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Owners see and change everything.
    let (_, b) = ui_get(&e, &ac, &format!("/ui/db?app={id}&path=t.db&table=todos")).await;
    assert_eq!(b["table"]["rows"].as_array().unwrap().len(), 2);
    assert_eq!(b["writable"], true);
    let (s, b) = ui_post(
        &e,
        &ac,
        "/ui/db/sql",
        json!({"app": id, "path": "t.db", "sql": "SELECT count(*) FROM todos"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["result"]["rows"][0][0]["text"], "2");
    let (s, _) = ui_post(
        &e,
        &ac,
        "/ui/new",
        json!({"app": id, "dir": "", "name": "x", "kind": "folder"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = get_page(&e, &ac, &format!("/apps/{id}/raw/t.db")).await;
    assert_eq!(s, StatusCode::OK);
    // ...and it didn't land in alice's own files.
    let (_, b) = ui_get(&e, &ac, "/ui/files").await;
    assert_eq!(b["entries"], json!([]));

    // Deleting the app takes its storage with it.
    let (s, _) = ui_post(
        &e,
        &rc,
        "/ui/admin/apps/delete",
        json!({"id": id, "confirm": "nope"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = ui_post(
        &e,
        &rc,
        "/ui/admin/apps/delete",
        json!({"id": id, "confirm": "T"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!e.state.app_store(id.parse().unwrap()).root.exists());
    let (s, _, _) = call(
        &e,
        app_op(&base, "t.db", "select", &bt, json!({"table": "todos"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn watch_folders() {
    let e = env();
    let u = user(&e, "alice").await;
    let t = token(&e, u, "files:write db:write").await;
    let r = token(&e, u, "files:read").await;

    // A folder may be watched before it exists.
    let res = e
        .app
        .clone()
        .oneshot(req("GET", "/api/v1/files/docs?op=watch", &r, Body::empty()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mut body = res.into_body();
    assert_eq!(sse_events(&mut body, 1).await[0].0, "ready");

    // Changes elsewhere aren't sent; nor are rows changing in a database in the folder.
    call(&e, req("PUT", "/api/v1/files/other.txt", &t, "x")).await;
    call(
        &e,
        req("POST", "/api/v1/files/docs/d.db?op=mkdb", &t, Body::empty()),
    )
    .await;
    let spec =
        json!({"tables": [{"name": "items", "columns": [{"name": "x", "type": "integer"}]}]});
    call(&e, db_op("docs/d.db", "migrate", &t, spec)).await;
    call(
        &e,
        db_op(
            "docs/d.db",
            "insert",
            &t,
            json!({"table": "items", "rows": [{"x": 1}]}),
        ),
    )
    .await;
    call(&e, req("PUT", "/api/v1/files/docs/a/b.txt", &t, "b")).await;
    call(
        &e,
        req("POST", "/api/v1/files/docs/sub?op=mkdir", &t, Body::empty()),
    )
    .await;
    call(
        &e,
        req(
            "POST",
            "/api/v1/files/docs/a/b.txt?op=move&to=moved.txt",
            &t,
            Body::empty(),
        ),
    )
    .await;
    call(
        &e,
        req(
            "DELETE",
            "/api/v1/files/docs?recursive=true",
            &t,
            Body::empty(),
        ),
    )
    .await;
    let events = sse_events(&mut body, 6).await;
    let paths: Vec<Value> = events
        .iter()
        .map(|(ev, d)| {
            assert_eq!(ev, "change");
            d["path"].clone()
        })
        .collect();
    // mkdb, migrate (the schema changed), write, mkdir, move (from; "to" is elsewhere), delete.
    assert_eq!(
        paths,
        [
            "docs/d.db",
            "docs/d.db",
            "docs/a/b.txt",
            "docs/sub",
            "docs/a/b.txt",
            "docs"
        ]
        .map(|p| json!(p))
    );

    // Watching a folder needs files:read.
    let db_only = token(&e, u, "db:read").await;
    let (s, _, _) = call(
        &e,
        req(
            "GET",
            "/api/v1/files/docs?op=watch",
            &db_only,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
