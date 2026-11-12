pub mod db;
pub mod files;

use axum::{
    Router,
    http::{HeaderName, Method, header},
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use crate::{oauth, state::AppState};

/// The bearer-token JSON API. It never reads cookies, so CORS can allow any origin.
pub fn router() -> Router<AppState> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::POST,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_MATCH,
            header::IF_NONE_MATCH,
        ])
        .expose_headers([
            header::ETAG,
            header::CONTENT_DISPOSITION,
            HeaderName::from_static("content-length"),
        ]);

    let file_routes = get(files::get)
        .put(files::put)
        .delete(files::delete)
        .post(files::post);
    Router::new()
        .route("/api/v1/files", file_routes.clone())
        .route("/api/v1/files/", file_routes.clone())
        .route("/api/v1/files/{*path}", file_routes)
        // OAuth endpoints that apps call directly: cookie-free, so open to any origin too.
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata),
        )
        .layer(cors)
}
