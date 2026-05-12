//! Axum application with a permissive CORS configuration.

use tower_http::cors::CorsLayer;

/// Build the application router — SEC011 example.
pub fn build_app() {
    // SEC011: CorsLayer::permissive() allows all origins
    let _cors = CorsLayer::permissive();
}
