//! Negative fixture for SEC008-csrf-missing: Axum app with CSRF protection.
//! The `tower_csrf` token appears in source, suppressing SEC008 findings.

use axum::Router;
use axum::routing::post;
use tower_csrf::CsrfLayer;

/// Transfer funds — protected by CSRF middleware.
pub async fn transfer_handler() -> &'static str {
    "transferred"
}

/// Build the application router with CSRF protection.
pub fn app() -> Router {
    Router::new()
        .route("/transfer", post(transfer_handler))
        .layer(CsrfLayer::new())
}
