//! Positive fixture for SEC008-csrf-missing: Axum app with state-changing
//! handlers and no CSRF protection.

use axum::Router;
use axum::routing::post;

/// Transfer funds — state-changing handler, no CSRF token present.
pub async fn transfer_handler() -> &'static str {
    "transferred"
}

/// Delete account — state-changing handler.
pub async fn delete_handler() -> &'static str {
    "deleted"
}

/// Build the application router.
pub fn app() -> Router {
    Router::new()
        .route("/transfer", post(transfer_handler))
        .route("/account", axum::routing::delete(delete_handler))
}
