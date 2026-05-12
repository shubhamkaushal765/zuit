//! Axum handler with an open redirect vulnerability.

use axum::response::Redirect;

/// Handler that redirects to a user-supplied URL — SEC009 example.
pub async fn redirect_handler(user_input: String) -> Redirect {
    // SEC009: unvalidated user input flows into Redirect::to
    Redirect::to(&format!("{}", user_input))
}
