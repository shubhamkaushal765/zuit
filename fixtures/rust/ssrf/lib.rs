//! Axum handler with a Server-Side Request Forgery vulnerability.

/// Handler that performs an HTTP request to a user-supplied host — SEC010 example.
pub async fn ssrf_handler(user_input: String) -> String {
    // SEC010: user-controlled input flows into reqwest::get
    let resp = reqwest::get(&format!("https://{}/api", user_input))
        .await
        .unwrap();
    resp.text().await.unwrap()
}
