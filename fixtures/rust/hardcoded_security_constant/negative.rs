// SEC012-hardcoded-security-constant: negative fixture
// None of the following should produce findings.

fn configure() {
    // RHS is a call expression (environment variable lookup)
    let api_key = std::env::var("API_KEY").unwrap_or_default();
    let _ = api_key;

    // Excluded suffixes
    let total_password_count = 0;
    let _ = total_password_count;

    let token_type = "bearer";
    let _ = token_type;

    // Empty string
    let password = "";
    let _ = password;

    // Unrelated names
    let username = "admin";
    let _ = username;
}
