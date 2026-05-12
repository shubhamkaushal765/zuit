//! Positive fixture for SEC007-path-traversal: opens file with a path containing `..`.

/// Read a file from a user-supplied relative path (path traversal risk).
pub fn read_user_file(user_input: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(std::path::Path::new(&format!("../uploads/{}", user_input)))
}
