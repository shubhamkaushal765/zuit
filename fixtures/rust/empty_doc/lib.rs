//! Positive fixture for DOC003-empty-doc.
//! Contains functions with empty or placeholder doc comments.

///
pub fn empty_doc_fn() -> i32 {
    42
}

/// .
pub fn punctuation_only_doc() -> bool {
    true
}

/// TODO
pub fn todo_placeholder() -> String {
    String::new()
}
