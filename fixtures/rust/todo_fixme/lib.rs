//! Fixture for DOC002-todo-fixme.

/// A function with no TODO. (This is a doc comment — must NOT trigger.)
pub fn ok() -> u32 {
    // TODO: revisit this constant
    42
}

// FIXME: this whole module is a placeholder
pub fn placeholder() {}
