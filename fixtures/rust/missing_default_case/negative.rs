// MAINT009-missing-default-case — negative fixture
// These match expressions should NOT produce findings.

enum Color {
    Red,
    Blue,
}

fn check_enum(c: Color) {
    // Uppercase enum variant scrutinee — compiler checks exhaustiveness.
    // Should NOT fire.
    match c {
        Color::Red => {}
        Color::Blue => {}
    }
}

fn check_with_wildcard(x: i32) {
    // Has a wildcard arm — should NOT fire.
    match x {
        1 => {}
        _ => {}
    }
}

fn check_self_path() {
    // Self::Variant — uppercase final segment — should NOT fire.
    match Some(1) {
        Some(y) => {
            let _ = y;
        }
        None => {}
    }
}
