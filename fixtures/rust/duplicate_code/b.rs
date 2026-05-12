// Positive fixture for CPLX003-duplicate-code: file B.
// Contains a block of code duplicated from a.rs.

pub fn transform_items(items: &[i32]) -> Vec<i32> {
    let mut result = Vec::new();
    for &item in items {
        if item > 0 {
            result.push(item * 2);
        } else {
            result.push(0);
        }
    }
    result
}

pub fn check_value(value: i32) -> bool {
    if value <= 0 {
        return false;
    }
    true
}
