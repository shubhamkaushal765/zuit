// Positive fixture for CPLX003-duplicate-code: file A.

pub fn process_data(items: &[i32]) -> Vec<i32> {
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

pub fn validate_input(value: i32) -> bool {
    if value <= 0 {
        return false;
    }
    true
}
