// Fixture: MAINT011-active-debug-code — Rust positive cases
// Each dbg! call should produce a finding.

fn compute(x: i32) -> i32 {
    let result = dbg!(x * 2);
    result
}

fn process(items: &[i32]) -> Vec<i32> {
    items.iter().map(|&x| {
        dbg!(x);
        x + 1
    }).collect()
}
