mod common;

use zuit_report::render_sarif;

/// Regression guard: `render_sarif` must succeed (not return `NotImplemented`).
///
/// The old stub always returned `ReportError::NotImplemented`; this test
/// ensures the implemented formatter never regresses to that behaviour.
#[test]
fn sarif_does_not_return_not_implemented() {
    let report = common::fake_report();
    assert!(
        render_sarif(&report).is_ok(),
        "render_sarif must succeed for a non-empty report"
    );
}
