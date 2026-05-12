mod common;

use zuit_report::render_markdown;

#[test]
fn snapshot_markdown() {
    let report = common::fake_report();
    let output = render_markdown(&report).unwrap();
    insta::assert_snapshot!(output);
}
