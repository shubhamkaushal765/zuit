mod common;

use zuit_report::render_json;

#[test]
fn snapshot_json() {
    let report = common::fake_report();
    let output = render_json(&report).unwrap();
    insta::assert_snapshot!(output);
}
