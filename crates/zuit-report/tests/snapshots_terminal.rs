mod common;

use zuit_report::{RenderOptions, render_terminal};

#[test]
fn snapshot_terminal_no_color() {
    let report = common::fake_report();
    let opts = RenderOptions {
        use_color: false,
        use_hyperlinks: false,
    };
    let output = render_terminal(&report, &opts).unwrap();
    insta::assert_snapshot!(output);
}

/// Verify that the coloured variant actually contains ANSI escape codes.
#[test]
fn color_output_contains_ansi_escapes() {
    let report = common::fake_report();
    let opts = RenderOptions {
        use_color: true,
        use_hyperlinks: false,
    };
    let output = render_terminal(&report, &opts).unwrap();
    assert!(
        output.contains('\x1b'),
        "expected ANSI escape sequences in coloured output"
    );
}
