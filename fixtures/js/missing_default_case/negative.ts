// MAINT009-missing-default-case — negative fixture
// This switch statement should NOT produce a finding.

function getLabel(x: number): string {
    switch (x) {
        case 1:
            return "one";
        case 2:
            return "two";
        default:
            return "unknown";
    }
}
