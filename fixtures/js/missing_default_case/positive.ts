// MAINT009-missing-default-case — positive fixture
// This switch statement should produce a finding.

function getLabel(x: number): string {
    switch (x) {
        case 1:
            return "one";
        case 2:
            return "two";
    }
    return "unknown";
}
