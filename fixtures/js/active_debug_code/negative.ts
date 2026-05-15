// Fixture: MAINT011-active-debug-code — JS/TS negative cases
// None of these should produce a MAINT011 finding.

function handleError(err: Error): void {
    console.error("Request failed:", err); // NOT flagged — legitimate error output
    console.warn("Deprecated API used"); // NOT flagged — legitimate warning
    console.info("Server listening on :8080"); // NOT flagged — legitimate info
}

function computeSum(a: number, b: number): number {
    return a + b;
}
