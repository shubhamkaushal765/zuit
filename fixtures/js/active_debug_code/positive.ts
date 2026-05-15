// Fixture: MAINT011-active-debug-code — JS/TS positive cases
// Each construct below should produce a finding.

function fetchData(url: string): Promise<Response> {
    debugger; // should be flagged (Severity::Medium)
    console.log("fetching", url); // should be flagged (Severity::Low)
    return fetch(url);
}

function processResult(data: unknown): void {
    console.debug("processing:", data); // should be flagged (Severity::Low)
    console.trace("stack trace"); // should be flagged (Severity::Low)
}
