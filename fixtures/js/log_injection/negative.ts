// Negative fixtures for SEC015-log-injection (CWE-117)
// None of these should trigger a finding.

// No placeholder, no user-input arg
function startup() {
    logger.info("startup complete");
}

// Placeholder but non-user arg (not param, not request-style)
function report() {
    logger.info("user count", 42);
}

// Greeting is a local variable, not a param of this function
const greeting = "hello";
function log_greeting() {
    console.log("user said", greeting);
}
