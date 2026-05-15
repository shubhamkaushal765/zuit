// Positive fixtures for SEC015-log-injection (CWE-117)

// Case 1: logger.info with template literal + param
function view(req: any) {
    logger.info(`user: ${req.body}`);
}

// Case 2: console.log with printf-style + request-style ident
function handle(req: any) {
    console.log("user: %s", req.body);
}

// Case 3: log.info with placeholder + param
function process(request: any) {
    log.info("processing: %s", request);
}

// Case 4: logger.warn with template + request-style ident
function receive(payload: any) {
    logger.warn(`received: ${payload}`);
}
