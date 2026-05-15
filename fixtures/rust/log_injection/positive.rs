// Positive fixtures for SEC015-log-injection (CWE-117)

use log;

struct Request;

// Case 1: log::info! with {} placeholder + param identifier
fn handler(req: Request) {
    log::info!("user: {}", req);
}

// Case 2: log::warn! with %s placeholder + request-style ident
fn process(request: Request) {
    log::warn!("processing: {}", request);
}

// Case 3: tracing::debug! with {} + param
fn trace_handler(input: String) {
    tracing::debug!("input: {}", input);
}

// Case 4: bare info! macro + request-style ident in request param
fn view(req: Request) {
    info!("received: {}", req);
}
