// SEC013-bind-all-interfaces: positive fixture
// Demonstrates wide-open server bind addresses that should be flagged.

use std::net::TcpListener;

fn bind_ipv4_any() {
    // FLAGGED: binds to all IPv4 interfaces.
    let _listener = TcpListener::bind("0.0.0.0:8080").unwrap();
}

fn bind_ipv6_any() {
    // FLAGGED: binds to all IPv6 interfaces (any-address).
    let _listener = TcpListener::bind("::").unwrap();
}

fn bind_with_port_string() {
    // FLAGGED: `0.0.0.0:PORT` form is also a wide-open address.
    bind("0.0.0.0:9000");
}

// Stub so the file parses without type errors in static analysis context.
fn bind(_addr: &str) {}
