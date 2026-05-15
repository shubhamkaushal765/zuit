// SEC013-bind-all-interfaces: negative fixture
// None of these should produce SEC013 findings.

use std::net::TcpListener;

fn bind_loopback() {
    // OK: explicitly restricted to loopback.
    let _listener = TcpListener::bind("127.0.0.1:8080").unwrap();
}

fn bind_ipv6_loopback() {
    // OK: IPv6 loopback is not all-interface.
    let _listener = TcpListener::bind("[::1]:8080").unwrap();
}

fn print_address() {
    // OK: not a bind callee.
    let addr = "0.0.0.0";
    println!("{addr}");
}

fn bind_variable(addr: &str) {
    // OK: first argument is not a string literal — not captured.
    bind(addr);
}

fn bind(_addr: &str) {}
