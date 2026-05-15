// SEC013-bind-all-interfaces: negative fixture
// None of these should produce SEC013 findings.

import express from 'express';
import http from 'http';

const app = express();

// OK: restricted to loopback.
app.listen("127.0.0.1", 3000);

// OK: port-only listen (no host string).
app.listen(3000);

// OK: not a bind callee.
console.log("0.0.0.0");

// OK: server listening on loopback.
const server = http.createServer(app);
server.listen("127.0.0.1:8080");
