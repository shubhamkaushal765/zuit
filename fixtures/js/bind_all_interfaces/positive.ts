// SEC013-bind-all-interfaces: positive fixture
// Demonstrates wide-open server bind addresses that should be flagged.

import http from 'http';
import express from 'express';

const app = express();

// FLAGGED: app.listen with IPv4 any-address.
app.listen("0.0.0.0", 3000);

// FLAGGED: server.listen with host:port string form.
const server = http.createServer(app);
server.listen("0.0.0.0:8080");

// FLAGGED: socket.bind with IPv6 any-address.
const sock = {} as any;
sock.bind("::");
