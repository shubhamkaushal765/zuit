# SEC013-bind-all-interfaces: positive fixture
# Demonstrates wide-open server bind addresses that should be flagged.

import socket
import flask
import uvicorn

# FLAGGED: Flask app.run with IPv4 any-address.
app = flask.Flask(__name__)
app.run("0.0.0.0", port=5000)

# FLAGGED: uvicorn.run with host="0.0.0.0" keyword argument.
uvicorn.run(app, host="0.0.0.0", port=8000)

# FLAGGED: socket.bind with tuple (any-address, port).
s = socket.socket()
s.bind(("0.0.0.0", 8080))

# FLAGGED: bare bind with IPv6 any-address.
bind("::")
