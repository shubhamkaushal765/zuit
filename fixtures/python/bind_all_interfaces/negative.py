# SEC013-bind-all-interfaces: negative fixture
# None of these should produce SEC013 findings.

import socket
import flask
import uvicorn

# OK: restricted to loopback.
app = flask.Flask(__name__)
app.run("127.0.0.1", port=5000)

# OK: uvicorn with localhost host.
uvicorn.run(app, host="127.0.0.1", port=8000)

# OK: socket bound to loopback.
s = socket.socket()
s.bind(("127.0.0.1", 8080))

# OK: not a bind callee.
print("0.0.0.0")
