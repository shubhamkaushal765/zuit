"""Positive fixture for SEC007-path-traversal: opens files with user-supplied paths."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/file")
def serve_file():
    """Serve a file from a user-supplied path (path traversal risk)."""
    filename = request.args.get("name", "")
    with open("uploads/" + filename + "..") as f:
        return f.read()
