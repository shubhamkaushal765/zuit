"""Flask endpoint with a Server-Side Request Forgery vulnerability."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/proxy")
def proxy():
    """Fetch a remote resource — destination comes from query param."""
    host = request.args.get("host")
    # SEC010: user-controlled host flows into HTTP request
    resp = requests.get(f"https://{host}/api")
    return resp.text
