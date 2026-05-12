"""Positive fixture for SEC008-csrf-missing: Flask app with state-changing handler, no CSRF protection."""

from flask import Flask, request

app = Flask(__name__)


@app.post("/transfer")
def transfer():
    """Transfer funds — state-changing handler with no CSRF protection."""
    amount = request.json.get("amount", 0)
    target = request.json.get("target", "")
    # perform the transfer
    return {"status": "ok", "amount": amount, "target": target}


@app.get("/balance")
def balance():
    """Read-only balance endpoint — not flagged."""
    return {"balance": 1000}
