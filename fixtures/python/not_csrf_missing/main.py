"""Negative fixture for SEC008-csrf-missing: Flask app with CSRF protection enabled."""

from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)


@app.post("/transfer")
def transfer():
    """Transfer funds — state-changing handler protected by Flask-WTF CSRF."""
    amount = request.json.get("amount", 0)
    target = request.json.get("target", "")
    return {"status": "ok", "amount": amount, "target": target}
