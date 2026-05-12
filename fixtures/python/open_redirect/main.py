"""Flask endpoint with an open redirect vulnerability."""

from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/login")
def login_redirect():
    """Redirect user after login — destination comes from query param."""
    return redirect(request.args.get("next"))  # SEC009: user input in redirect
