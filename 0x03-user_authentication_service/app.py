#!/usr/bin/env python3
"""
Flask app
"""


from flask import Flask, jsonify
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """GET method
    Return:
        - json payload.
    """
    return jsonify({"message": "Bienvenue"})
