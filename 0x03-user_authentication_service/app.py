#!/usr/bin/env python3
"""
Flask app
"""


from flask import Flask, jsonify, request

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


@app.route('/users', methods=['POST'])
def register_user():
    try:
        email = request.form.get('email')
        password = request.form.get('password')

        if email is None or password is None:
            return jsonify(
                {"message": "Both 'email' and 'password' fields are required"}
                ), 400

        if AUTH.register_user(email, password):
            return jsonify({"email": email, "message": "user created"}), 200
        else:
            return jsonify({"message": "email already registered"}), 400

    except Exception as e:
        return jsonify({"message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
