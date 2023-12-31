#!/usr/bin/env python3
"""
Flask app
"""


from flask import (Flask,
                   jsonify,
                   request,
                   make_response,
                   abort,
                   redirect)

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


@app.route('/sessions', methods=['POST'])
def login() -> str:
    """logs in a user"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(400, "Both 'email' and 'password' fields are required")

    if AUTH.valid_login(email, password):
        # If the login is correct, create a new session
        session_id = AUTH.create_session(email)

        if session_id:
            # Store the session ID as a cookie
            response = make_response(
                jsonify({"email": email, "message": "logged in"}), 200)
            response.set_cookie('session_id', session_id)
            return response

    # If the login is incorrect or if any other error occurs
    abort(401, "Authentication failed")


@app.route('/sessions', methods=['DELETE'])
def log_out() -> str:
    """Find the user with the requested session ID.
    If the user exists destroy the session and redirect the user to GET /.
    If the user does not exist, respond with a 403 HTTP status.
    """
    session_id = request.cookies.get("session_id", None)

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> str:
    """ Responds to the GET /profile route.
    If the user exist, respond with a 200 HTTP status and a JSON Payload
    If the session ID is invalid or the user does not exist,
    respond with a 403 HTTP status.
    """
    session_id = request.cookies.get("session_id", None)

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    msg = {"email": user.email}

    return jsonify(msg), 200


@app.route('/reset_password', methods=['POST'])
def reset_password() -> str:
    """responds to the POST /reset_password route
    If the email is not registered, respond with a 403 status code.
    Otherwise, generate a token and respond with a 200 HTTP status
      and JSON Payload
    """
    try:
        email = request.form['email']
    except KeyError:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """ Responds to the PUT /reset_password route.
    Updates the password
    If the token is invalid, catch the exception and respond with
      a 403 HTTP code.
    If the token is valid, respond with a 200 HTTP code
    """
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify(
        {"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
