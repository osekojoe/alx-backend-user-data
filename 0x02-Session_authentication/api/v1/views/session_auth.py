#!/usr/bin/env python3
"""
handles all routes for the Session authentication
"""


import os
from typing import Tuple
from flask import abort, jsonify, request

from models.user import User
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    # Retrieve email and password parameters using request.form.get()
    email = request.form.get('email')
    password = request.form.get('password')

    # Check for missing email or password
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Retrieve the User instance based on the email
    user = User.search({'email': email})

    # If no User found, return a 404 error
    if not user:
        return jsonify({"error": "no user found for this email"}), 404

    # If the password is not valid, return a 401 error
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create a Session ID for the User ID
    session_id = auth.create_session(user.id)

    # Return the dictionary representation of the User
    user_dict = user.to_json()

    # Create a response with the User dictionary
    response = jsonify(user_dict)

    # Set the cookie with the Session ID
    session_cookie_name = os.getenv("SESSION_NAME", "_my_session_id")
    response.set_cookie(session_cookie_name, session_id)

    return response, 200
