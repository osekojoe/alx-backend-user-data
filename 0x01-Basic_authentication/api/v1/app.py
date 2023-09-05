#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None

# Based on the environment variable AUTH_TYPE, load and
# assign the right instance of authentication to auth
auth_type = os.getenv("AUTH_TYPE")
if auth_type == 'auth':
    auth = Auth()
elif auth_type == 'basic_auth':
    auth = BasicAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


# Error handler for 401 Unauthorized
@app.errorhandler(401)
def unauthorized_error(error) -> str:
    '''unauthorized error'''
    response = jsonify({"error": "Unauthorized"})
    response.status_code = 401
    return response


# Error handler for 403 Forbidden
@app.errorhandler(403)
def forbidden_error(error) -> str:
    '''forbidden error'''
    response = jsonify({"error": "Forbidden"})
    response.status_code = 403
    return response


# define before_request method
@app.before_request
def before_request():
    '''filter requests'''
    if auth is None:
        return

    # paths which dont require authentication
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/', '/api/v1/forbidden/']

    # Check if the request path is not in the excluded_paths list
    if auth and auth.require_auth(request.path, excluded_paths):
        # check for authorization header
        if not auth.authorization_header(request):
            abort(401)
        # check for current user
        if not auth.current_user(request):
            abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
