#!/usr/bin/env python3
"""
Authentication handler
"""


import os
import re
from typing import List, TypeVar
from flask import request
import fnmatch

User = TypeVar('User')


class Auth:
    '''Authentication handling'''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if authentication is required for a given path.

        :param path: The path to check for authentication.
        :param excluded_paths: List of paths that are excluded from
          authentication checks.
        :return: True if authentication is required, False otherwise.
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        '''Get the authorization header from the Flask request.

        :param request: The Flask request object.
        :return: The authorization header or None if not found.
        '''
        if request is None:
            return None

        authorization_header = request.headers.get('Authorization')
        if authorization_header is None:
            return None

        return authorization_header

    def current_user(self, request=None) -> TypeVar('User'):
        '''Get the current user based on the Flask request.
        :param request: The Flask request object.
        :return: The current user or None if not authenticated.
        '''
        if request is None:
            return None

    def session_cookie(self, request=None):
        """
        Get the value of the session cookie from a request.

        :param request: The Flask request object.
        :return: The value of the session cookie or None if
          request is None or the cookie is not found.
        """
        if request is None:
            return None

        session_cookie_name = os.getenv("SESSION_NAME", "_my_session_id")

        # Use .get() to access the cookie in the request cookies dictionary
        return request.cookies.get(session_cookie_name)
