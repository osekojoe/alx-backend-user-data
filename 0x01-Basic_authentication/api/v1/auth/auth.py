#!/usr/bin/env python3
"""
Authentication handler
"""


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
        :param excluded_paths: List of paths that are excluded from authentication checks.
        :return: True if authentication is required, False otherwise.
        """
        if path is None or not excluded_paths:
            return True

        # Check if path is in excluded_paths using fnmatch
        for pattern in excluded_paths:
            if fnmatch.fnmatch(path, pattern):
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
