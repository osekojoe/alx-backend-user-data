#!/usr/bin/env python3
"""

"""


from typing import List, TypeVar
from flask import request

User = TypeVar('User')


class Auth:
    '''Authentication handling'''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''Get the authorization header from the Flask request.
        :param request: The Flask request object.
        :return: The authorization header or None if not found.'''
        return False

    def authorization_header(self, request=None) -> str:
        '''Get the authorization header from the Flask request.

        :param request: The Flask request object.
        :return: The authorization header or None if not found.
        '''
        if request is None:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''Get the current user based on the Flask request.
        :param request: The Flask request object.
        :return: The current user or None if not authenticated.
        '''
        if request is None:
            return None
