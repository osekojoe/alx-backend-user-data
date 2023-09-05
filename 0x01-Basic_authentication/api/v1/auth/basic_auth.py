#!/usr/bin/env python3
"""
Basic Authentication handler
"""


import base64
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic Authentication handler - inherits from Auth
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for a Basic Authentication"""
        if (authorization_header is None or
                not isinstance(authorization_header, str) or
                not authorization_header.startswith('Basic')):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header
        """
        if base64_authorization_header is None or not isinstance(
             base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except Exception as e:
            return None
