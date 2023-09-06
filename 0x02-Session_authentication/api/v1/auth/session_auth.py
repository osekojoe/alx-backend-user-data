#!/usr/bin/env python3
"""
Session authentication module for the API.
"""


from .auth import Auth
import uuid


class SessionAuth(Auth):
    """
    Session authentication class
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a Session ID for a user.

        :param user_id: The user's ID.
        :return: The created Session ID or None if user_id is not valid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        # Generate a Session ID using uuid4
        session_id = str(uuid.uuid4())
        # Store the user_id in the user_id_by_session_id dictionary
        self.user_id_by_session_id[session_id] = user_id

        return session_id
