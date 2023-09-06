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

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Get a User ID based on a Session ID.

        :param session_id: The Session ID.
        :return: The User ID associated with the Session ID, or None if session_id is not valid or not found.
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        # Use .get() to access the User ID based on the Session ID
        return self.user_id_by_session_id.get(session_id)
