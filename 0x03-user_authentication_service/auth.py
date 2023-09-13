#!/usr/bin/env python3
"""
Hashing input passwords
"""


import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """hash password"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


def _generate_uuid() -> str:
    """
    Generate a new UUID and return it as a string.
    This function is private to the auth module.
    """
    new_uuid = uuid.uuid4()
    return str(new_uuid)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register new user to the database.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        else:
            raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """ Locate the user by email
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        # Check if the provided password matches the hashed password
        hashed_password = user.hashed_password
        provided_password = password.encode()

        if bcrypt.checkpw(provided_password, hashed_password):
            return True

        return False

    def create_session(self, email: str) -> str:
        """takes an email string argument and returns the
        session ID as a string.
        """
        user = self._db.find_user_by_email(email)

        if user:
            # Generate a new UUID using your _generate_uuid function
            session_id = self._generate_uuid()

            # Store the session_id in the database for the user
            self._db.set_user_session_id(user.id, session_id)

            return session_id

        return None  # if the user does not exist
