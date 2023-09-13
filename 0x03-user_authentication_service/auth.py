#!/usr/bin/env python3
"""
Hashing input passwords
"""


import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
from typing import Union

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
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        # Generate a new UUID using your _generate_uuid function
        session_id = _generate_uuid()

        # Store the session_id in the database for the user
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """takes a single session_id string argument
        Returns corresponding User or None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """takes a single user_id integer argument and
        returns None.
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)

        return None

    def get_reset_password_token(self, email: str) -> str:
        """If the user does not exist, raise a ValueError exception.
        If it exists, generate a UUID and update the user’s
          reset_token database field. Return the toke"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_pwd_token = _generate_uuid()

        self._db.update_user(user.id, reset_token=reset_pwd_token)

        return reset_pwd_token
