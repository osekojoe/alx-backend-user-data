#!/usr/bin/env python3
"""
Hashing input passwords
"""


import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """hash password"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


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
