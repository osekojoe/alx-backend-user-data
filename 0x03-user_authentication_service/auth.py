#!/usr/bin/env python3
"""
Hashing input passwords
"""


import bcrypt


def _hash_password(password: str) -> bytes:
    """hash password"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password
