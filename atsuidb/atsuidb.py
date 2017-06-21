import os
import re
import time
import json
import pymongo

from binascii import b2a_hex, a2b_hex
from hashlib import sha512

from bson.objectid import ObjectId
from pymongo.errors import DuplicateKeyError

from . import errors

# An class so that objects can keep a persistent DB connection
class AtsuiDB:
    def __init__(self):
        # creat a persistent DB connection
        self.mongo = pymongo.MongoClient()
        if not self.mongo:
            raise Exception("database connection refused")
        self.users = self.mongo["atsui_meta"].users

    # Inserts a new user to the DB
    def register(self, username, password, details={}):
        # check if user exists
        if self.users.find_one({"username": username.lower()}) is not None:
            raise errors.UsernameTaken()
        # generate salted password hash
        salt = self.gen_salt(as_hex=False)
        # convert salt to hex for storage as string
        salt_hex = b2a_hex(salt)
        password_hash = self.hash_password(password, salt)
        # construct user model
        user_data = {
            "is_admin": False,
            "username": username.lower(),
            "password_hash": password_hash,
            "salt": salt_hex,
            "details": details,
            "session_salt": None,   # created on login
            "roles": [   # everyone joins the "Public" role
                ["Public", get_hash(b"")]
            ],
        }
        # insert the user into the database
        self.users.insert_one(user_data)
        return user_data

    # Logs a user in, creating a new session token and salt
    def login(self, username, password):
        # find the user
        user_data = self.users.find_one({"username": username.lower()})
        if user_data is None:
            raise errors.LoginInvalid("user not found")
        # check their password
        if not self.check_password(user_data, password):
            raise errors.LoginInvalid("Incorrect password")
        # create a new session token for the user
        session_token = self.create_session(user_data)
        # construct data for sending
        safe_user_data = self.get_safe_user(user_data)
        return {
            "session_token": session_token,
            "user_data": safe_user_data,
            "user_id": str(user_data["_id"])
        }

    # Sends a message
    def send(self, data, collection, sender, recipient, auths):
        print(1)
        # find the auth pair of the desired sender
        sender = self.users.find_one({"username": sender})
        sender_pair = False
        # search for it in the supplied auths
        for auth in request['auths']:
          if auth[0] == str(sender["_id"]):
            sender_pair = auth
        # if no authentication was found, disregard
        if not sender_pair:
            raise errors.LoginRequired()
        print(2)
        # authenticate sender
        sender = util.auth(sender_pair[0], sender_pair[1])
        if not sender:# this should never happen
            raise errors.LoginRequired()
        print(3)

        # find recipient
        recipient = users.find_one({"username": recipient})
        if not recipient:
            raise errors.DataRequired()
        print(4)

        # store document
        return mongo["atsui"][collection].insert_one(data)

    # Creates a session token for a given user
    def create_session(self, user_data):
        # create a salt so the same session key is only valid once
        session_salt = self.gen_salt(as_hex=False)
        # add the salt to the database so we can verify it later
        self.users.update_one(
            {"_id": user_data["_id"]},
            {
                "$set": {"session_salt": session_salt}
            }
        )
        # construct a session key from the salt
        session_key = self.hash_password(user_data["password_hash"], session_salt)
        return session_key

    # general hash method
    def get_hash(self, data, as_hex=True):
        hasher = sha512()
        hasher.update(data)
        if as_hex:
            return hasher.hexdigest()
        else:
            return hasher.digest()

    # password hash method
    def hash_password(self, password, salt, as_hex=True):
        hasher = sha512()
        hasher.update(password.encode("utf8"))
        hasher.update(salt)
        if as_hex:
            return hasher.hexdigest()
        else:
            return hasher.digest()

    # salt generator
    def gen_salt(self, as_hex=True):
        salt = os.urandom(32)
        if as_hex:
            return b2a_hex(salt)
        else:
            return salt

    # validated a submitted password
    def check_password(self, user_data, password):
        pass_salt = a2b_hex(user_data["salt"])
        password_hash = self.hash_password(password, pass_salt)
        return password_hash == user_data["password_hash"]

    # Strips all possibly sensitive information from a user model
    def get_safe_user(self, user):
        safe_user = {}
        for key in ["username", "display_name", "details", "roles", "is_admin"]:
            try:
                safe_user[key] = user[key]
            except KeyError:
                pass
        return safe_user

    # Authenticates a user using a session token, id pair
    # Reads from cookies if available
    def authenticate(self, user_id=None, session=None):
        if user_id is None or session is None:
            try:
                user_id = request.cookies["user_id"]
                session = request.cookies["session"]
            except KeyError:
                return None

        user_data = users.find_one({'_id': ObjectId(user_id)})

        # check if the session is legit
        if not user_data:
            return None
        if not session == self.hash_password(
                user_data["password_hash"], user_data["session_salt"]):
            return None
        return user_data

    def keys_exist(self, keys, dicti):
        for key in keys:
            if key not in dicti:
                return False
        return True
