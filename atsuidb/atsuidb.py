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
        self.datachests = self.mongo["atsui_meta"].datachests

    # Inserts a new user to the DB
    def register(self, username, password, details={}):
        # check if user exists
        if self.users.find_one({"username": username.lower()}) is not None:
            raise errors.UsernameTaken()
        # names starting with # or @ not allowed for clarity
        if username[0] in ["@", "#"]:
            raise errors.DataInvalid()
        # generate salted password hash
        salt = self.gen_salt(as_hex=True)
        password_hash = self.hash_password(password, salt)
        # construct user model
        user_data = {
            "is_admin": False,
            "username": username.lower(),
            "password_hash": password_hash,
            "salt": salt_hex,
            "details": details,
            "session_salt": None,   # created on login
            "auths": [   # everyone joins the "Public" role
                ["#Public", get_hash(b"")]
            ],
        }
        # insert the user into the database
        self.users.insert_one(user_data)
        return user_data

    def create_datachest(self, name, password, details):
        # check if user exists
        if self.datachests.find_one({"name": name}) is not None:
            raise errors.UsernameTaken()
        # names starting with # or @ not allowed for clarity
        if name[0] in ["@", "#"]:
            raise errors.DataInvalid()
        # generate salted password hash
        salt = self.gen_salt(as_hex=True) if password != "" else ""
        password_hash = self.hash_password(password, salt)
        # construct user model
        chest_data = {
            "is_admin": False,
            "name": name,
            "password_hash": password_hash,
            "salt": salt,
            "details": details,
            "session_salt": ""
        }
        # insert the chest into the database
        self.datachests.insert_one(chest_data)
        return chest_data

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
    def send(self, data, collection, sender_id, recipient_id, auths):
        # find the auth pair of the desired sender
        sender = self.name_lookup(sender_id)
        sender_pair = False
        # process auth list, processing username <-> uid operations
        auths = self.escape_user_query(auths)
        # check that the sender can authenticate
        for auth in auths:
            if auth[0] == str(sender["_id"]):
                sender_pair = auth
        # if no authentication was found, disregard
        if not sender_pair:
            raise errors.LoginRequired()
        # authenticate sender
        sender = self.authenticate(sender_pair[0], sender_pair[1], sender)
        if not sender:# this should never happen
            raise errors.LoginRequired()
        # find recipient
        recipient = self.name_lookup(recipient_id)
        if not recipient:
            raise errors.DataRequired()

        # create nice document
        document = {
            "sender": sender_id,
            "recipient": recipient_id,
            "data": data
        }
        # store document
        id = self.mongo["atsui"][collection].insert_one(document).inserted_id
        document["_id"] = id
        return document

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
    def authenticate(self, user_id=None, session=None, user_data=None):
        if user_id is None or session is None:
            try:
                user_id = request.cookies["user_id"]
                session = request.cookies["session"]
            except KeyError:
                raise errors.DataRequired()

        if not user_data:
            user_data = self.users.find_one({'_id': ObjectId(user_id)})

        # check if the session is legit
        if not user_data:
            raise errors.LoginInvalid()
        if not session == self.hash_password(
                user_data["password_hash"], user_data["session_salt"]):
            raise errors.LoginInvalid()
        return user_data

    def keys_exist(self, keys, dicti):
        for key in keys:
            if key not in dicti:
                return False
        return True

    # Make a user submitted query ready for use in mongodb
    def escape_user_query(self, query):
        # if input is an array
        if isinstance(query, list) or isinstance(query, tuple):
            # recurse for each element in the array
            for i in range(len(query)):
                query[i] = self.escape_user_query(query[i])
        # if input is a dict
        elif isinstance(query, dict):
            # look for special operations and replace them with operation output
            for key, value in query.items():
                # convert name to uid
                if key == "$uid_of":
                    if value[0] == "#":
                        target = self.datachests.find_one({"name": value[1:]})
                    elif value[0] == "@":
                        target = self.users.find_one({"username": value[1:]})
                    else:
                        raise errors.DataInvalid(
                            "Username or datachest supplied without classifier"
                        )
                    if not target:
                        raise errors.UserNotFound()
                    return str(target["_id"])
                # Converts a string based ObjectID to a ObjectID object
                elif key == "$oid":
                    return ObjectId(value)
                elif key[0] == "$":
                    operation = key[1:]
                    if operation not in ["eq", "gt", "lt", "in", "and", "or"]:
                        raise errors.DataInvalid("Invalid operation in query")
                else:
                    query[key] = self.escape_user_query(query[key])
        return query

    def name_lookup(self, name):
        if name[0] == "#":
            user = self.datachests.find_one({"name": name[1:]})
        elif name[0] == "@":
            user = self.users.find_one({"username": name[1:]})
        else:
            raise errors.DataInvalid("Name missing idetifier (@, #)")
        if not user:
            raise errors.UserNotFound()
        return user
