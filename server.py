import os
import re
import time
import json

from flask import request, jsonify, Flask, make_response
from flask_socketio import SocketIO, emit, send
from bson.objectid import ObjectId
from flask_cors import CORS

import atsuidb.atsuidb
import atsuidb.errors

app = Flask(__name__)
socket = SocketIO(app)
CORS(app)
adb = atsuidb.atsuidb.AtsuiDB()

# Returns a flask success response
def make_success_response(extra={}):
    data_res = extra
    data_res["success"] = True
    res = make_response(jsonify(data_res), 200)
    return res

# Handle errors with proper status code and error message
@app.errorhandler(atsuidb.errors.ApiError)
def api_exception_handler(e):
    print(e.name)
    response = jsonify({
        "success": False,
        "errors": [e.to_dict()]
    })
    response.status_code = e.status_code
    return response

# Registers a new user and logs them in
@app.route("/api/1/register", methods=["POST"])
def api_register():
    # get optional fields
    details = request.form["details"] if "details" in request.form else {}
    # get required fields
    try:
        username = request.form["username"]
        password = request.form["password"]
    except KeyError as e:
        raise atsuidb.errors.DataRequired(e.args[0])
    # basic username and password validation
    if not (1 <= len(username) <= 140):
        raise atsuidb.errors.DataInvalid("username")
    if len(password) <= 6:
        raise atsuidb.errors.DataInvalid("password")

    # register the user
    adb.register(username, password, details)
    # now behave like a login request
    return api_login()

# Logs in a user. Returns their authentication information
@app.route("/api/1/login", methods=["POST"])
def api_login():
    try:
        username = request.form["username"]
        password = request.form["password"]
    except KeyError as e:
        raise DataRequired(e.args[0])
    # log the user in
    return make_success_response(adb.login(username, password))

# Takes authentication information and returns user info
@app.route("/api/1/authenticate", methods=["POST"])
def api_authenticate():
    user_data = authenticate()
    if not user_data:
        raise LoginRequired()

    safe_user_data = get_safe_user(user_data)
    return make_success_response({"user_data": safe_user_data})

# API method for sending documents
@app.route("/api/1/send", methods=["POST"])
def api_send():
    # validate request
    request_data = json.loads(request.form["data"])
    if not adb.keys_exist(
            ["sender", "recipient", "auths", "collection", "data"],
            request_data):
        raise atsuidb.errors.DataRequired()
    # attempt to send document
    document = adb.send(
        request_data["data"],
        request_data["collection"],
        request_data["sender"],
        request_data["recipient"],
        request_data["auths"]
    )
    if not document:
        raise atsuidb.errors.DataRequired()
    # Now update all the listeners
    document_tidy = {
        "sender": document["sender"],
        "recipient": document["recipient"],
        "data": document["data"],
        "id": str(document["_id"]),
        "update": False
    }
    emit_to_relevant_sockets(request_data, document_tidy)
    return make_response("success")

# API method for updating documents
@app.route("/api/1/update", methods=["POST"])
def api_update(data):
    request = json.loads(data)
    # validate request
    if not util.keys_exist(
            ["auths", "collection", "data", "document_id"],
            request):
        emit("log", "Missing Arguments")
        return "0"
    # find document
    coll = util.get_collection(request['collection'])
    document = coll.find_one({"_id": ObjectId(request['document_id'])})
    # authenticate update
    authenticated = False
    for auth in request['auths']:
        if auth[0] == document['sender']:
            if util.auth(auth[0], auth[1]):
                authenticated = True
                sender = auth[0]
                break
            else:
                # don't allow more than one invalid request to prevent
                # server-side password bruteforcing. Just incase.
                break
    if not authenticated:
        emit("log", "Insufficient permissions")
        return "0"
    # update document
    document = util.update_document(request['data'], request['document_id'],
                                    request['collection'])
    if not document:
        emit('log', make_error(
            'unknown_error',
            "Data was not added to the DB for some reason"
        ))
        return "0"
    # send Updates
    document_tidy = {
        "sender": document["sender"],
        "recipient": document["recipient"],
        "data": document["data"],
        "id": str(document["_id"]),
        "ts": document["ts"],
        "update": True
    }
    util.emit_to_relevant_sockets(request, document)
    emit("log", "Data was updated")

@app.route("/api/1/change_password", methods=["POST"])
def api_change_password():
    """Changes a user"s password."""
    try:
        cur_password = request.form["cur_password"]
        new_password = request.form["new_password"]
    except KeyError as e:
        raise DataRequired(e.args[0])

    # Make sure the user is logged in
    user_data = authenticate()
    if not user_data:
        raise LoginRequired()

    # check if the old password matches the current password
    # it should be, but just in case they're cookie stealing
    if not check_password(user_data, cur_password):
        raise PasswordIncorrect()

    # update the user
    salt = gen_salt(as_hex=False)
    salt_hex = b2a_hex(salt)
    passhash = hash_password(new_password, salt)

    util.update_user(
        user_data["_id"],
        {
            "$set": {
                "salt": salt_hex,
                "passhash": passhash,
            }
        }
    )

    # calling user will need new session key, but ceebs

    return make_success_response()


# Completely deletes a user"s account
@app.route("/api/1/delete_account", methods=["POST"])
def api_delete_account():
    user_data = authenticate()
    if not user_data:
        raise LoginRequired()

    users.delete_one({"_id": ObjectId(user_data["_id"])})
    return make_success_response({"message": "T^T"})

# converts a user/group name into an id
@app.route("/api/1/get_uid", methods=["GET"])
def get_uid():
    try:
        username = request.args["username"]
    except KeyError as e:
        raise DataRequired(e.args[0])

    user_data = users.find_one({"username": username.lower()}, {"_id": True})
    if not user_data:
        raise UserNotFound()

    return make_success_response({"id": str(user_data["_id"])})


# Updates users" details property.
@app.route("/api/1/update-user", methods=["POST"])
def update_user():
    try:
        new_details = request.form["new_details"]
    except KeyError as e:
        raise DataRequired(e.args[0])

    user_data = authenticate()
    if not user_data:
        raise LoginRequired()

    #   User is authed, do some stuff
    new_details = json.loads(new_details)
    update_query = {
        "$set": {
            "details": user["details"].update(new_details)
        }
    }
    if util.update_user(user["_id"], update_query):
        return make_success_response()
    else:
        raise UnknownError()


# runs when a socket disconnects
@socket.on("disconnect", namespace="/atsui")
def disconnect():
    print(len(all_sockets))
    # if socket is requesting
    if request.sid in all_sockets:
        # remove from requesters
        all_sockets[request.sid].connected = False
        del all_sockets[request.sid]

""" query structure:
{
    collection: str,
    query:
}
"""
# Adds a new subscription to a socket
@socket.on("request", namespace="/atsui")
def request_handler(data):
    request_data = json.loads(data)
    if not util.keys_exist(["collection", "auths"], request_data):
        emit("log", "Missing Arguments")
        return "0"
    # check all authentications
    users = adb.get_collection('users',  db=util.config['auth_db'])
    auths = adb.escape_user_query(request_data['auths'])
    # iterate supplied auths and emit if any of them fail
    for pair in auths:
        if not adb.auth(pair[0], pair[1]):
            emit("log", "A supplied username was not found")
            return "0"
    # escape the where clause
    if "where" in request_data:
        request_data['where'] = atsui.escape_user_query(request_data['where'])
    # send the user backlogs if requested
    if "backlog" in request_data and request_data["backlog"]:
        # get previously sent documents
        backlog = adb.get_documents(
            request_data['auths'],
            request_data["collection"],
            time_order=True,
            where=request_data['where'] if "where" in request_data else False
        )
        # send each document separately
        for document in backlog:
            # make sure it's a client document
            if document["visible"]:
                document_tidy = {
                    "sender": document["sender"],
                    "recipient": document["recipient"],
                    "data": document["data"],
                    "id": str(document["_id"]),
                    "ts": document["ts"],
                    "update": False
                }
                emit("data", document_tidy)
    # add socket to dict of sockets to keep updated
    # (Choosing speed over memory here)
    # create a socket object to represent this connection
    socket = Socket(request.sid, request_data)
    # add us to a list of all requester sockets
    if not request_data["collection"] in live_sockets:
        live_sockets[request_data["collection"]] = []
    live_sockets[request_data["collection"]].append(socket)
    all_sockets[socket.sid] = socket

# Emits document to all sockets subscibed to request
def emit_to_relevant_sockets(request_data, document):
    # skip if there are obviously no listeners
    if not request_data['collection'] in live_sockets\
            or len(live_sockets[request_data['collection']]) < 1:
        return True
    # for each listener in this collection
    for socket in live_sockets[request_data['collection']]:
        # remove disconnected sockets
        if not socket.connected:
            live_sockets[request_data['collection']].remove(socket)
            continue
        # if the listener is authenticated as the sender or the recipient
        if mongoquery.Query({"$or": [{"sender": {"$in": socket.ids}},
                                     {"recipient": {"$in": socket.ids}}
                ]}).match(document):
            # check user defined query
            if mongoquery.Query(socket.where).match(document):
                # document matches this users specifications. Send document
                socket.emit("data", document)

# Object that represents a socket connection
class Socket:
    def __init__(self, sid, query):
        self.sid = sid
        self.query = query
        self.connected = True
        auths = query['auths']
        self.ids = list(ObjectId(auth[0]) for auth in auths)
        self.where = query['where'] if "where" in query else False

    # Emits data to a socket's unique room
    def emit(self, event, data):
        emit(event, data, room=self.sid)

live_sockets = {}
all_sockets = {}

if __name__ == "__main__":
    socket.run(app, "0.0.0.0", 8000, debug=True)
