import websocket
import requests

class AtsuiClient:
    def __init__(self, collection, uri=False, auths=[]):
        self.uri = uri if uri else "localhost"
        self.socket_url = "http://" + self.uri + "/socket"
        self.ajax_url = "http://" + self.uri + "/api/1/"
        self.collection = colletion
        self.callbacks = {}
        # This is just sha512(sha512("")). Don't trip, yo.
        self.blank_sha512 =
            '8fb29448faee18b656030e8f5a8b9e9a695900f36a3b7d7ebb0d9d51e06c8569'
            'd81a55e39b481cf50546d697e7bde1715aa6badede8ddc801c739777be77f166'
        self.auths = auths
        self.auths.append([{"$uid_of": "Public"}, self.blank_sha512])

    # Decorator that adds a callback that runs when a document is posted to
    # `collection`
    # query = posted documents must match query trigger
    # backlog = should we run for all past documents?
    # Example:
    # @atsui.listen("messages", query={"sender": {"$uid": "God"}}, backlog=True)
    # def new_message_from_god(message):
    #   print("Got a new message from god: " + message.data.text)
    def listen(self, callback):
        def listen_request(query={}, backlog=False):
            self.query = query
            self.backlog = backlog
            self.listen_callback = callback
        return listen_request

    def send(self, data, sender, recipient):
        requests.post(
            self.ajax_url,
            json.dumps({
                "collection": self.collection,
                "sender": sender,
                "recipient": recipient,
                "auths": self.auths,
                "data": data
            })
        )

    def add_auth(self, auth):
        self.auths.append(auth)

    def on_error(self, callback):
        def add_error_handler():
            self.error_callback = callback
        return add_error_handler

    def on_disconnect(self, callback):
        def add_disconnect_handler():
            self.disconnect_callback = callback
        return add_disconnect_handler

    def _on_open(self):
        # perform the listen request
        self.query["collection"] = self.collection
        self.query["auths"] = self.auths
        self.ws.emit("listen", json.dumps(self.query))

    def run(self):
        websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(self.socket_url,
                on_message = self.listen_callback,
                on_error = self.error_callback,
                on_close = self.disconnect_callback)
        ws.on_open = self._on_open
        ws.run_forever()
