// rtm wrapper
function AtsuiClient(collection, url, _debug) {
  this.uri = url || document.location.host;
  this.socket_url = "http://" + this.uri + "/socket";
  this.ajax_url = "http://" + this.uri + "/api/1/";
  this.collection = collection;
  this.debug = true ? _debug : false;
  // This is just sha512(sha512("")). Don't trip, yo.
  this.blank_sha512 =
    '8fb29448faee18b656030e8f5a8b9e9a695900f36a3b7d7ebb0d9d51e06c8569' +
    'd81a55e39b481cf50546d697e7bde1715aa6badede8ddc801c739777be77f166';

  // creates a new connection to the database
  this.new_connection = function () {
    if (typeof this.ws != "undefined"){
        this.ws.disconnect();
    }
    this.ws = io.connect(this.socket_url);
    if (this.debug){
      this.ws.on("log", function(data){console.log(data)});
      this.ws.on("error", function(data){console.log(data)});
    }
    return this.ws;
  };

  this.clean_up = function(){
    for (i in window.rtm_sockets){
      window.rtm_sockets[i].disconnect();
    }
  }

  // listens to all possible messages matching `where` if specified
  this.listen = function () {   // ([backlog:bool, where:obj, callback:func])
    // create a new db connection
    this.new_connection(), query = {};
    query['backlog'] = true;
    // gather arguments and build query
    for (var i in arguments){
      var argument = arguments[i];
      switch (typeof argument){
        case "function":   // callback
          this.ws.on("data", argument);
          break;
        case "boolean":   // backlog
          query['backlog'] = argument;
          break;
        case "object":   // where
          query['where'] = argument;
          break;
      }
    }
    // get all user auths
    query['auths'] = this.get_auth();
    // set collection
    query['collection'] = this.collection;
    // send query
    this.ws.emit('listen', JSON.stringify(query));
  };

  // sends data to the target collection
  this.send = function(data, sender, recipient){
    $.post(
      this.ajax_url + "send", {data: JSON.stringify({
        collection: this.collection,
        sender: typeof sender != "undefined" ? sender : $.Cookie('username'),
        auths: this.get_auth(),
        recipient: typeof recipient != "undefined" ? recipient : "Public",
        data: data
      })},
      function(data){
        // success
        return true;
      }
    );
  }

  // updates target document with data
  this.update = function(document_id, data){
    // use an already created non-blocking connection if available
    if (typeof this.send_con == "undefined"){
      this.send_con = this.new_connection();
    }
    this.send_con.emit('update', JSON.stringify({
      collection: this.collection,
      auths: this.get_auth(),
      data: data,
      document_id: document_id
    }));
  }

  this.keys_exist = function(key_list, obj){
    for (var i in key_list){
      var key = key_list[i];
      if (obj[key] == undefined){
        return false;
      }
    }
    return true;
  }

  // gets all datachests the user is authenticated to see
  this.get_auth = function(){
    if (typeof user_data != "undefined"){
      var auths = user_data.auths;
    }
    else {
      // if the user is not logged in, create a set of public auths
      var auths = [[{"$auid_of": "#Public"}, this.blank_sha512]];
    }
    return auths;
  }
}
