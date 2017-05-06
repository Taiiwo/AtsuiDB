# AtsuiDB
AtsuiDB is (will be) a Flask application (written in Python) inspired by firebase that aims to give database access to the front end, bypassing possible insecure database wrappers, and removing the need for writing repetitive back-end code.

Aims
----
The basic aim for AtsuiDB is to allow the developer to make front-end JavaScript calls to an API provided by AtsuiDB. The API will allow front end applications to insert and retrieve data from a mongodb database. It does this in such a way that makes it impossible for a user to read data they don't have access to, or insert data where it's not permitted, all in a way that's simple, and easy to implement for the developer.

AtsuiDB is, however, a very broad idea, and has many more capabilities that can be implemented due to the way it's laid out. Here is a list of those features. Context will be added to them later.

- P2P data availability, lowering bandwidth costs and resource consumption
- Signed data for 100% verification of data integrity
- Data encrypted in transfer, allowing for distribution by anyone, with no risk to security
- Real-time updates to data distributed through a network of websockets

How does it work?
-----------------
In mongodb, each database contains a list of collections, and each collection contains a list of documents. A document is effectively a JSON object, capable of storing information in a useful format for easy integration into your application.

In AtsuiDB, imagine each document as an envelope, with a `to` and `from` public key. All data within the letter is encrypted for both keys and signed with `from` key, allowing you to verify that the message was in fact sent by someone authenticated as the author. Because this document is encrypted, it can be handled and stored by anyone, as they will not be able to read the contents unless they have the private key of either the author or the recipient. Because of this, it is possible to allow all documents sent to a client to be made available to all other clients that can connect to it, safely in the knowledge that it can never be modified by the client, or read by anyone who requests data without access.

For example. Imagine a blog page with a list of posts. The first user connects, authenticates, and asks for all of the blog posts in the database (All the documents with "blog_publisher" as the author and "blog_reader" as the recipient, for example). The client is then subscribed to all changes to that data. Any time a new blog post is published, the client is sent the information via websocket.

In continuation of this example, if a second client(client_b) were to connect to the database at a time where the server is busy, client_b would be given a list of clients that are still connected via websocket, and have been given the data they are requesting. On this list would be the client from the example above(client_a). In this case, client_b could make the same request to client_a, and retrieve the same information (verifyable by the cryptographic signatures), along with all of the updates sent to client_a by the main server.

How hard is it to implement?
----------------------------
While the distribution method is quite complicated, the request method is designed to be simpler than the average database request.

Consider the following pseudo-javascript:
```javascript
var adb = AtsuiDB("blog-posts");   // init the database connection
adb.request(
  {author: "blog_publisher"},   // query specifying the documents required
  function(blog_post){   // function executed for every document received
    append_blog_post_to_page(blog_post);   // a pseudo function that adds posts to the page
  }
);
```
In the above example, data will be discretely requested from the best available source (ideally the server, then other clients the least number of hops from it). Every document that is received, in order, will be verified, decrypted, and sent to the callback function which adds a single post to the page. This will populate your page with blog posts, but will also update your page when any new blog post is published.

Inserting data is just as simple as you'd imagine. You don't need to use a websocket, and the data is send directly to a HTTP API. Consider the following code:
```javascript
var adb = AtsuiDB("blog-posts");   // init the database connection
adb.send(
  {
    author: "blog_publisher",   // keys will be found and used automatically
    recipient: "blog_reader",
    data: {content: "this is a blog post", title:"10 things you didn't know about database connection"}
  },
  function(status) {
    // optional callback function when the data has been sent
  }
);
```

Authentication
--------------
Authentication is an important part of AtsuiDB. Each user can have access to multiple roles. Roles can be public or private, where private roles will require any user to be given access to them by a user with the permission to do so. On the other hand, anyone is capable of adding themselves to roles that are public. To handle this complicated process, each user is given a keychain. The user submits their username and password to the database in exchange for a list of authentication tokens for their roles. These tokens are stored as cookies and used automatically for any database connection they attempt to make. The authentication process can be implemented as follows:

### Logging in
```javascript
// set the username and password that will be used to authenticate next request
AtsuiDB.login("username", "password");
```

### Logging out
```javascript
// destroys cookies
AtsuiDB.logout();
```

### Creating a user
```javascript
// create a new user. Keys will be generated locally
AtsuiDB.register("username", "password");
```

### Creating a role
```javascript
AtsuiDB.create_role({
  name: "blog_publisher",   // name of role
  parent: "admin"   // role that can administrate this role
});
```

### managing a role
```javascript
// adds user to role
AtsuiDB.role_invite("blog_publisher", "username");
// removes user from role
AtsuiDB.role_remove("blog_publisher", "username");
```

Admin Panel
-----------
Included in AtsuiDB is also an admin panel located at `/AtsuiDB`. This panel can be used to create and manage roles, inspect and edit the documents in specific collections, and manage other server settings. Users can also optionally visit this panel to see all the data they have access to, and edit any data they have the permissions to edit (Anything they, or any role they belong to, are the "author" of).
