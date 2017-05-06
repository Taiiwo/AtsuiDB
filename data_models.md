Data Models
===========
The aim of this document is to outline the different data models to be used in this project.

User
----
```JSON
{
    "username": "username of user",
    "password_hash": "salted password hash",
    "session_salt": "a key generated for each session, can be used to authenticate",
    "keys": {   // Encryption keys sent to the user for P2P transit
        "public_key": "GPG public key",
        "private_key": "GPG private key"
    },
    "roles": {   // List of roles the user has access to
        "role_name, used to identify a role": "role_token, can be used to authenticate as a member of this role",
        ...
    }
}
```

Role
-----
```JSON
{
    "role_name": "name used to identify the role",
    "parent": "role or user than can manage the role",
    "members": [list of members of the role],
}
```

Document
--------
```JSON
{
    "recipient": "The person or group the document is for",
    "author": "The user that created the document",
    "author_role": "role the author is using to publish the document. optional".
    "signature": "GPG sig of the document signed by the server for use in P2P exchange",
    "content": {Content of the document}
}
```