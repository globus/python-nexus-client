python-nexus-client
===================

Python client for interacting with GlobusOnline Nexus service.

The main entry point to this library is nexus.Client.  This allows
access to all of the main methods.

When a user authenticates with Nexus, they are issued a token.  An API
client can validate a user's authentication by taking that token and
calling client.authenticate_user(token).
