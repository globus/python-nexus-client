python-nexus-client
===================

Example python client for interacting with Globus Nexus service.

The main entry point to this library is `nexus.Client`.  This allows
access to all of the main methods.

When a user authenticates with Nexus, they are issued a token.  An API
client can validate a user's authentication by taking that token and
calling `client.authenticate_user(token)`.

This Library is Only an Example
---

This library is officially an example, and the Globus Team is not committed to
supporting it.
It is maintained on a "best effort" basis, and it is not guaranteed to work
correctly as our service evolves.

Updates for February 13th, 2016
---

On 2016-02-13, Globus is slated to launch a new centralized authentication and
authorization service named Globus Auth.
We will be maintaining limited backwards compatibility for clients of the Nexus
service, and this library will contain some instructional information regarding
the transition.

As always, this library is example code intended as a reference, and not
guaranteed to be fully functional.
