# Sender-constrained introspection reference

This reference starts four independent components:

- an HTTPS Authorization Server fixture that issues opaque DPoP-bound tokens;
- a four-worker resource server;
- Redis for proof replay and bounded introspection caching;
- a short-lived certificate generator for the RS→AS TLS channel.

The resource server authenticates to the AS with RFC 7523 `private_key_jwt`,
requires RFC 9701 signed responses, validates the AS certificate and signing
key, checks the opaque token's `cnf.jkt` against a local RFC 9449 proof, and
uses Redis without placing raw access tokens in keys.

Run:

```sh
sh docker/reference/introspection/verify.sh
```
