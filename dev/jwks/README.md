# Dev JWKS Fixture

This directory contains a deliberately public, checked-in RSA signing fixture for local development only.

- `jwks.json` is served by the compose dev profile as the local JWKS endpoint.
- `dev-signing-key.pem` is the matching private key for minting local test tokens.

The private key is not a production credential. It is intentionally named as a dev signing key, committed to the repository, and should never be reused outside the local GreenGateway dev profile.
