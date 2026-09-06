# Local development JWKS

Run `node scripts/init-dev-jwks.mjs` before starting the Compose dev profile.
It creates a fresh RSA key under the ignored `generated/` directory and writes
only the public JWKS under `generated/public/`, the directory served by Compose.
Repeated runs preserve the key and regenerate its public JWKS. Keep the private
file private on your OS; Unix creation uses mode 0600.

The old repository-wide signing fixture is retired and its public key is refused
by the gateway regardless of key ID or issuer. Delete the generated directory
and rerun initialization to rotate local credentials. Development issuer and
audience values remain test-only; production trust comes from your own IdP.
