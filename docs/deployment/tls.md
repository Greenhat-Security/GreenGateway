# Runbook: TLS to the database and the certificate authority

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule: every production connection to the authority is TLS with certificate and hostname verification, and there is no plaintext fallback.** A server that will not speak TLS fails the connection at startup. The gateway does not degrade, retry in the clear, or warn and continue.

## The settings

| Setting | Default | What it does |
| --- | --- | --- |
| `DATABASE_TLS_MODE` | `verify` | `verify` requires TLS with certificate and hostname verification. `loopback-dev` skips TLS entirely and is refused for any target that is not loopback, the literal name `localhost`, or a Unix socket. |
| `DATABASE_TLS_CA_FILE` | unset | A PEM bundle of extra trust anchors, layered **on top of** the platform trust store. It is never a replacement for it. |

`sslmode` in the DSN is rejected. TLS policy is one setting, in the environment, where your configuration management can see it — not a query parameter buried in a credential file.

The hostname that gets verified is the host in the DSN. If the DSN says `db.internal.example.com`, the server's certificate must carry `db.internal.example.com` in its subject alternative names. An IP address in the DSN needs an IP SAN, which most internal CAs will not issue; use a name.

## Case 1: the database's CA is already in the platform trust store

Nothing to configure. Leave `DATABASE_TLS_MODE=verify`, leave `DATABASE_TLS_CA_FILE` unset, and confirm:

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-runtime \
  gateway migrate check
```

Expected output: the schema status line and exit `0`. A TLS problem surfaces here, before any replica starts, as a connection failure naming the TLS reason.

This is the case for every major managed PostgreSQL whose server certificates chain to a public CA. It is not the case for a private CA, or for a managed service whose certificate chains to its own root.

## Case 2: a private or provider CA

Put the CA's PEM at `DATABASE_TLS_CA_FILE`. It is public material — world-readable is fine; group- or world-**writable** is refused, because a writable trust anchor is not a trust anchor.

```sh
install -m 0444 provider-ca.pem /etc/greengateway/tls/ca.pem
```

Then set:

```sh
DATABASE_TLS_MODE=verify
DATABASE_TLS_CA_FILE=/etc/greengateway/tls/ca.pem
```

Verify before you deploy it, with the tool that will actually be doing the verifying:

```sh
STATE_BACKEND=postgres DEPLOYMENT_ID=deploy-prod-eu \
  DATABASE_URL_FILE=/run/secrets/greengateway/database-url-migration \
  DATABASE_TLS_MODE=verify DATABASE_TLS_CA_FILE=/etc/greengateway/tls/ca.pem \
  gateway migrate check
```

If you want to see the chain independently first:

```sh
openssl s_client -connect db.internal.example.com:5432 -starttls postgres \
  -CAfile /etc/greengateway/tls/ca.pem -verify_hostname db.internal.example.com </dev/null
```

Expected output ends with `Verify return code: 0 (ok)`. Anything else is the problem you are about to hit, described more clearly than the gateway will describe it.

## Case 3: a CA you run yourself, for the compose example or a lab

The [example compose file](docker-compose.ha.yml) needs a certificate for the name `db`. This produces one, and a CA to sign it, valid for one year. Run it in `docs/deployment/`.

```sh
mkdir -p tls && cd tls

openssl req -x509 -newkey rsa:4096 -sha256 -days 1825 -nodes \
  -keyout ca.key -out ca.pem \
  -subj "/CN=GreenGateway example CA"

openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr \
  -subj "/CN=db"

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:db\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")

# PostgreSQL refuses to start if the key is group- or world-readable, and it
# must be owned by the uid the server runs as (999 in the postgres:16 image).
chmod 0600 server.key
sudo chown 999:999 server.key

rm server.csr ca.key   # keep ca.key only if you intend to issue more certs
```

Expected output: `server.crt` and `ca.pem` in `docs/deployment/tls/`, and:

```sh
openssl x509 -in server.crt -noout -subject -ext subjectAltName -dates
```

showing `subject=CN=db`, `DNS:db`, and a `notAfter` a year out.

The gateway containers mount `ca.pem` at `/etc/greengateway/tls/ca.pem`; the database container mounts `server.crt` and `server.key`. `tls/` is a working directory for a local example — do not commit key material to the repository.

## Expiry is an outage you can schedule

A server certificate that expires takes every replica offline at once: they all fail the same verification against the same authority, and `/readyz` goes to `503` deployment-wide. This failure mode has no partial degradation and no automatic recovery.

```sh
openssl s_client -connect db.internal.example.com:5432 -starttls postgres </dev/null 2>/dev/null \
  | openssl x509 -noout -enddate
```

Alert on `notAfter` at 30 days, not at 7. Renewing the server certificate is a database-side operation: install the new certificate and reload the server (`SELECT pg_reload_conf();` for PostgreSQL, or the managed provider's equivalent). Existing gateway connections are unaffected; new connections pick it up. The gateway needs no restart and no configuration change unless the **CA** changed.

Rotating the **CA** does need a gateway change, and the order matters:

1. Add the new CA to `DATABASE_TLS_CA_FILE` **alongside** the old one — the file is a bundle, so concatenate them.
2. Roll the replicas so all of them trust both.
3. Switch the server to the certificate signed by the new CA.
4. Remove the old CA from the bundle and roll again.

Doing steps 3 and 1 in the other order takes the deployment down between them.

## When a step fails

**`certificate verify failed` / `unable to get local issuer certificate`.** The chain the server presents does not reach an anchor the gateway trusts. Run the `openssl s_client` command above with `-showcerts` and compare the issuer of the last certificate the server sent against what is in your bundle. The usual cause is a server sending only its leaf and omitting the intermediate.

**`hostname mismatch` / `NotValidForName`.** The DSN's host is not in the certificate's SANs. Either change the DSN to the name on the certificate or reissue the certificate for the name in the DSN. Do not reach for `loopback-dev`; it will be refused for a non-loopback target, and if it were not, you would have turned a verification failure into a silent plaintext connection.

**Startup refuses `DATABASE_TLS_MODE=loopback-dev`.** It is doing its job. That mode exists for a database on loopback or a Unix socket, in development and CI, and it is refused everywhere else so it cannot quietly become a production plaintext connection.

**`DATABASE_TLS_CA_FILE` refused at startup.** The file is group- or world-writable. `chmod 0444` and check the directory above it too.

**The server refuses to start with `private key file "server.key" has group or world access`.** `chmod 0600` and `chown` it to the server's uid. This is the database complaining, not the gateway.
