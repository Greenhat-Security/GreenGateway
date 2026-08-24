# GreenGateway Admin UI

This is the Vite + React + TypeScript admin UI scaffold. It is built as a separate npm project and embedded into the Rust gateway binary for production serving at the configured admin prefix, which defaults to `/admin`.

## Development

Run the Rust backend and Vite dev server side by side:

```sh
cargo run
```

```sh
cd admin-ui
npm ci
npm run dev
```

Open the Vite URL at `http://127.0.0.1:5173/admin/`. The Vite dev server proxies the default `/v1/admin` API calls to `http://127.0.0.1:8080`.

To point the dev proxy at another backend:

```sh
GREENGATEWAY_BACKEND_URL=http://127.0.0.1:9090 npm run dev
```

Production builds are produced by:

```sh
npm run build
```

The gateway Cargo build script also runs `npm ci` and `npm run build` so `cargo build --workspace` can produce a binary with embedded admin assets from a fresh checkout.

## Connections, Inventory, and Playground

The embedded UI includes the managed Connections inventory/editor, unified
capability inventory, and constrained tool playground. These surfaces are
redacted clients of the same authenticated, permission-checked admin APIs used
in production; they do not reveal stored secret values or provide arbitrary
upstream request controls.

For operator workflows and security boundaries, see:

- [Connections admin guide](../docs/connections/admin-guide.md)
- [Connections operator guide](../docs/connections/operator-guide.md)
- [Connections migration and rollback](../docs/connections/migration.md)
- [Configuration reference](../docs/configuration.md)

Local UI development still needs a running gateway with a configured
`POLICY_FILE` and the relevant `admin:connections:*` / `admin:tools:*`
permissions. Leaving `CONNECTIONS_SQLITE_PATH` unset is a valid read-only test
state: legacy projections may be visible, while managed Connection and local
secret mutations remain unavailable.
