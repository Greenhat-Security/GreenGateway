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
