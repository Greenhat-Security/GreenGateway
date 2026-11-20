// A real standalone gateway for the Policy Studio live-backend spec
// (tests/policy-studio-live.spec.ts): its embedded admin UI and admin API on
// one origin, bearer JWTs from a disposable JWKS, a policy with a shadow rule
// and a shadowed deny the analyzer proves, a local upstream for retained
// traffic, a SQLite audit store replay reads, the default policy history
// (drafts, the stored suite, replay jobs) and POLICY_TESTS_REQUIRED=true.
// Everything is generated for the run under a temporary directory and
// deleted on exit. Values are low-entropy fakes.
import {
  chmodSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { spawn } from 'node:child_process';

const FIXTURE_HOST = '127.0.0.1';
const FIXTURE_PORT = 43221;
const GATEWAY_PORT = 43222;
const KEY_ID = 'policy-studio-live-jwt';
const RUNTIME_PREFIX = 'greengateway-policy-studio-live-';
const STARTED_AT = new Date().toISOString();

const workspaceRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
);
const runtimeRoot = mkdtempSync(path.join(realpathSync(tmpdir()), RUNTIME_PREFIX));
const policyPath = path.join(runtimeRoot, 'policy.json');
const masterKeyName = 'local-secret-primary.key';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = {
  keys: [{ ...publicKey.export({ format: 'jwk' }), alg: 'RS256', kid: KEY_ID, use: 'sig' }],
};

const bearerTokens = {
  operator: signedToken('studio-operator', ['studio-operator']),
  reader: signedToken('studio-reader', ['studio-reader']),
};

const observed = { startedAt: STARTED_AT, upstreamCalls: 0 };

// Routes for the policy admin API, as dev/policy.json has them: every unsafe
// method under /v1/admin/policy needs admin:policy:write unless a more
// specific route comes first.
const POLICY_ADMIN_ROUTES = [
  { methods: ['GET'], path_prefix: '/v1/admin/audit', permission: 'admin:audit:read' },
  { methods: ['GET'], path_prefix: '/v1/admin/policy', permission: 'admin:policy:read' },
  { methods: ['POST'], path_prefix: '/v1/admin/policy/validate', permission: 'admin:policy:read' },
  { methods: ['POST'], path_prefix: '/v1/admin/policy/tests/runs', permission: 'admin:policy:simulate' },
  { methods: ['POST'], path_prefix: '/v1/admin/policy/simulations', permission: 'admin:policy:simulate' },
  { methods: ['POST', 'DELETE'], path_prefix: '/v1/admin/policy/replays', permission: 'admin:policy:simulate' },
  { methods: ['POST', 'DELETE'], path_prefix: '/v1/admin/policy/analyses/suppressions', permission: 'admin:policy:write' },
  { methods: ['POST'], path_prefix: '/v1/admin/policy/analyses', permission: 'admin:policy:analyze' },
  { methods: ['PUT', 'POST', 'PATCH', 'DELETE'], path_prefix: '/v1/admin/policy', permission: 'admin:policy:write' },
];

prepareRuntimeFiles();

const fixtureServer = createServer((request, response) => {
  const requestUrl = new URL(request.url ?? '/', `http://${FIXTURE_HOST}:${FIXTURE_PORT}`);
  if (request.method === 'GET' && requestUrl.pathname === '/jwks.json') {
    return json(response, 200, jwks);
  }
  if (request.method === 'GET' && requestUrl.pathname === '/__fixture/tokens') {
    return json(response, 200, bearerTokens);
  }
  if (request.method === 'GET' && requestUrl.pathname === '/__fixture/state') {
    return json(response, 200, observed);
  }
  if (request.method === 'GET' && requestUrl.pathname.startsWith('/upstream/')) {
    observed.upstreamCalls += 1;
    return json(response, 200, { status: 'ok' });
  }
  return json(response, 404, { error: 'not_found' });
});

let gatewayProcess;
let shuttingDown = false;
let gatewayOutputTail = '';

fixtureServer.on('error', (error) => {
  console.error(`[policy-studio-fixture] local service failed: ${error.message}`);
  void shutdown(1);
});

fixtureServer.listen(FIXTURE_PORT, FIXTURE_HOST, async () => {
  try {
    await buildGateway();
    startGateway();
  } catch (error) {
    console.error(`[policy-studio-fixture] gateway setup failed: ${safeError(error)}`);
    await shutdown(1);
  }
});

process.on('SIGINT', () => void shutdown(0));
process.on('SIGTERM', () => void shutdown(0));
process.on('uncaughtException', (error) => {
  console.error(`[policy-studio-fixture] uncaught failure: ${safeError(error)}`);
  void shutdown(1);
});
process.on('unhandledRejection', (error) => {
  console.error(`[policy-studio-fixture] unhandled failure: ${safeError(error)}`);
  void shutdown(1);
});

function prepareRuntimeFiles() {
  chmodSync(runtimeRoot, 0o700);
  writeFileSync(path.join(runtimeRoot, masterKeyName), randomBytes(32), { mode: 0o600 });
  writeFileSync(
    policyPath,
    JSON.stringify(
      {
        schema_version: '0.1.0',
        id: 'policy-studio-live',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {
          'studio-operator': {
            permissions: [
              'admin:policy:read',
              'admin:policy:write',
              'admin:policy:simulate',
              'admin:policy:analyze',
              'admin:audit:read',
            ],
          },
          'studio-reader': { permissions: ['admin:policy:read'] },
        },
        rules: [
          // Observed, never enforced: a would-deny that still forwards.
          { id: 'upstream-watched', methods: ['GET'], path: '/upstream/watched', action: 'shadow' },
          { id: 'upstream-open', methods: ['GET'], path: '/upstream/**', action: 'allow' },
          // Never decides: the allow above matches first. The analyzer proves
          // it shadowed and proposes moving it before that allow.
          { id: 'upstream-secret-blocked', methods: ['GET'], path: '/upstream/secret', action: 'deny' },
        ],
        routes: POLICY_ADMIN_ROUTES,
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
}

async function buildGateway() {
  const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  await runCommand(
    cargo,
    ['build', '--manifest-path', path.join(workspaceRoot, 'Cargo.toml'), '-p', 'gateway'],
    workspaceRoot,
  );
}

function startGateway() {
  const configuredTarget = process.env.CARGO_TARGET_DIR;
  const targetRoot = configuredTarget
    ? path.resolve(workspaceRoot, configuredTarget)
    : path.join(workspaceRoot, 'target');
  const executable = path.join(
    targetRoot,
    'debug',
    process.platform === 'win32' ? 'gateway.exe' : 'gateway',
  );
  gatewayProcess = spawn(executable, [], {
    cwd: workspaceRoot,
    env: gatewayEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  gatewayProcess.stdout.on('data', rememberGatewayOutput);
  gatewayProcess.stderr.on('data', rememberGatewayOutput);
  gatewayProcess.on('error', (error) => {
    console.error(`[policy-studio-fixture] gateway process failed: ${error.message}`);
    void shutdown(1);
  });
  gatewayProcess.on('exit', (code, signalName) => {
    if (shuttingDown) return;
    console.error(
      `[policy-studio-fixture] gateway exited early (${code ?? signalName ?? 'unknown'}). ${gatewayOutputTail}`,
    );
    void shutdown(1);
  });
}

function gatewayEnvironment() {
  const environment = {};
  for (const name of ['PATH', 'Path', 'PATHEXT', 'SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE']) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  return {
    ...environment,
    LISTEN_ADDR: `${FIXTURE_HOST}:${GATEWAY_PORT}`,
    CONNECTIONS_SQLITE_PATH: path.join(runtimeRoot, 'connections.sqlite'),
    PRINCIPAL_SQLITE_PATH: path.join(runtimeRoot, 'principals.sqlite'),
    SERVICE_TOKEN_SQLITE_PATH: path.join(runtimeRoot, 'tokens.sqlite'),
    // The audit store of record, which replay jobs read.
    AUDIT_SQLITE_PATH: path.join(runtimeRoot, 'audit.sqlite'),
    CONNECTION_SECRETS_ROOT: runtimeRoot,
    CONNECTION_LOCAL_SECRET_KEYRING: JSON.stringify([
      { id: 'policy-studio-primary', file: masterKeyName, role: 'primary' },
    ]),
    // Drafts, the stored suite and replay jobs live in the default
    // <POLICY_FILE>.history.sqlite beside it.
    POLICY_FILE: policyPath,
    POLICY_TESTS_REQUIRED: 'true',
    AUTH_ENABLED: 'true',
    AUTH_MODE: 'required',
    AUTH_PROVIDERS: JSON.stringify([
      {
        name: 'policy-studio-jwt',
        type: 'jwt',
        jwks_url: `http://${FIXTURE_HOST}:${FIXTURE_PORT}/jwks.json`,
        roles_claim: 'roles',
        require_jti: false,
      },
    ]),
    CSRF_ENABLED: 'true',
    UPSTREAM_URL: `http://${FIXTURE_HOST}:${FIXTURE_PORT}`,
    EGRESS_ALLOWED_HOSTS: FIXTURE_HOST,
    EGRESS_DENY_PRIVATE_IPS: 'false',
    SHUTDOWN_DRAIN_DELAY_MS: '0',
    SHUTDOWN_TIMEOUT_MS: '1000',
    AUDIT_DRAIN_TIMEOUT_MS: '1000',
    RUST_LOG: 'warn',
  };
}

function runCommand(command, arguments_, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, { cwd, env: process.env, stdio: 'inherit', windowsHide: true });
    child.on('error', reject);
    child.on('exit', (code, signalName) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} exited with ${code ?? signalName ?? 'unknown status'}`));
    });
  });
}

function signedToken(subject, roles) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: 'RS256', kid: KEY_ID, typ: 'JWT' }));
  const payload = base64Url(
    JSON.stringify({
      sub: subject,
      email: `${subject}@example.test`,
      roles,
      iat: now,
      exp: now + 3_600,
      jti: `${subject}-${now}`,
    }),
  );
  const signingInput = `${header}.${payload}`;
  const signature = sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function json(response, status, body) {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(encoded),
    'Content-Type': 'application/json',
  });
  response.end(encoded);
}

function rememberGatewayOutput(chunk) {
  gatewayOutputTail = `${gatewayOutputTail}${chunk.toString('utf8')}`.slice(-8_192);
}

async function shutdown(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  if (gatewayProcess && gatewayProcess.exitCode === null) {
    gatewayProcess.kill();
    await Promise.race([
      new Promise((resolve) => gatewayProcess.once('exit', resolve)),
      new Promise((resolve) => setTimeout(resolve, 1_000)),
    ]);
    if (gatewayProcess.exitCode === null) gatewayProcess.kill('SIGKILL');
  }
  await new Promise((resolve) => fixtureServer.close(resolve));
  const canonicalTemp = realpathSync(tmpdir());
  const resolvedRoot = path.resolve(runtimeRoot);
  if (
    path.dirname(resolvedRoot) === canonicalTemp &&
    path.basename(resolvedRoot).startsWith(RUNTIME_PREFIX)
  ) {
    rmSync(resolvedRoot, { force: true, recursive: true });
  }
  process.exit(exitCode);
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}
