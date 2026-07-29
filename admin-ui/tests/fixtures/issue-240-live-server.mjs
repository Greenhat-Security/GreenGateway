import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateKeyPairSync,
  randomBytes,
  sign,
} from 'node:crypto';
import { spawn } from 'node:child_process';

const FIXTURE_HOST = '127.0.0.1';
const FIXTURE_PORT = 43201;
const GATEWAY_PORT = 43202;
const KEY_ID = 'issue-240-live-jwt';
const RUNTIME_PREFIX = 'greengateway-issue-240-live-';
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

const workspaceRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
);
const runtimeRoot = mkdtempSync(
  path.join(realpathSync(tmpdir()), RUNTIME_PREFIX),
);
const policyPath = path.join(runtimeRoot, 'policy.json');
const databasePath = path.join(runtimeRoot, 'connections.sqlite');
const masterKeyName = 'local-secret-primary.key';
const masterKeyPath = path.join(runtimeRoot, masterKeyName);

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const publicJwk = publicKey.export({ format: 'jwk' });
const jwks = {
  keys: [
    {
      ...publicJwk,
      alg: 'RS256',
      kid: KEY_ID,
      use: 'sig',
    },
  ],
};

const bearerTokens = {
  reader: signedToken('issue-240-reader', ['connections-reader']),
  writer: signedToken('issue-240-writer', ['connections-editor']),
  secretManager: signedToken('issue-240-secret-manager', [
    'connections-secret-manager',
  ]),
  superadmin: signedToken('issue-240-superadmin', [
    'connections-superadmin',
  ]),
};

const observed = {
  introspectionCalls: 0,
  introspectedSessions: [],
  upstreamCalls: 0,
  upstreamAuthorizationHeaders: 0,
  upstreamPaths: [],
};

prepareRuntimeFiles();

const fixtureServer = createServer(async (request, response) => {
  const requestUrl = new URL(
    request.url ?? '/',
    `http://${FIXTURE_HOST}:${FIXTURE_PORT}`,
  );

  if (request.method === 'GET' && requestUrl.pathname === '/health') {
    return json(response, 200, { ready: true });
  }
  if (request.method === 'GET' && requestUrl.pathname === '/jwks.json') {
    return json(response, 200, jwks);
  }
  if (
    request.method === 'GET' &&
    requestUrl.pathname === '/__fixture/tokens'
  ) {
    return json(response, 200, bearerTokens, {
      'Cache-Control': 'no-store',
    });
  }
  if (
    request.method === 'GET' &&
    requestUrl.pathname === '/__fixture/state'
  ) {
    return json(response, 200, observed, {
      'Cache-Control': 'no-store',
    });
  }
  if (request.method === 'POST' && requestUrl.pathname === '/introspect') {
    const body = await readJsonBody(request);
    const session = typeof body.session === 'string' ? body.session : '';
    observed.introspectionCalls += 1;
    observed.introspectedSessions.push(session);
    const roles = cookieRoles(session);
    if (roles === null) {
      return json(response, 401, { error: 'invalid_session' });
    }
    return json(response, 200, {
      user_id: `user-${session}`,
      email: `${session}@example.test`,
      roles,
    });
  }
  if (
    (request.method === 'GET' || request.method === 'HEAD') &&
    requestUrl.pathname === '/upstream/health'
  ) {
    observed.upstreamCalls += 1;
    observed.upstreamPaths.push(requestUrl.pathname);
    if (request.headers.authorization) {
      observed.upstreamAuthorizationHeaders += 1;
    }
    if (request.method === 'HEAD') {
      response.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json',
      });
      response.end();
      return;
    }
    return json(response, 200, { status: 'healthy' });
  }

  return json(response, 404, { error: 'not_found' });
});

let gatewayProcess;
let shuttingDown = false;
let gatewayOutputTail = '';

fixtureServer.on('error', (error) => {
  console.error(`[issue-240-fixture] local service failed: ${error.message}`);
  void shutdown(1);
});

fixtureServer.listen(FIXTURE_PORT, FIXTURE_HOST, async () => {
  try {
    await buildGateway();
    startGateway();
  } catch (error) {
    console.error(
      `[issue-240-fixture] gateway setup failed: ${safeError(error)}`,
    );
    await shutdown(1);
  }
});

process.on('SIGINT', () => {
  void shutdown(0);
});
process.on('SIGTERM', () => {
  void shutdown(0);
});
process.on('uncaughtException', (error) => {
  console.error(
    `[issue-240-fixture] uncaught failure: ${safeError(error)}`,
  );
  void shutdown(1);
});
process.on('unhandledRejection', (error) => {
  console.error(
    `[issue-240-fixture] unhandled failure: ${safeError(error)}`,
  );
  void shutdown(1);
});

function prepareRuntimeFiles() {
  chmodSync(runtimeRoot, 0o700);
  writeFileSync(masterKeyPath, randomBytes(32), { mode: 0o600 });
  chmodSync(masterKeyPath, 0o600);
  writeFileSync(
    policyPath,
    JSON.stringify(
      {
        schema_version: '0.1.0',
        id: 'issue-240-live-admin-policy',
        default_action: 'deny',
        enforcement_mode: 'enforce',
        roles: {
          'connections-reader': {
            permissions: ['admin:connections:read'],
          },
          'connections-editor': {
            permissions: [
              'admin:connections:read',
              'admin:connections:write',
              'admin:connections:test',
            ],
          },
          'connections-secret-manager': {
            permissions: [
              'admin:connections:read',
              'admin:connections:secrets:write',
            ],
          },
          'connections-superadmin': {
            permissions: ['*'],
          },
        },
        routes: [
          {
            methods: ['GET', 'POST', 'PUT', 'DELETE'],
            path_prefix: '/v1/admin/connections',
            permission: 'admin:connections:read',
          },
          {
            methods: ['GET', 'POST', 'PUT', 'DELETE'],
            path_prefix: '/v1/admin/connection-secrets',
            permission: 'admin:connections:read',
          },
        ],
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  chmodSync(policyPath, 0o600);
}

async function buildGateway() {
  const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  await runCommand(
    cargo,
    [
      'build',
      '--manifest-path',
      path.join(workspaceRoot, 'Cargo.toml'),
      '-p',
      'gateway',
    ],
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
    console.error(
      `[issue-240-fixture] gateway process failed: ${error.message}`,
    );
    void shutdown(1);
  });
  gatewayProcess.on('exit', (code, signalName) => {
    if (shuttingDown) {
      return;
    }
    console.error(
      `[issue-240-fixture] gateway exited early (${code ?? signalName ?? 'unknown'}). ${gatewayOutputTail}`,
    );
    void shutdown(1);
  });
}

function gatewayEnvironment() {
  const environment = {};
  for (const name of [
    'PATH',
    'Path',
    'PATHEXT',
    'SYSTEMROOT',
    'SystemRoot',
    'WINDIR',
    'TEMP',
    'TMP',
    'TMPDIR',
    'HOME',
    'USERPROFILE',
  ]) {
    if (process.env[name] !== undefined) {
      environment[name] = process.env[name];
    }
  }

  return {
    ...environment,
    LISTEN_ADDR: `${FIXTURE_HOST}:${GATEWAY_PORT}`,
    CONNECTIONS_SQLITE_PATH: databasePath,
    CONNECTION_SECRETS_ROOT: runtimeRoot,
    CONNECTION_LOCAL_SECRET_KEYRING: JSON.stringify([
      {
        id: 'issue-240-primary',
        file: masterKeyName,
        role: 'primary',
      },
    ]),
    POLICY_FILE: policyPath,
    AUTH_ENABLED: 'true',
    AUTH_MODE: 'required',
    AUTH_COOKIE_NAME: 'session',
    AUTH_PROVIDERS: JSON.stringify([
      {
        name: 'issue-240-jwt',
        type: 'jwt',
        jwks_url: `http://${FIXTURE_HOST}:${FIXTURE_PORT}/jwks.json`,
        roles_claim: 'roles',
        require_jti: false,
      },
      {
        name: 'issue-240-cookie',
        type: 'cookie_session',
        introspection_url: `http://${FIXTURE_HOST}:${FIXTURE_PORT}/introspect`,
        introspection_timeout_ms: 2_000,
        cache_ttl_ms: 100,
        user_id_claim: 'user_id',
        email_claim: 'email',
        roles_claim: 'roles',
      },
    ]),
    CSRF_ENABLED: 'true',
    CSRF_COOKIE_NAME: 'csrf_token',
    CSRF_HEADER_NAME: 'x-csrf-token',
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
    const child = spawn(command, arguments_, {
      cwd,
      env: process.env,
      stdio: 'inherit',
      windowsHide: true,
    });
    child.on('error', reject);
    child.on('exit', (code, signalName) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `${command} exited with ${code ?? signalName ?? 'unknown status'}`,
        ),
      );
    });
  });
}

function signedToken(subject, roles) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(
    JSON.stringify({ alg: 'RS256', kid: KEY_ID, typ: 'JWT' }),
  );
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
  const signature = sign(
    'RSA-SHA256',
    Buffer.from(signingInput),
    privateKey,
  ).toString('base64url');
  return `${signingInput}.${signature}`;
}

function base64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function cookieRoles(session) {
  switch (session) {
    case 'cookie-superadmin':
      return ['connections-superadmin'];
    case 'cookie-reader':
      return ['connections-reader'];
    default:
      return null;
  }
}

async function readJsonBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BODY_BYTES) {
      throw new Error('fixture request body exceeded the safe test limit');
    }
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString('utf8');
  return body.length === 0 ? {} : JSON.parse(body);
}

function json(response, status, body, headers = {}) {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(encoded),
    'Content-Type': 'application/json',
    ...headers,
  });
  response.end(encoded);
}

function rememberGatewayOutput(chunk) {
  gatewayOutputTail = `${gatewayOutputTail}${chunk.toString('utf8')}`.slice(
    -8_192,
  );
}

async function shutdown(exitCode) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;

  if (gatewayProcess && gatewayProcess.exitCode === null) {
    gatewayProcess.kill();
    await Promise.race([
      new Promise((resolve) => gatewayProcess.once('exit', resolve)),
      new Promise((resolve) => setTimeout(resolve, 1_000)),
    ]);
    if (gatewayProcess.exitCode === null) {
      gatewayProcess.kill('SIGKILL');
    }
  }

  await new Promise((resolve) => fixtureServer.close(resolve));
  cleanupRuntimeRoot();
  process.exit(exitCode);
}

function cleanupRuntimeRoot() {
  const canonicalTemp = realpathSync(tmpdir());
  const resolvedRoot = path.resolve(runtimeRoot);
  if (
    path.dirname(resolvedRoot) === canonicalTemp &&
    path.basename(resolvedRoot).startsWith(RUNTIME_PREFIX)
  ) {
    rmSync(resolvedRoot, { force: true, recursive: true });
  }
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}
