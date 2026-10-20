// A disposable OIDC provider in front of a real HTTPS gateway with
// ADMIN_SESSION_MODE=standalone_memory, for the live admin-session browser
// test. Every key, certificate, client secret, code and token is generated
// for this run and deleted on exit.
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
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
} from 'node:crypto';
import { spawn } from 'node:child_process';

const HOST = '127.0.0.1';
const IDP_PORT = 43211;
const GATEWAY_PORT = 43212;
const ISSUER = `http://${HOST}:${IDP_PORT}`;
const GATEWAY_ORIGIN = `https://${HOST}:${GATEWAY_PORT}`;
const REDIRECT_URI = `${GATEWAY_ORIGIN}/v1/admin/auth/callback`;
const CLIENT_ID = 'greengateway-admin-session-live';
const PROVIDER_NAME = 'admin-session-live';
const KEY_ID = 'admin-session-live-signing';
const OPERATOR_ROLE = 'admin-session-operator';
const RUNTIME_PREFIX = 'greengateway-admin-session-live-';
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const PENDING_CODE_TTL_MS = 60_000;

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
const certificatePath = path.join(runtimeRoot, 'gateway-cert.pem');
const certificateKeyPath = path.join(runtimeRoot, 'gateway-key.pem');
const opensslConfigPath = path.join(runtimeRoot, 'openssl.cnf');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const jwks = {
  keys: [
    {
      ...publicKey.export({ format: 'jwk' }),
      alg: 'RS256',
      kid: KEY_ID,
      use: 'sig',
    },
  ],
};
const clientSecret = randomBytes(32).toString('hex');
const pendingCodes = new Map();

const observed = {
  authorizations: 0,
  tokenExchanges: 0,
  rejectedRequests: 0,
  accessTokens: [],
};

const providerServer = createServer(async (request, response) => {
  try {
    await handleProviderRequest(request, response);
  } catch (error) {
    observed.rejectedRequests += 1;
    console.error(
      `[admin-session-fixture] provider request failed: ${safeError(error)}`,
    );
    if (!response.headersSent) {
      json(response, 400, { error: 'invalid_request' });
    }
  }
});

let gatewayProcess;
let shuttingDown = false;
let gatewayOutputTail = '';

providerServer.on('error', (error) => {
  console.error(
    `[admin-session-fixture] provider failed: ${error.message}`,
  );
  void shutdown(1);
});

prepareRuntimeFiles()
  .then(() => new Promise((resolve) => {
    // The gateway reads OIDC discovery at startup, so the provider must be up.
    providerServer.listen(IDP_PORT, HOST, resolve);
  }))
  .then(buildGateway)
  .then(startGateway)
  .catch(async (error) => {
    console.error(
      `[admin-session-fixture] setup failed: ${safeError(error)}`,
    );
    await shutdown(1);
  });

process.on('SIGINT', () => {
  void shutdown(0);
});
process.on('SIGTERM', () => {
  void shutdown(0);
});
process.on('uncaughtException', (error) => {
  console.error(
    `[admin-session-fixture] uncaught failure: ${safeError(error)}`,
  );
  void shutdown(1);
});
process.on('unhandledRejection', (error) => {
  console.error(
    `[admin-session-fixture] unhandled failure: ${safeError(error)}`,
  );
  void shutdown(1);
});

async function handleProviderRequest(request, response) {
  const url = new URL(request.url ?? '/', ISSUER);

  if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    return json(response, 200, {
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/jwks.json`,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
    });
  }
  if (request.method === 'GET' && url.pathname === '/jwks.json') {
    return json(response, 200, jwks);
  }
  if (request.method === 'GET' && url.pathname === '/authorize') {
    return authorize(url, response);
  }
  if (request.method === 'POST' && url.pathname === '/token') {
    return exchangeCode(await readBody(request), response);
  }
  if (request.method === 'GET' && url.pathname === '/__fixture/state') {
    return json(response, 200, observed);
  }
  return json(response, 404, { error: 'not_found' });
}

/** Signs the operator in without a login form and returns to the gateway. */
function authorize(url, response) {
  const params = url.searchParams;
  const state = params.get('state');
  const nonce = params.get('nonce');
  const codeChallenge = params.get('code_challenge');
  if (
    params.get('response_type') !== 'code' ||
    params.get('client_id') !== CLIENT_ID ||
    params.get('redirect_uri') !== REDIRECT_URI ||
    params.get('code_challenge_method') !== 'S256' ||
    !params.get('scope')?.split(' ').includes('openid') ||
    !state || !nonce || !codeChallenge
  ) {
    observed.rejectedRequests += 1;
    return json(response, 400, { error: 'invalid_request' });
  }
  const code = randomBytes(32).toString('base64url');
  pendingCodes.set(code, {
    nonce,
    codeChallenge,
    expiresAt: Date.now() + PENDING_CODE_TTL_MS,
  });
  observed.authorizations += 1;
  const location = new URL(REDIRECT_URI);
  location.searchParams.set('code', code);
  location.searchParams.set('state', state);
  response.writeHead(302, {
    'Cache-Control': 'no-store',
    Location: location.toString(),
  });
  response.end();
}

/** One use per code, with client authentication and the PKCE verifier. */
function exchangeCode(body, response) {
  const params = new URLSearchParams(body);
  const code = params.get('code') ?? '';
  const pending = pendingCodes.get(code);
  pendingCodes.delete(code);
  const verifier = params.get('code_verifier') ?? '';
  if (
    !pending ||
    pending.expiresAt < Date.now() ||
    params.get('grant_type') !== 'authorization_code' ||
    params.get('client_id') !== CLIENT_ID ||
    !sameSecret(params.get('client_secret') ?? '', clientSecret) ||
    params.get('redirect_uri') !== REDIRECT_URI ||
    createHash('sha256').update(verifier).digest('base64url') !== pending.codeChallenge
  ) {
    observed.rejectedRequests += 1;
    return json(response, 400, { error: 'invalid_grant' });
  }
  const now = Math.floor(Date.now() / 1000);
  const accessToken = signedToken({
    iss: ISSUER,
    sub: 'admin-session-operator',
    email: 'admin-session-operator@example.test',
    roles: [OPERATOR_ROLE],
    iat: now,
    exp: now + 600,
  });
  const idToken = signedToken({
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: 'admin-session-operator',
    nonce: pending.nonce,
    iat: now,
    exp: now + 600,
  });
  observed.tokenExchanges += 1;
  observed.accessTokens.push(accessToken);
  return json(response, 200, {
    access_token: accessToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: 600,
  });
}

function sameSecret(candidate, expected) {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function prepareRuntimeFiles() {
  chmodSync(runtimeRoot, 0o700);
  writeFileSync(
    policyPath,
    JSON.stringify({
      schema_version: '0.1.0',
      id: 'admin-session-live-policy',
      default_action: 'deny',
      enforcement_mode: 'enforce',
      roles: {
        [OPERATOR_ROLE]: { permissions: ['admin:traffic:read'] },
      },
      routes: [
        { methods: ['GET'], path_prefix: '/v1/admin/traffic', permission: 'admin:traffic:read' },
      ],
    }, null, 2),
    { mode: 0o600 },
  );
  // A leaf for 127.0.0.1 only. The browser is told to accept it; the gateway
  // requires HTTPS for the redirect URI and serves the Secure __Host- cookie.
  writeFileSync(
    opensslConfigPath,
    [
      '[req]',
      'distinguished_name = subject',
      'x509_extensions = leaf',
      'prompt = no',
      '[subject]',
      `CN = ${HOST}`,
      '[leaf]',
      'basicConstraints = critical,CA:FALSE',
      'keyUsage = critical,digitalSignature',
      'extendedKeyUsage = serverAuth',
      `subjectAltName = IP:${HOST}`,
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  await runCommand('openssl', [
    'req', '-x509', '-config', opensslConfigPath,
    '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-days', '1', '-keyout', certificateKeyPath, '-out', certificatePath,
  ], runtimeRoot, 'pipe');
  chmodSync(certificateKeyPath, 0o600);
  chmodSync(certificatePath, 0o644);
}

async function buildGateway() {
  const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  await runCommand(
    cargo,
    ['build', '--manifest-path', path.join(workspaceRoot, 'Cargo.toml'), '-p', 'gateway'],
    workspaceRoot,
    'inherit',
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
    cwd: runtimeRoot,
    env: gatewayEnvironment(),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  gatewayProcess.stdout.on('data', rememberGatewayOutput);
  gatewayProcess.stderr.on('data', rememberGatewayOutput);
  gatewayProcess.on('error', (error) => {
    console.error(
      `[admin-session-fixture] gateway process failed: ${error.message}`,
    );
    void shutdown(1);
  });
  gatewayProcess.on('exit', (code, signalName) => {
    if (shuttingDown) {
      return;
    }
    console.error(
      `[admin-session-fixture] gateway exited early (${code ?? signalName ?? 'unknown'}). ${gatewayOutputTail}`,
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
    LISTEN_ADDR: `${HOST}:${GATEWAY_PORT}`,
    TLS_CERT_FILE: certificatePath,
    TLS_KEY_FILE: certificateKeyPath,
    POLICY_FILE: policyPath,
    AUTH_ENABLED: 'true',
    AUTH_MODE: 'required',
    AUTH_PROVIDERS: JSON.stringify([
      {
        name: PROVIDER_NAME,
        type: 'jwt',
        issuer: ISSUER,
        roles_claim: 'roles',
        require_jti: false,
        client_id: CLIENT_ID,
        client_secret: clientSecret,
        redirect_uri: REDIRECT_URI,
      },
    ]),
    ADMIN_LOGIN_PROVIDER: PROVIDER_NAME,
    ADMIN_SESSION_MODE: 'standalone_memory',
    CSRF_ENABLED: 'true',
    EGRESS_ALLOWED_HOSTS: HOST,
    EGRESS_DENY_PRIVATE_IPS: 'false',
    SHUTDOWN_DRAIN_DELAY_MS: '0',
    SHUTDOWN_TIMEOUT_MS: '1000',
    AUDIT_DRAIN_TIMEOUT_MS: '1000',
    RUST_LOG: 'warn',
  };
}

function runCommand(command, arguments_, cwd, stdio) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      cwd,
      env: process.env,
      stdio: ['ignore', stdio, stdio],
      windowsHide: true,
    });
    let output = '';
    child.stdout?.on('data', (chunk) => { output = `${output}${chunk}`.slice(-4_096); });
    child.stderr?.on('data', (chunk) => { output = `${output}${chunk}`.slice(-4_096); });
    child.on('error', reject);
    child.on('exit', (code, signalName) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `${command} exited with ${code ?? signalName ?? 'unknown status'}. ${output}`,
        ),
      );
    });
  });
}

function signedToken(claims) {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', kid: KEY_ID, typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const signature = sign(
    'RSA-SHA256',
    Buffer.from(signingInput),
    privateKey,
  ).toString('base64url');
  return `${signingInput}.${signature}`;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BODY_BYTES) {
      throw new Error('fixture request body exceeded the safe test limit');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
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

  await new Promise((resolve) => providerServer.close(resolve));
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
