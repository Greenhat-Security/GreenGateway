// A disposable OIDC provider in front of three real HTTPS gateways with
// ADMIN_SESSION_MODE=standalone_memory, for the live admin-session browser
// tests. Every key, certificate, client secret, code and token is generated
// for this run and deleted on exit; nothing here is a committed credential.
//
// - standard: one HTTPS listener, the default admin prefix and CSRF names.
// - split: a plain-HTTP data listener and an HTTPS management listener with a
//   custom admin prefix and CSRF names. Its configured public origin
//   (https://localhost:43214) is not its listen address (127.0.0.1:43214).
// - expiring: the standard layout with a five-second session deadline.
//
// The gateways' TLS leaf is issued by a throwaway CA created for the run. The
// fixture's own requests verify it, and GET /__fixture/ca.pem hands the CA
// certificate (public material only) to the spec so its requests do too.
import {
  chmodSync,
  createWriteStream,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { isIP } from 'node:net';
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
const ISSUER = `http://${HOST}:${IDP_PORT}`;
// The browser reaches the authorization endpoint under its own host name,
// mapped to 127.0.0.1 by the spec's Chromium launch arguments. Cookies are
// scoped by host, not port, so serving it from 127.0.0.1 would hand it every
// gateway cookie there; a separate host is what a production IdP has. The
// gateways only use the issuer, token and JWKS URLs, which stay on 127.0.0.1.
const IDP_BROWSER_AUTHORITY = `idp.admin-session-live.test:${IDP_PORT}`;
const PROVIDER_NAME = 'admin-session-live';
const KEY_ID = 'admin-session-live-signing';
const OPERATOR_SUBJECT = 'admin-session-operator';
// The operator holds both roles, so it may delegate the narrower one to a
// service token it creates through the admin UI.
const OPERATOR_ROLE = 'admin-session-operator';
const DELEGATED_ROLE = 'admin-session-reader';
const RUNTIME_PREFIX = 'greengateway-admin-session-live-';
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const PENDING_CODE_TTL_MS = 60_000;
const ACCESS_TOKEN_TTL_SECONDS = 600;
// The gateway accepts a JWT until exp plus this leeway (JWT_EXP_LEEWAY_SECS in
// gateway/src/auth/jwt.rs). A short-lived token is minted with exp already in
// the past by less than the leeway, so it stays valid for only a few seconds.
const GATEWAY_JWT_EXP_LEEWAY_SECONDS = 60;
const SHORT_ACCESS_TOKEN_SECONDS = 4;
const GATEWAY_READY_TIMEOUT_MS = 240_000;
const GATEWAY_OUTPUT_TAIL_BYTES = 8_192;

const GATEWAYS = [
  {
    name: 'standard',
    clientId: 'greengateway-admin-session-live',
    prefix: '/admin',
    origin: `https://${HOST}:43212`,
    readyUrls: [`https://${HOST}:43212/readyz`],
    environment: (tls) => ({
      LISTEN_ADDR: `${HOST}:43212`,
      TLS_CERT_FILE: tls.certificate,
      TLS_KEY_FILE: tls.key,
    }),
  },
  {
    name: 'split',
    clientId: 'greengateway-admin-session-split',
    prefix: '/ops-console',
    origin: 'https://localhost:43214',
    readyUrls: [
      `http://${HOST}:43213/readyz`,
      'https://localhost:43214/v1/ops-console/auth/config',
    ],
    environment: (tls) => ({
      LISTEN_ADDR: `${HOST}:43213`,
      ADMIN_LISTEN_ADDR: `${HOST}:43214`,
      ADMIN_TLS_CERT_FILE: tls.certificate,
      ADMIN_TLS_KEY_FILE: tls.key,
      ADMIN_PREFIX: '/ops-console',
      CSRF_COOKIE_NAME: '__Host-ggw-ops-csrf',
      CSRF_HEADER_NAME: 'x-ggw-ops-csrf',
    }),
  },
  {
    name: 'expiring',
    clientId: 'greengateway-admin-session-expiring',
    prefix: '/admin',
    origin: `https://${HOST}:43215`,
    readyUrls: [`https://${HOST}:43215/readyz`],
    environment: (tls) => ({
      LISTEN_ADDR: `${HOST}:43215`,
      TLS_CERT_FILE: tls.certificate,
      TLS_KEY_FILE: tls.key,
      ADMIN_SESSION_TTL_SECS: '5',
    }),
  },
].map((gateway) => ({
  ...gateway,
  clientSecret: randomBytes(32).toString('hex'),
  redirectUri: `${gateway.origin}/v1${gateway.prefix}/auth/callback`,
  process: undefined,
  outputTail: '',
}));

const workspaceRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
);
const runtimeRoot = mkdtempSync(
  path.join(realpathSync(tmpdir()), RUNTIME_PREFIX),
);
const tls = {
  caCertificate: path.join(runtimeRoot, 'ca-cert.pem'),
  caKey: path.join(runtimeRoot, 'ca-key.pem'),
  caConfig: path.join(runtimeRoot, 'ca.cnf'),
  certificate: path.join(runtimeRoot, 'gateway-cert.pem'),
  key: path.join(runtimeRoot, 'gateway-key.pem'),
  request: path.join(runtimeRoot, 'gateway.csr'),
  leafConfig: path.join(runtimeRoot, 'leaf.cnf'),
};
let caCertificatePem = '';

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
const clients = new Map(GATEWAYS.map((gateway) => [gateway.clientId, gateway]));
const pendingCodes = new Map();
// Gateway names whose next token exchange mints a short-lived access token.
const shortAccessTokensRequested = new Set();
let gatewaysReady = false;

const observed = {
  authorizations: 0,
  tokenExchanges: 0,
  rejectedRequests: 0,
  accessTokens: [],
  // Names of any cookies a browser or gateway sent to the provider. Gateway
  // cookies are host-only on other hosts, so this must stay empty.
  cookieNames: [],
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

let shuttingDown = false;

providerServer.on('error', (error) => {
  console.error(
    `[admin-session-fixture] provider failed: ${error.message}`,
  );
  void shutdown(1);
});

prepareRuntimeFiles()
  .then(() => new Promise((resolve) => {
    // The gateways read OIDC discovery at startup, so the provider must be up.
    providerServer.listen(IDP_PORT, HOST, resolve);
  }))
  .then(buildGateway)
  .then(startGateways)
  .then(waitForGateways)
  .then(() => {
    gatewaysReady = true;
  })
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
  rememberCookieNames(request.headers.cookie);

  if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    return json(response, 200, {
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/jwks.json`,
      authorization_endpoint: `http://${IDP_BROWSER_AUTHORITY}/authorize`,
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
    if (request.headers.host !== IDP_BROWSER_AUTHORITY) {
      observed.rejectedRequests += 1;
      return json(response, 400, { error: 'invalid_request' });
    }
    return authorize(url, response);
  }
  if (request.method === 'POST' && url.pathname === '/token') {
    return exchangeCode(await readBody(request), response);
  }
  if (request.method === 'GET' && url.pathname === '/__fixture/ready') {
    return json(response, gatewaysReady ? 200 : 503, { ready: gatewaysReady });
  }
  if (request.method === 'GET' && url.pathname === '/__fixture/ca.pem') {
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/x-pem-file',
    });
    response.end(caCertificatePem);
    return undefined;
  }
  if (request.method === 'GET' && url.pathname === '/__fixture/state') {
    return json(response, 200, {
      ...observed,
      artifacts: Object.fromEntries(
        GATEWAYS.map((gateway) => [gateway.name, gatewayFiles(gateway)]),
      ),
    });
  }
  if (request.method === 'POST' && url.pathname === '/__fixture/short-access-token') {
    // One use: the next token exchange by this gateway's client is short-lived.
    const gateway = GATEWAYS.find((candidate) => candidate.name === url.searchParams.get('gateway'));
    if (!gateway) {
      return json(response, 404, { error: 'unknown_gateway' });
    }
    shortAccessTokensRequested.add(gateway.name);
    return json(response, 200, { remaining_seconds: SHORT_ACCESS_TOKEN_SECONDS });
  }
  return json(response, 404, { error: 'not_found' });
}

/** Signs the operator in without a login form and returns to the gateway. */
function authorize(url, response) {
  const params = url.searchParams;
  const client = clients.get(params.get('client_id') ?? '');
  const state = params.get('state');
  const nonce = params.get('nonce');
  const codeChallenge = params.get('code_challenge');
  if (
    !client ||
    params.get('response_type') !== 'code' ||
    params.get('redirect_uri') !== client.redirectUri ||
    params.get('code_challenge_method') !== 'S256' ||
    !params.get('scope')?.split(' ').includes('openid') ||
    !state || !nonce || !codeChallenge
  ) {
    observed.rejectedRequests += 1;
    return json(response, 400, { error: 'invalid_request' });
  }
  const code = randomBytes(32).toString('base64url');
  pendingCodes.set(code, {
    clientId: client.clientId,
    nonce,
    codeChallenge,
    expiresAt: Date.now() + PENDING_CODE_TTL_MS,
  });
  observed.authorizations += 1;
  const location = new URL(client.redirectUri);
  location.searchParams.set('code', code);
  location.searchParams.set('state', state);
  response.writeHead(302, {
    'Cache-Control': 'no-store',
    Location: location.toString(),
  });
  response.end();
  return undefined;
}

/** One use per code, with client authentication and the PKCE verifier. */
function exchangeCode(body, response) {
  const params = new URLSearchParams(body);
  const code = params.get('code') ?? '';
  const pending = pendingCodes.get(code);
  pendingCodes.delete(code);
  const client = clients.get(params.get('client_id') ?? '');
  const verifier = params.get('code_verifier') ?? '';
  if (
    !pending ||
    !client ||
    pending.clientId !== client.clientId ||
    pending.expiresAt < Date.now() ||
    params.get('grant_type') !== 'authorization_code' ||
    !sameSecret(params.get('client_secret') ?? '', client.clientSecret) ||
    params.get('redirect_uri') !== client.redirectUri ||
    createHash('sha256').update(verifier).digest('base64url') !== pending.codeChallenge
  ) {
    observed.rejectedRequests += 1;
    return json(response, 400, { error: 'invalid_grant' });
  }
  const now = Math.floor(Date.now() / 1000);
  const short = shortAccessTokensRequested.delete(client.name);
  const remaining = short ? SHORT_ACCESS_TOKEN_SECONDS : ACCESS_TOKEN_TTL_SECONDS;
  const exp = short
    ? now + SHORT_ACCESS_TOKEN_SECONDS - GATEWAY_JWT_EXP_LEEWAY_SECONDS
    : now + ACCESS_TOKEN_TTL_SECONDS;
  const accessToken = signedToken({
    iss: ISSUER,
    sub: OPERATOR_SUBJECT,
    email: 'admin-session-operator@example.test',
    roles: [OPERATOR_ROLE, DELEGATED_ROLE],
    iat: now,
    exp,
  });
  const idToken = signedToken({
    iss: ISSUER,
    aud: client.clientId,
    sub: OPERATOR_SUBJECT,
    nonce: pending.nonce,
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
  });
  observed.tokenExchanges += 1;
  observed.accessTokens.push(accessToken);
  return json(response, 200, {
    access_token: accessToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: remaining,
  });
}

function sameSecret(candidate, expected) {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function rememberCookieNames(header) {
  for (const pair of (header ?? '').split(';')) {
    const name = pair.split('=')[0]?.trim();
    if (name && !observed.cookieNames.includes(name)) {
      observed.cookieNames.push(name);
    }
  }
}

async function prepareRuntimeFiles() {
  chmodSync(runtimeRoot, 0o700);
  for (const gateway of GATEWAYS) {
    const files = gatewayFiles(gateway);
    mkdirSync(files.directory, { mode: 0o700 });
    writeFileSync(files.policy, JSON.stringify(policyFor(gateway), null, 2), {
      mode: 0o600,
    });
  }
  await issueCertificate();
  caCertificatePem = readFileSync(tls.caCertificate, 'utf8');
}

/**
 * Routes are matched per admin prefix; the token handlers additionally check
 * admin:tokens:write for creation and revocation.
 */
function policyFor(gateway) {
  const apiPrefix = `/v1${gateway.prefix}`;
  return {
    schema_version: '0.1.0',
    id: `admin-session-live-${gateway.name}`,
    default_action: 'deny',
    enforcement_mode: 'enforce',
    roles: {
      [OPERATOR_ROLE]: {
        permissions: ['admin:traffic:read', 'admin:tokens:read', 'admin:tokens:write'],
      },
      [DELEGATED_ROLE]: { permissions: ['admin:traffic:read'] },
    },
    routes: [
      { methods: ['GET'], path_prefix: `${apiPrefix}/traffic`, permission: 'admin:traffic:read' },
      {
        methods: ['GET', 'POST', 'DELETE'],
        path_prefix: `${apiPrefix}/tokens`,
        permission: 'admin:tokens:read',
      },
    ],
  };
}

/**
 * A one-day CA and a leaf for 127.0.0.1 and localhost. The CA key signs the
 * leaf and is deleted at once; the browser is told to accept the leaf, while
 * the fixture and the spec verify it against the CA certificate.
 */
async function issueCertificate() {
  writeFileSync(
    tls.caConfig,
    [
      '[req]',
      'distinguished_name = subject',
      'x509_extensions = ca',
      'prompt = no',
      '[subject]',
      'CN = GreenGateway admin-session live test CA',
      '[ca]',
      'basicConstraints = critical,CA:TRUE,pathlen:0',
      'keyUsage = critical,keyCertSign,cRLSign',
      'subjectKeyIdentifier = hash',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  writeFileSync(
    tls.leafConfig,
    [
      '[req]',
      'distinguished_name = subject',
      'prompt = no',
      '[subject]',
      `CN = ${HOST}`,
      '[leaf]',
      'basicConstraints = critical,CA:FALSE',
      'keyUsage = critical,digitalSignature',
      'extendedKeyUsage = serverAuth',
      `subjectAltName = IP:${HOST},DNS:localhost`,
      'authorityKeyIdentifier = keyid',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  const ecKey = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
  await runCommand('openssl', [
    'req', '-x509', '-new', '-config', tls.caConfig, ...ecKey,
    '-days', '1', '-keyout', tls.caKey, '-out', tls.caCertificate,
  ], runtimeRoot, 'pipe');
  await runCommand('openssl', [
    'req', '-new', '-config', tls.leafConfig, ...ecKey,
    '-keyout', tls.key, '-out', tls.request,
  ], runtimeRoot, 'pipe');
  await runCommand('openssl', [
    'x509', '-req', '-in', tls.request, '-CA', tls.caCertificate,
    '-CAkey', tls.caKey, '-set_serial', `0x${randomBytes(16).toString('hex')}`,
    '-days', '1', '-sha256', '-extfile', tls.leafConfig, '-extensions', 'leaf',
    '-out', tls.certificate,
  ], runtimeRoot, 'pipe');
  rmSync(tls.caKey, { force: true });
  rmSync(tls.request, { force: true });
  chmodSync(tls.key, 0o600);
  chmodSync(tls.certificate, 0o644);
  chmodSync(tls.caCertificate, 0o644);
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

function startGateways() {
  const configuredTarget = process.env.CARGO_TARGET_DIR;
  const targetRoot = configuredTarget
    ? path.resolve(workspaceRoot, configuredTarget)
    : path.join(workspaceRoot, 'target');
  const executable = path.join(
    targetRoot,
    'debug',
    process.platform === 'win32' ? 'gateway.exe' : 'gateway',
  );

  for (const gateway of GATEWAYS) {
    const files = gatewayFiles(gateway);
    const output = createWriteStream(files.output, { flags: 'a', mode: 0o600 });
    const child = spawn(executable, [], {
      cwd: files.directory,
      env: gatewayEnvironment(gateway, files),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    gateway.process = child;
    const remember = (chunk) => {
      output.write(chunk);
      gateway.outputTail = `${gateway.outputTail}${chunk.toString('utf8')}`.slice(
        -GATEWAY_OUTPUT_TAIL_BYTES,
      );
    };
    child.stdout.on('data', remember);
    child.stderr.on('data', remember);
    child.on('error', (error) => {
      console.error(
        `[admin-session-fixture] ${gateway.name} gateway process failed: ${error.message}`,
      );
      void shutdown(1);
    });
    child.on('exit', (code, signalName) => {
      output.end();
      if (shuttingDown) {
        return;
      }
      console.error(
        `[admin-session-fixture] ${gateway.name} gateway exited early (${code ?? signalName ?? 'unknown'}). ${gateway.outputTail}`,
      );
      void shutdown(1);
    });
  }
}

async function waitForGateways() {
  const deadline = Date.now() + GATEWAY_READY_TIMEOUT_MS;
  for (const gateway of GATEWAYS) {
    for (const readyUrl of gateway.readyUrls) {
      while ((await probeStatus(readyUrl)) !== 200) {
        if (Date.now() > deadline) {
          throw new Error(`${gateway.name} gateway did not become ready`);
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
  }
}

/** HTTPS probes verify the leaf against the run's CA, including its name. */
function probeStatus(target) {
  const url = new URL(target);
  const secure = url.protocol === 'https:';
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  return new Promise((resolve) => {
    const request = (secure ? httpsRequest : httpRequest)({
      host: HOST,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers: { Host: url.host },
      timeout: 2_000,
      ...(secure
        ? {
            ca: caCertificatePem,
            ...(isIP(hostname) ? {} : { servername: hostname }),
          }
        : {}),
    }, (response) => {
      response.resume();
      resolve(response.statusCode ?? 0);
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(0));
    request.end();
  });
}

function gatewayFiles(gateway) {
  const directory = path.join(runtimeRoot, gateway.name);
  return {
    directory,
    policy: path.join(directory, 'policy.json'),
    tokens: path.join(directory, 'tokens.sqlite'),
    audit: path.join(directory, 'audit.jsonl'),
    // The audit store of record the default AUDIT_DURABILITY=required needs;
    // without one the gateway refuses to start.
    auditStore: path.join(directory, 'audit.sqlite'),
    output: path.join(directory, 'gateway.log'),
  };
}

function gatewayEnvironment(gateway, files) {
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
    POLICY_FILE: files.policy,
    SERVICE_TOKEN_SQLITE_PATH: files.tokens,
    AUDIT_LOG_FILE: files.audit,
    AUDIT_SQLITE_PATH: files.auditStore,
    AUTH_ENABLED: 'true',
    AUTH_MODE: 'required',
    AUTH_PROVIDERS: JSON.stringify([
      {
        name: PROVIDER_NAME,
        type: 'jwt',
        issuer: ISSUER,
        roles_claim: 'roles',
        require_jti: false,
        client_id: gateway.clientId,
        client_secret: gateway.clientSecret,
        redirect_uri: gateway.redirectUri,
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
    // Verbose enough that the spec's scan of this output for credentials
    // covers more than startup warnings.
    RUST_LOG: 'info',
    ...gateway.environment(tls),
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
  return undefined;
}

async function shutdown(exitCode) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;

  const exited = (child) => child.exitCode !== null || child.signalCode !== null;
  await Promise.all(GATEWAYS.map(async (gateway) => {
    const child = gateway.process;
    if (!child || exited(child)) {
      return;
    }
    child.kill();
    await Promise.race([
      new Promise((resolve) => child.once('exit', resolve)),
      new Promise((resolve) => setTimeout(resolve, 1_000)),
    ]);
    if (!exited(child)) {
      child.kill('SIGKILL');
    }
  }));

  // Keep-alive connections would otherwise hold close() open.
  providerServer.closeAllConnections();
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
    try {
      rmSync(resolvedRoot, { force: true, recursive: true, maxRetries: 5, retryDelay: 100 });
      console.log('[admin-session-fixture] removed the run\'s keys, certificates and gateway state');
    } catch (error) {
      console.error(
        `[admin-session-fixture] could not remove the run's files: ${safeError(error)}`,
      );
    }
  }
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}
