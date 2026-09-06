#!/usr/bin/env node
// Fresh local credentials. Only the public subdirectory is served by Compose.
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../dev/jwks/generated/', import.meta.url));
const keyPath = path.join(root, 'dev-signing-key.pem');
await mkdir(path.join(root, 'public'), { recursive: true, mode: 0o700 });
try {
  await access(keyPath);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    flag: 'wx', mode: 0o600,
  });
}
const jwk = createPublicKey(await readFile(keyPath)).export({ format: 'jwk' });
Object.assign(jwk, { kid: 'greengateway-dev-jwks-2026-07-03', use: 'sig', alg: 'RS256' });
await writeFile(path.join(root, 'public/jwks.json'), JSON.stringify({ keys: [jwk] }, null, 2));
console.log('Local development JWKS ready; the private key is excluded from the served directory.');
