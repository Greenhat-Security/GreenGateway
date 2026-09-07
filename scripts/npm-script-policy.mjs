// Dependency-free: this gate runs before installing either npm project.
import { readFileSync, existsSync, realpathSync } from 'node:fs';
import { dirname, delimiter, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const identityKeys = ['version', 'resolved', 'integrity', 'optional', 'os', 'cpu', 'libc'];

export function checkProject(root, project) {
  if (!['.', 'admin-ui'].includes(project)) throw new Error('Expected project . or admin-ui');
  const policy = readJson(join(root, 'npm-script-policy.json'));
  if (policy.schema_version !== 1) throw new Error('Unsupported npm script policy schema');
  const reviewed = policy.projects?.[project];
  if (!reviewed || typeof reviewed !== 'object') throw new Error(`${project}: missing review inventory`);
  const directory = join(root, project);
  const lock = readJson(join(directory, 'package-lock.json'));
  if (lock.lockfileVersion !== 3 || !lock.packages) throw new Error(`${project}: expected npm v3 lockfile`);
  const flagged = Object.entries(lock.packages).filter(([path, value]) => path && value.hasInstallScript);
  if (!isDeepStrictEqual(flagged.map(([path]) => path).sort(), Object.keys(reviewed).sort())) {
    throw new Error(`${project}: lifecycle package inventory changed; review npm-script-policy.json`);
  }
  const expected = {};
  for (const [path, entry] of flagged) {
    const review = reviewed[path];
    for (const key of identityKeys) {
      if (!isDeepStrictEqual(entry[key], review[key])) {
        throw new Error(`${project}/${path}: reviewed ${key} changed; dependency review required`);
      }
    }
    if (!/^https:\/\/registry\.npmjs\.org\/.+\/-\/.+\.tgz$/.test(entry.resolved)
        || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity)) {
      throw new Error(`${project}/${path}: expected immutable registry tarball identity and SHA-512`);
    }
    // No current build needs an installer. Future exceptions require an explicit
    // change to this guard, the inventory rationale and clean-build evidence.
    if (review.allow !== false || !review.reason?.trim() || !review.scripts || !review.source_sha256) {
      throw new Error(`${project}/${path}: dependency scripts must remain explicitly denied with review evidence`);
    }
    expected[entry.resolved] = false;
  }
  const manifest = readJson(join(directory, 'package.json'));
  if (!isDeepStrictEqual(manifest.allowScripts, expected)) {
    throw new Error(`${project}: allowScripts must exactly match reviewed resolved identities`);
  }
  const config = readFileSync(join(directory, '.npmrc'), 'utf8').replace(/\r\n/g, '\n').trim();
  if (config !== 'engine-strict=true\nstrict-allow-scripts=true') {
    throw new Error(`${project}: committed strict npm configuration changed`);
  }
  const prefix = project === '.' ? '' : '../';
  if (manifest.scripts?.preinstall !== `node ${prefix}scripts/npm-script-policy.mjs check ${project}`) {
    throw new Error(`${project}: ordinary npm installs must verify the review inventory`);
  }
  for (const event of ['install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare']) {
    if (manifest.scripts?.[event]) throw new Error(`${project}: unreviewed project install hook ${event}`);
  }
}

function npmCli() {
  // Execute npm's JS entry with this exact Node, avoiding cmd.exe shell parsing.
  for (const directory of (process.env.PATH || '').split(delimiter)) {
    const shim = join(directory, process.platform === 'win32' ? 'npm.cmd' : 'npm');
    if (!existsSync(shim)) continue;
    const cli = process.platform === 'win32'
      ? join(directory, 'node_modules/npm/bin/npm-cli.js') : realpathSync(shim);
    if (!existsSync(cli)) throw new Error('Cannot locate npm CLI beside its PATH entry');
    return cli;
  }
  throw new Error('Pinned npm must be on PATH');
}

function run(cli, args, cwd, capture = false) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd, stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`npm ${args[0]} failed (${result.status})`);
  return result.stdout?.trim();
}

export function installProject(root, project) {
  checkProject(root, project);
  const pins = readJson(join(root, 'build-tools.json'));
  if (process.versions.node !== pins.node
      || readFileSync(join(root, '.node-version'), 'utf8').trim() !== pins.node
      || readFileSync(join(root, '.npm-version'), 'utf8').trim() !== pins.npm) {
    throw new Error('Node/npm version contract mismatch');
  }
  const cli = npmCli();
  const directory = join(root, project);
  if (run(cli, ['--version'], directory, true) !== pins.npm) throw new Error('Pinned npm version required');
  run(cli, ['ci', '--strict-allow-scripts', '--ignore-scripts=false',
    '--dangerously-allow-all-scripts=false', '--include=optional', '--engine-strict'], directory);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command, project, ...extra] = process.argv.slice(2);
    if (extra.length) throw new Error('Unexpected arguments');
    if (command === 'check' && project) checkProject(ROOT, project);
    else if (command === 'check' && !project) {
      for (const name of ['.', 'admin-ui']) checkProject(ROOT, name);
    } else if (command === 'install' && project) installProject(ROOT, project);
    else throw new Error('Usage: node scripts/npm-script-policy.mjs check [.|admin-ui] | install <.|admin-ui>');
    console.log(`npm lifecycle policy verified${project ? `: ${project}` : ''}.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
