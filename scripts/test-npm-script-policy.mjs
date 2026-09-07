import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkProject, installProject } from './npm-script-policy.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'ggw-review-gate-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'admin-ui'));
  for (const path of ['npm-script-policy.json', 'package.json', 'package-lock.json', '.npmrc',
    'admin-ui/package.json', 'admin-ui/package-lock.json', 'admin-ui/.npmrc']) {
    copyFileSync(join(ROOT, path), join(root, path));
  }
  return root;
}
function change(root, file, mutate) {
  const path = join(root, file);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  writeFileSync(path, JSON.stringify(value));
}

test('both current inventories pass, including CRLF npmrc checkouts', (t) => {
  const root = fixture(t);
  for (const project of ['.', 'admin-ui']) {
    writeFileSync(join(root, project, '.npmrc'), 'engine-strict=true\r\nstrict-allow-scripts=true\r\n');
    checkProject(root, project);
  }
});

for (const project of ['.', 'admin-ui']) {
  test(`${project}: a newly script-bearing dependency blocks before invoking npm`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package-lock.json`, (lock) => {
      lock.packages['node_modules/new-marker'] = { version: '1.0.0', hasInstallScript: true };
    });
    // This isolated root contains no tool pins or npm executable: the review
    // must fail before version probes or installation can be reached.
    assert.throws(() => installProject(root, project), /inventory changed/);
  });

  for (const field of ['version', 'resolved', 'integrity']) {
    test(`${project}: changing denied package ${field} requires review`, (t) => {
      const root = fixture(t);
      change(root, `${project}/package-lock.json`, (lock) => {
        lock.packages['node_modules/esbuild'][field] += '-changed';
      });
      assert.throws(() => checkProject(root, project), new RegExp(`reviewed ${field} changed`));
    });
  }

  test(`${project}: another platform cannot hide a changed optional script`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package-lock.json`, (lock) => {
      lock.packages['node_modules/fsevents'].integrity += '-changed';
    });
    assert.throws(() => checkProject(root, project), /reviewed integrity changed/);
  });

  test(`${project}: platform or optionality changes require review`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package-lock.json`, (lock) => {
      lock.packages['node_modules/fsevents'].os = ['linux'];
    });
    assert.throws(() => checkProject(root, project), /reviewed os changed/);
  });

  test(`${project}: broad approval or missing denial is refused`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package.json`, (manifest) => { manifest.allowScripts = { esbuild: true }; });
    assert.throws(() => checkProject(root, project), /allowScripts must exactly match/);
  });

  test(`${project}: removing install metadata cannot silently remove a review`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package-lock.json`, (lock) => {
      delete lock.packages['node_modules/esbuild'].hasInstallScript;
    });
    assert.throws(() => checkProject(root, project), /inventory changed/);
  });

  test(`${project}: ordinary npm install must retain its project inventory check`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package.json`, (manifest) => { delete manifest.scripts.preinstall; });
    assert.throws(() => checkProject(root, project), /ordinary npm installs/);
  });

  test(`${project}: new project install hooks need explicit review`, (t) => {
    const root = fixture(t);
    change(root, `${project}/package.json`, (manifest) => { manifest.scripts.postinstall = 'node extra.cjs'; });
    assert.throws(() => checkProject(root, project), /unreviewed project install hook/);
  });

  test(`${project}: config bypass or duplicate key is refused`, (t) => {
    const root = fixture(t);
    writeFileSync(join(root, project, '.npmrc'),
      'engine-strict=true\nstrict-allow-scripts=true\nstrict-allow-scripts=false\n');
    assert.throws(() => checkProject(root, project), /strict npm configuration changed/);
  });
}

test('root cannot gain a dependency-script exception by editing only JSON', (t) => {
  const root = fixture(t);
  change(root, 'npm-script-policy.json', (policy) => { policy.projects['.']['node_modules/esbuild'].allow = true; });
  assert.throws(() => checkProject(root, '.'), /must remain explicitly denied/);
});

test('aliased install location still requires review of its resolved identity', (t) => {
  const root = fixture(t);
  change(root, 'package-lock.json', (lock) => {
    lock.packages['node_modules/alias'] = lock.packages['node_modules/esbuild'];
    delete lock.packages['node_modules/esbuild'];
  });
  assert.throws(() => checkProject(root, '.'), /inventory changed/);
});
