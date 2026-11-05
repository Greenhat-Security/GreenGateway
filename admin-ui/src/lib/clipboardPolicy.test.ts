import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The admin UI never uses the asynchronous clipboard API or the legacy copy
 * command (issue #242). The gateway serves the console with a
 * Permissions-Policy that denies `clipboard-read` and `clipboard-write`
 * (`gateway/src/middleware/headers.rs`, `PERMISSIONS_POLICY`), so a call
 * would fail in a browser anyway; this keeps the source honest about it.
 * Tokens and templates leave the page only when the operator selects them
 * and copies them with the keyboard or the context menu.
 */
const FORBIDDEN = [
  /navigator\s*\.\s*clipboard/,
  /\bClipboardItem\b/,
  /execCommand\s*\(/,
  /['"]clipboard-(read|write)['"]/,
];

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    if (!/\.(ts|tsx)$/.test(entry.name) || /\.test\.(ts|tsx)$/.test(entry.name)) return [];
    return [path];
  });
}

describe('clipboard policy', () => {
  it('no admin UI source reads or writes the clipboard', () => {
    // Resolved from the vitest root (`admin-ui`), as other source checks do.
    const files = sourceFiles(resolve(process.cwd(), 'src'));
    expect(files.length).toBeGreaterThan(20);
    const offenders = files.filter((file) => {
      const text = readFileSync(file, 'utf8');
      return FORBIDDEN.some((pattern) => pattern.test(text));
    });
    expect(offenders).toEqual([]);
  });

  it('the gateway denies the clipboard to the admin UI', () => {
    const headers = readFileSync(
      resolve(process.cwd(), '../gateway/src/middleware/headers.rs'),
      'utf8',
    );
    const declaration = headers.match(/pub\(crate\) const PERMISSIONS_POLICY: &str = "([^"]+)";/);
    expect(declaration).not.toBeNull();
    const directives = (declaration?.[1] ?? '').split(', ');
    expect(directives).toContain('clipboard-read=()');
    expect(directives).toContain('clipboard-write=()');
    const adminUi = readFileSync(resolve(process.cwd(), '../gateway/src/admin_ui.rs'), 'utf8');
    expect(adminUi).toContain('middleware::headers::PERMISSIONS_POLICY');
  });
});
