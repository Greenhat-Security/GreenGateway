import { afterEach, describe, expect, it } from 'vitest';

import { adminApiUrl, adminBasePath } from './config';

afterEach(() => {
  document
    .querySelectorAll('meta[name^="greengateway-admin-"]')
    .forEach((element) => element.remove());
});

describe('admin runtime config', () => {
  it('defaults to the built-in admin paths when meta tags are absent', () => {
    expect(adminBasePath()).toBe('/admin');
    expect(adminApiUrl('/status')).toBe('/v1/admin/status');
  });

  it('uses gateway-injected admin path meta tags', () => {
    appendMeta('greengateway-admin-base', '/ops');
    appendMeta('greengateway-admin-api-base', '/ops/api');

    expect(adminBasePath()).toBe('/ops');
    expect(adminApiUrl('audit')).toBe('/ops/api/audit');
  });

  it('ignores malformed admin path meta tags', () => {
    appendMeta('greengateway-admin-base', 'ops');
    appendMeta('greengateway-admin-api-base', '/');

    expect(adminBasePath()).toBe('/admin');
    expect(adminApiUrl('/status')).toBe('/v1/admin/status');
  });
});

function appendMeta(name: string, content: string) {
  const meta = document.createElement('meta');
  meta.name = name;
  meta.content = content;
  document.head.append(meta);
}
