import { describe, expect, it } from 'vitest';

import { principalDetailPath } from './principals';

describe('principalDetailPath', () => {
  it('trims subject and auth method query params for detail links', () => {
    const path = principalDetailPath({
      subject: ' alice ',
      issuer: 'https://idp.example',
      auth_method: ' bearer ',
    });

    const url = new URL(path, 'http://localhost');

    expect(url.pathname).toBe('/identities/detail');
    expect(url.searchParams.get('subject')).toBe('alice');
    expect(url.searchParams.get('issuer')).toBe('https://idp.example');
    expect(url.searchParams.get('auth_method')).toBe('bearer');
  });
});
