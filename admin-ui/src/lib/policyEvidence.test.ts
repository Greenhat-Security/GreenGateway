import { afterEach, expect, it, vi } from 'vitest';

import { fetchPolicyEvidence } from './policyEvidence';

afterEach(() => vi.unstubAllGlobals());

it('cancels an oversized chunked package before reading or parsing the remainder', async () => {
  const cancel = vi.fn();
  const response = new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(4 * 1024 * 1024));
      controller.enqueue(new Uint8Array(1));
    },
    cancel,
  }), { headers: { 'content-type': 'application/vnd.greengateway.policy-evidence+json' } });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
  await expect(fetchPolicyEvidence({ publication: { version: 1 } }, {}, new AbortController().signal))
    .rejects.toThrow('invalid or mismatched evidence package');
  expect(cancel).toHaveBeenCalledOnce();
});
