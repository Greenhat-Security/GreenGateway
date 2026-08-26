import { describe, expect, it } from "vitest";

import { withForwardedClientIdentity } from "./forwarded";

describe("withForwardedClientIdentity", () => {
  it("replaces the forwarded headers with the edge-supplied client address", () => {
    const forwarded = withForwardedClientIdentity(
      new Request("https://gateway.example.test/v1/orders", {
        headers: {
          "cf-connecting-ip": "203.0.113.7",
          // A caller can send whatever it likes here; it must not survive.
          "x-forwarded-for": "10.0.0.1, 192.0.2.9",
          "x-real-ip": "10.0.0.1",
        },
      }),
    );

    expect(forwarded.headers.get("x-forwarded-for")).toBe("203.0.113.7");
    expect(forwarded.headers.get("x-real-ip")).toBe("203.0.113.7");
  });

  it("strips forwarded headers entirely when the edge supplied no client address", () => {
    // Without this the gateway could be handed a caller-authored chain and,
    // once the peer is trusted, treat it as one Cloudflare vouched for.
    const forwarded = withForwardedClientIdentity(
      new Request("https://gateway.example.test/v1/orders", {
        headers: { "x-forwarded-for": "10.0.0.1", "x-real-ip": "10.0.0.1" },
      }),
    );

    expect(forwarded.headers.get("x-forwarded-for")).toBeNull();
    expect(forwarded.headers.get("x-real-ip")).toBeNull();
  });

  it("leaves the request otherwise intact", () => {
    const forwarded = withForwardedClientIdentity(
      new Request("https://gateway.example.test/v1/orders", {
        method: "POST",
        headers: {
          "cf-connecting-ip": "203.0.113.7",
          authorization: "Bearer token-value",
          "content-type": "application/json",
        },
        body: '{"item":1}',
      }),
    );

    expect(forwarded.method).toBe("POST");
    expect(forwarded.url).toBe("https://gateway.example.test/v1/orders");
    expect(forwarded.headers.get("authorization")).toBe("Bearer token-value");
    expect(forwarded.headers.get("content-type")).toBe("application/json");
  });
});
