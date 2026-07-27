import { describe, expect, it } from "vitest";

import {
  buildGreenGatewayContainerEnv,
  CONTAINER_PING_ENDPOINT,
  CONTAINER_PORT,
  GREEN_GATEWAY_ENV_KEYS,
} from "./config";

describe("buildGreenGatewayContainerEnv", () => {
  it("uses the process-only liveness probe for container supervision", () => {
    expect(CONTAINER_PING_ENDPOINT).toBe("localhost/livez");
  });

  it("forces the container to listen on the Cloudflare-routed port", () => {
    const env = buildGreenGatewayContainerEnv({
      LISTEN_ADDR: "127.0.0.1:9999",
      UPSTREAM_URL: "https://api.example.com",
    });

    expect(env.LISTEN_ADDR).toBe(`0.0.0.0:${CONTAINER_PORT}`);
    expect(env.UPSTREAM_URL).toBe("https://api.example.com");
  });

  it("passes only supported non-empty string settings into the container", () => {
    const env = buildGreenGatewayContainerEnv({
      AUTH_MODE: "observe",
      JWT_JWKS_URL: "   ",
      CLOUDFLARE_API_TOKEN: "secret",
      GREENGATEWAY_CONTAINER: {},
      RATE_LIMIT_READ_RPS: 1,
    });

    expect(env).toMatchObject({
      LISTEN_ADDR: "0.0.0.0:8080",
      AUTH_MODE: "observe",
    });
    expect(env).not.toHaveProperty("JWT_JWKS_URL");
    expect(env).not.toHaveProperty("CLOUDFLARE_API_TOKEN");
    expect(env).not.toHaveProperty("RATE_LIMIT_READ_RPS");
  });

  it("does not allow a split admin listener because the Worker exposes one container port", () => {
    expect(GREEN_GATEWAY_ENV_KEYS).not.toContain("ADMIN_LISTEN_ADDR");
  });

  it("passes the complete trusted proxy boundary into the container", () => {
    const env = buildGreenGatewayContainerEnv({
      TRUST_PROXY_HEADERS: "true",
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,2001:db8:1234::/48",
    });

    expect(env).toMatchObject({
      TRUST_PROXY_HEADERS: "true",
      TRUSTED_PROXY_CIDRS: "10.0.0.0/8,2001:db8:1234::/48",
    });
  });

  it("forwards the complete graceful-shutdown budget", () => {
    const env = buildGreenGatewayContainerEnv({
      SHUTDOWN_DRAIN_DELAY_MS: "5000",
      SHUTDOWN_TIMEOUT_MS: "30000",
      AUDIT_DRAIN_TIMEOUT_MS: "5000",
    });

    expect(env).toMatchObject({
      SHUTDOWN_DRAIN_DELAY_MS: "5000",
      SHUTDOWN_TIMEOUT_MS: "30000",
      AUDIT_DRAIN_TIMEOUT_MS: "5000",
    });
  });

  it("forwards bounded login, discovery, and NAT64 settings", () => {
    const env = buildGreenGatewayContainerEnv({
      ADMIN_LOGIN_PENDING_TTL_SECS: "600",
      ADMIN_LOGIN_PENDING_MAX_ENTRIES: "1024",
      ADMIN_LOGIN_PENDING_MAX_PER_IP: "8",
      DISCOVERY_ENDPOINT_LIMIT: "10000",
      EGRESS_NAT64_PREFIXES: "64:ff9b::/96",
    });

    expect(env).toMatchObject({
      ADMIN_LOGIN_PENDING_TTL_SECS: "600",
      ADMIN_LOGIN_PENDING_MAX_ENTRIES: "1024",
      ADMIN_LOGIN_PENDING_MAX_PER_IP: "8",
      DISCOVERY_ENDPOINT_LIMIT: "10000",
      EGRESS_NAT64_PREFIXES: "64:ff9b::/96",
    });
  });
});
