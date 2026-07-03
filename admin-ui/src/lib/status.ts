import { adminFetchJson } from './api';

export type GatewayStatus = {
  version: string;
  uptime_seconds: number;
  listen_addr: string;
  auth_enabled: boolean;
  rbac: {
    policy_loaded: boolean;
    policy_id: string | null;
  };
  audit_sinks: {
    stdout: boolean;
    file: boolean;
    sqlite: boolean;
    broadcast: boolean;
  };
  rate_limits: {
    read: RateLimitStatus;
    write: RateLimitStatus;
  };
  cors_allow_origins: string[];
  trust_proxy_headers: boolean;
  csrf_enabled: boolean;
  egress: {
    allowed_hosts_count: number;
    deny_private_ips: boolean;
  };
};

export type RateLimitStatus = {
  requests_per_second: number;
  burst: number;
};

export function fetchGatewayStatus(): Promise<GatewayStatus> {
  return adminFetchJson<GatewayStatus>('/v1/admin/status');
}
