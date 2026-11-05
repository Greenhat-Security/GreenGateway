import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

/**
 * The credential-free MCP client configuration templates served by
 * `GET /v1{ADMIN_PREFIX}/mcp/client-configs` (`admin:mcp:clients:read`,
 * issue #242). The gateway renders every template from its own
 * `GATEWAY_PUBLIC_URL`; this console only shows them as text and never
 * derives a URL from `window.location`.
 *
 * The shape mirrors `gateway-config/src/mcp_client_configs.rs` and
 * `docs/schemas/mcp-client-configs.v1alpha1.schema.json`. A document of any
 * other version or shape is refused whole rather than partly rendered.
 */
export const MCP_CLIENTS = ['generic', 'claude-desktop', 'cursor', 'vscode'] as const;
export type McpClient = (typeof MCP_CLIENTS)[number];

export const MCP_CLIENT_AUTHS = ['oauth', 'token'] as const;
export type McpClientAuth = (typeof MCP_CLIENT_AUTHS)[number];

export type McpTemplateFormat = 'json' | 'url';

export type McpClientTemplate = {
  client: McpClient;
  auth: McpClientAuth;
  format: McpTemplateFormat;
  /** Where the client reads a file holding this template; empty when it takes it in its own interface. */
  locations: string[];
  /** The template, ending in a line feed. Rendered as text only. */
  content: string;
};

export type McpClientConfigs = {
  apiVersion: 'greengateway.dev/v1alpha1';
  kind: 'McpClientConfigs';
  /** The gateway's MCP endpoint, computed by the gateway from GATEWAY_PUBLIC_URL. */
  mcpUrl: string;
  serverName: string;
  /** Whether the gateway advertises an authorization server; OAuth templates exist only then. */
  oauth: boolean;
  /** The environment variable every token template reads (always GREENGATEWAY_MCP_TOKEN). */
  tokenVariable: string;
  templates: McpClientTemplate[];
};

/** The refusal a document that is not a readable `McpClientConfigs` raises. */
export class McpClientConfigsUnreadable extends Error {
  constructor() {
    super('The gateway returned MCP client templates this console does not read.');
    this.name = 'McpClientConfigsUnreadable';
  }
}

export async function fetchMcpClientConfigs(): Promise<McpClientConfigs> {
  const document = await adminFetchJson<unknown>(adminApiUrl('/mcp/client-configs'));
  return readMcpClientConfigs(document);
}

const DOCUMENT_KEYS = ['apiVersion', 'kind', 'mcpUrl', 'serverName', 'oauth', 'tokenVariable', 'templates'];
const TEMPLATE_KEYS = ['client', 'auth', 'format', 'locations', 'content'];

/** Checks the document is exactly this version's shape. */
export function readMcpClientConfigs(document: unknown): McpClientConfigs {
  if (
    !hasExactly(document, DOCUMENT_KEYS) ||
    document.apiVersion !== 'greengateway.dev/v1alpha1' ||
    document.kind !== 'McpClientConfigs' ||
    typeof document.mcpUrl !== 'string' ||
    typeof document.serverName !== 'string' ||
    typeof document.oauth !== 'boolean' ||
    typeof document.tokenVariable !== 'string' ||
    !Array.isArray(document.templates) ||
    !document.templates.every(isTemplate)
  ) {
    throw new McpClientConfigsUnreadable();
  }
  return document as McpClientConfigs;
}

function isTemplate(value: unknown): value is McpClientTemplate {
  return (
    hasExactly(value, TEMPLATE_KEYS) &&
    (MCP_CLIENTS as readonly unknown[]).includes(value.client) &&
    (MCP_CLIENT_AUTHS as readonly unknown[]).includes(value.auth) &&
    (value.format === 'json' || value.format === 'url') &&
    Array.isArray(value.locations) &&
    value.locations.every((location) => typeof location === 'string') &&
    typeof value.content === 'string'
  );
}

function hasExactly(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
