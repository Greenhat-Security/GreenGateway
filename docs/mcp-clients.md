# MCP client configuration templates

GreenGateway generates configuration templates for MCP clients that connect to its own MCP endpoint (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#mcp-client-templates)). Templates are offered for a generic Streamable HTTP client, Claude Desktop, Cursor and VS Code. None of them holds a credential, and GreenGateway never edits a client's configuration file: an operator reads a template and puts it where the client expects it.

**Status: alpha.** The template document is `greengateway.dev/v1alpha1` and may change before the release that ends the alpha. The client formats below are the ones these clients documented when this release was written; check them against the client version you run.

## Where templates come from

The same document is available in three places, all rendered by the shared `gateway-config` library:

- **Admin API:** `GET /v1{ADMIN_PREFIX}/mcp/client-configs` returns the `McpClientConfigs` document ([schema](schemas/mcp-client-configs.v1alpha1.schema.json), [OpenAPI](openapi/admin-mcp-client-configs.v1alpha1.openapi.json)). See [the admin route](configuration.md#mcp-client-templates).
- **Admin UI:** the **MCP clients** page shows the endpoint, whether OAuth is available, and the template for the chosen client and authentication as read-only text.
- **`ggctl`:** `ggctl mcp-config --server URL --client generic|claude-desktop|cursor|vscode [--auth oauth|token] [--name NAME]` writes one template to standard output; see [`ggctl mcp-config`](ggctl.md#mcp-config).

Every one of them reads the route above, which needs the `admin:mcp:clients:read` permission (see [least privilege](#least-privilege)).

## The URL in a template

Every template names the gateway's MCP endpoint and nothing else: never an upstream Connection, an upstream MCP server or another origin. The gateway computes that URL from `GATEWAY_PUBLIC_URL` exactly as it computes the resource identifier of its [OAuth protected-resource metadata](configuration.md#gateway_public_url): the public URL with `/mcp` appended to its path, in canonical URL form. For `GATEWAY_PUBLIC_URL=https://gateway.example.test/base/` that is `https://gateway.example.test/base/mcp`, which is also the `aud` a JWT must carry for this resource.

The URL never comes from the request: not from `Host`, `Forwarded` or `X-Forwarded-*` headers, not from the browser's location, and not from a query parameter. When `GATEWAY_PUBLIC_URL` is unset the route answers `409` with reason `public_url_not_configured` instead of guessing; set it and restart the gateway. A public URL whose MCP endpoint holds `$`, `{`, `}` or `\` (characters a client configuration file interpolates or escapes), or is longer than 16 KiB, is refused the same way with reason `public_url_not_templatable`.

## Templates

Each template has a client, an authentication mode and a format. `oauth` templates are offered only when the protected-resource metadata advertises an authorization server, which it does when an `AUTH_PROVIDERS` JWT provider has an `issuer`; without one, the document says `"oauth": false` and holds token templates only.

| Client | `oauth` | `token` | Format | Where it goes |
| --- | --- | --- | --- | --- |
| `generic` | yes | yes | JSON | A description of the connection (`transport: streamable-http`, `url`, and for a token the header to send) to translate into any Streamable HTTP client's own configuration. |
| `claude-desktop` | yes | no | URL | The URL of a custom connector, which Claude Desktop authorizes with OAuth. |
| `cursor` | yes | yes | JSON | `mcpServers` in `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` (`%USERPROFILE%\.cursor\mcp.json` on Windows) for every project. |
| `vscode` | yes | yes | JSON | `servers` in `.vscode/mcp.json` in a workspace. |

An `oauth` template holds the URL and nothing that authenticates; the client finds the authorization server through the gateway's `WWW-Authenticate` challenge and protected-resource metadata and obtains its own token. A `token` template sends `Authorization: Bearer` with the token read from the environment variable `GREENGATEWAY_MCP_TOKEN` in the client's own interpolation syntax: `${env:GREENGATEWAY_MCP_TOKEN}` for Cursor and VS Code, `${GREENGATEWAY_MCP_TOKEN}` (shell syntax) in the generic description. Set the variable in the environment the client starts in; the template never holds the token itself. Claude Desktop has no token template: it connects to a remote server as a custom connector with OAuth, and GreenGateway does not generate a local bridge that would need the token in its configuration file.

The JSON templates name the server entry `greengateway`. `?name=` on the route, `--name` for `ggctl`, chooses another entry name: 1 to 64 ASCII letters, digits, `-` and `_`, starting with a letter or digit. A name outside that grammar is refused, never escaped into a template, and is not echoed back.

For example, the Cursor token template for `GATEWAY_PUBLIC_URL=https://gateway.example.test`:

```json
{
  "mcpServers": {
    "greengateway": {
      "url": "https://gateway.example.test/mcp",
      "headers": {
        "Authorization": "Bearer ${env:GREENGATEWAY_MCP_TOKEN}"
      }
    }
  }
}
```

If the client's file already holds other servers, merge the entry rather than replacing the file.

## Least privilege

Three different authorities are involved, and none implies another.

- **Reading templates** needs `admin:mcp:clients:read`. It is not `admin:config:read` and grants nothing else: a template names only the public MCP endpoint and holds no credential. Under a default-deny policy, route it as well:

  ```json
  {"methods": ["GET"], "path_prefix": "/v1/admin/mcp", "permission": "admin:mcp:clients:read"}
  ```

- **Using the MCP endpoint** needs a principal whose roles pass the policy route for `/mcp` (whatever permission the deployment routes it to, `admin:mcp:use` in the [development policy](../dev/policy.json)) and appear in the `allowed_roles` of each tool the client should call. Give an MCP client a dedicated role that grants only that route's permission and is listed only for the tools it needs, for example:

  ```json
  {
    "roles": {"mcp-client": {"permissions": ["mcp:use"]}},
    "routes": [{"methods": ["POST"], "path_prefix": "/mcp", "permission": "mcp:use"}],
    "tools": {"search_docs": {"allowed_roles": ["mcp-client"]}}
  }
  ```

  With `GATEWAY_PUBLIC_URL` set, a credential must also be bound to the MCP resource: a JWT must carry the MCP URL above in its `aud` claim, and a GreenGateway `ggw_` service token must carry the exact `mcp:tools` scope. That binding authenticates the credential for `/mcp` only; what it may do there is still decided by its roles.

- **Minting a token** for a `token` template is a separate `POST /v1{ADMIN_PREFIX}/tokens` under `admin:tokens:write`, bounded by the existing scope delegation rules of the [service token admin API](configuration.md#service_token_sqlite_path): request exactly `["mcp-client", "mcp:tools"]` for the role above. A caller whose roles grant `*` may delegate both; any other caller may delegate only roles it carries and can activate, which for the `mcp:tools` marker means the policy must define it as a role that caller holds. The template permission cannot mint or reveal a token, and a token shown once in the admin UI is never part of a template.

## Copying

The admin UI never reads or writes the clipboard. It serves the same `Permissions-Policy` as every gateway response, which denies `clipboard-read` and `clipboard-write`, and its pages copy nothing on their own: **Select all** on the MCP clients page, like **Select token** for a newly created service token, selects the text so the operator copies it with the keyboard or the context menu. A value leaves the page only by the operator's own action.

## What is not done

- No client's configuration file is opened, created or edited, by the gateway, the admin UI or `ggctl`.
- No template is rendered for an upstream MCP server or Connection; templates always point at the gateway.
- No OS keychain or secret-store placeholder is generated yet; token templates use the environment variable only.
