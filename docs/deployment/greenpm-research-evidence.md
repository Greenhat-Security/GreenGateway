# GreenPM research evidence transport

Refs Greenhat-Security/GreenPM#26.

The application owns project/task research, revisions, review, artifact access and ZIP generation. Gateway validates and delegates the current human cookie session and enforces route policy. HR performs read-only requests with that same verified caller; it does not receive the origin admission secret or a shared administrator identity.

## Route configuration

Deploy a binary that recognizes `body_limit_profile` first. In the secret-backed `UPSTREAM_ROUTES`, merge only `"body_limit_profile":"greenpm_research_v1"` into the existing `greenpm-owned` entry. Keep its existing `add_request_headers` secret value and every unrelated setting unchanged. Never print the full route table.

The profile requires these already configured non-secret fields:

```json
{
  "id": "greenpm-owned",
  "path_prefix": "/api/greenpm-owned",
  "upstream_url": "https://greenpm-api.fly.dev",
  "forward_cookie_session": true,
  "body_limit_profile": "greenpm_research_v1"
}
```

This is a merge example, not a complete secret or replacement route table. Unknown profiles fail startup. The fixed profile binds the two operations to the reviewed application origin, not merely a reusable route label. It inherits the ordinary route TLS, DNS/IP validation, timeouts, admission, credential delegation and audit behavior. No global body-limit changes are needed.

| Operation | Gateway budget | Application budget |
| --- | --- | --- |
| POST tasks/{UUID}/research/evidence | 1,572,864 JSON request bytes | 1,048,576 decoded bytes, strict base64 and supported media types |
| GET projects/{UUID}/research/export | 23,068,672 complete response bytes | 20,971,520 uncompressed ZIP bytes and 23,068,672 wire bytes |
| Every other operation | Existing global defaults/settings | Existing ordinary JSON limit 65,536 bytes; artifact download max 1 MiB |

Only canonical lowercase UUID paths and the exact methods select the larger limits; query strings and alternative encodings do not. The upload budget applies before declared-body admission and during actual buffered reads, including requests without a length. Export buffering fails before successful headers or attachment bytes leave Gateway. Gateway does not inspect ZIP contents: the application's uncompressed-size check is required. Binary response bytes, Content-Disposition, Content-Type, private cache policy, CSP, nosniff and integrity-hash headers survive the ordinary hop-by-hop header filter.

## Exact policy addition

The [seven-rule fragment](../examples/greenpm-research-rules.json) adds nine method/path pairs. Merge those rules immediately before `greenpm-owned-deny-other-operations` in the active policy. Preserve all existing rules, order and other policy sections. Each allow requires the `greenpm-owned` dispatch and `provider:greenhat-session` / `session_cookie` principal boundary. The fragment does not grant project membership or review permission; the API continues to enforce those.

The research rules cover the catalog, project/task research reads and updates, review, evidence upload/download and project export. HR uses only GET catalog/project/task research reads; browser writes still require matching CSRF and application Origin checks. Do not add auth/CSRF exemptions, wildcard allows or direct-origin fallbacks.

## Activation and rollback

1. Build, test and review the source change. Publish the resulting pinned image through the normal release process. Record the image digest and rollout revision; `/version` alone is not a commit witness.
2. Read current deployment settings and the active policy. Preserve a protected rollback copy, including its policy revision/ETag. The checked-in recovery seed does not prove which policy is active.
3. Deploy the compatible Gateway binary while the profile is absent. Confirm health and existing PM/Admin/other application operations before enabling anything.
4. Merge the one profile field into the secret source and synchronize the existing route table through the normal deployment process. Keep global request/response caps unchanged. Verify startup/health.
5. Validate the complete proposed policy with the admin validation endpoint, then replace it conditionally with the exact current ETag. A rule-create API that appends after the catch-all deny will not enable these operations.
6. Verify authenticated two-user behavior: catalog visibility, same-project access, cross-project/org denial, missing/revoked session denial, ordinary body limits, upload at cap and cap+1 with/without Content-Length, export above 5 MiB, export over 22 MiB, query/encoding/method near misses, JSON-only requests, CSRF rejection, direct-origin rejection and redirect refusal. Confirm evidence/hash headers and actor attribution without logging cookies or content.
7. Enable the HR integration only after PM and Gateway gates pass. HR additionally matches Auth subject/email to its enabled user, checks PM's actor/organization echo against the Company mapping, and records immutable evidence references with approved time.

To roll back, remove the research policy allows first, remove the profile field while retaining all other route fields, then restore the previous image if needed. An older binary rejects this new field, so never roll back the binary while leaving the field configured. Retain research data for later recovery; Gateway rollout does not require a destructive data migration.

No live environment is changed by this source patch or these examples.

Research exports have a dedicated one-buffer admission budget per Gateway process, independent of ordinary route concurrency. Busy exports return `503` with `Retry-After: 5` before any body/origin work. The permit remains held through downstream completion, cancellation, deadline or shutdown; retained archive chunks are independent allocations of at most 64 KiB. Enabling the profile changes the HA static-config fingerprint, so replicas cannot silently disagree on the limits. A fleet of N replicas permits at most N such buffers; apply the same profile consistently.
