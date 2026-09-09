# Traffic overview

The admin dashboard shows request methods flowing into observed upstream
destinations. Ribbon widths represent request counts. Select a method,
destination or endpoint search to narrow the view, or switch to Table for
counts. Expand a destination to open its endpoints in the existing traffic
detail view.

Destination bars summarize current rule coverage. Endpoint-wide rules count
as covered, an explicit `none` scope counts as no matching rule, and partial,
mixed or unknown scopes remain in the unknown group. These are current rule
matches applied to observed traffic, not historical authorization decisions.

The overview requires `admin:traffic:read` and discovery storage. It starts
with the 50 busiest endpoints; Load more adds pages up to 500. Counts cover
lifetime observations for the loaded endpoints and active filters, not the
whole installation or a selected time window. Refresh fetches a new first
page. Missing routing context stays visible as Destination not recorded.
The diagram groups destinations after the largest six into Other destinations;
the breakdown retains each destination. Origins omit credentials, paths and
query strings. Requests are not unique users, byte volumes or data categories.

Development uses synthetic fixtures at
`admin-ui/tests/fixtures/traffic-overview.ts`. No production telemetry or
credentials are needed. With the versions in `build-tools.json`, run:

```sh
node scripts/npm-script-policy.mjs install admin-ui
cd admin-ui
npm test -- src/lib/trafficFlow.test.ts src/views/TrafficOverview.test.tsx
npx --no-install playwright install chromium
npx --no-install playwright test tests/traffic-overview.screenshot.spec.ts
```

The browser fixture covers light/dark themes, desktop/mobile layouts,
filtering and endpoint links. Unit tests cover request accounting, missing
context, partial coverage, pagination, error recovery and permission loss.
