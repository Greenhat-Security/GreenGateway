# Kubernetes deployment boundaries

Render the base with `kubectl kustomize deploy/kubernetes`. The data Service
exposes only port 8080; admin routes move to a separate loopback listener on
9090 and are absent from the data listener. Management network access is opt-in:
`kubectl kustomize deploy/kubernetes-management` adds a ClusterIP admin Service
and allows only pods AND namespaces carrying the management labels in its policy.
Gateway authentication and endpoint permissions remain required on that listener.
Route it through an authenticated management proxy with TLS; no public management
Ingress is supplied. Kubernetes-authorized port forwarding can reach loopback and
is a separate operator privilege.

Apply the NetworkPolicy with the workload and use a CNI that enforces it. Adapt
the ingress-controller selectors and DNS selectors to your cluster. The base
allows egress only to DNS and explicitly labelled TLS upstream pods. Before use,
add the actual IdP/JWKS, upstream API, secret-store and database destinations and
ports. A standard NetworkPolicy cannot select external destinations by hostname;
use stable CIDRs or your CNI's FQDN policy support. Node-local DNS needs its own
destination rule. Policies are additive: a separate allow-all policy defeats this
boundary. Pod labels and namespace labels must be controlled by administrators.

The Connections example remains single-replica SQLite. Apply the same network
policy with it and provide private keys through the deployment secret manager.
Supply real identity settings before deployment; the checked-in identity URLs
are explicit placeholders. The image pin below contains the audit fixes and
patched JWT validation.

## Verified image

Both examples pin the promoted image from revision
`878e6c904da65683ca72d312a529ad79984a6978`, with OCI index digest
`sha256:db1f8d0d344e9f552a32037301f076b9c5b6934d9db66c0b62024bd7bc355838`.
The [release CI and promotion](https://github.com/Greenhat-Security/GreenGateway/actions/runs/34052819898)
passed before this pin was advanced. Registry resolution and the image's revision
label were checked against that run. The published runtime platform is
`linux/amd64`; node selectors keep these workloads on compatible nodes.

The image build log confirms `jsonwebtoken` 10.4.0. The exact image passed
these local checks on 2026-09-06:

- Startup, readiness and graceful shutdown as UID/GID 10001, with a read-only
  root filesystem, all capabilities dropped and no external network access.
- Anonymous management API requests returned 401. A freshly signed local test
  identity reached the API on the management listener; the authenticated API
  path and UI were absent from the data listener. The UI carried its CSP.
- The documented Compose rehearsal passed verified database TLS, clean
  bootstrap, separate migration/runtime privileges, two ready replicas,
  database dump/restore, restored-schema verification and restored readiness.

The identity check used a fresh loopback JWKS fixture and an ephemeral writable
policy-history volume. The Compose rehearsal used disposable databases and
random credentials; it published no host ports and removed its resources.
These checks do not validate Kubernetes CNI enforcement, production identity
configuration, database failover/PITR, capacity SLOs or mixed-version upgrades.
Track those environment-specific checks in
[#389](https://github.com/Greenhat-Security/GreenGateway/issues/389) before rollout.
