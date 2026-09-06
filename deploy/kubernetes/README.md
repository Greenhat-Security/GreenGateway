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
Supply real identity settings and a newly promoted, verified application digest
before deployment; the checked-in identity URLs are explicit placeholders.
