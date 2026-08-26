/// Rewrites the forwarded-client headers on a container subrequest so they
/// describe the real caller rather than whatever the caller claimed.
///
/// The end user's connection terminates at Cloudflare's edge, so the connection
/// the container accepts is opened by the Durable Object. Every request
/// therefore arrives from the same peer address, and the gateway's per-IP bounds
/// -- pre-auth rate limiting, the pending-login store -- collapse onto a single
/// shared key unless something recovers the client identity here.
///
/// `cf-connecting-ip` is the value Cloudflare guarantees, and the gateway reads
/// `x-forwarded-for` / `x-real-ip`, so this translates between them. Both are
/// **set**, never appended: a value the client supplied must not survive into
/// the subrequest, and this worker is the only ingress to the container, so
/// overwriting is what makes the result trustworthy.
///
/// The gateway still ignores these headers unless the connection peer is inside
/// `TRUSTED_PROXY_CIDRS` and `TRUST_PROXY_HEADERS` is on -- see
/// docs/deployment/cloudflare.md. Supplying the header is necessary but not by
/// itself sufficient, and that is deliberate: the trust decision stays an
/// explicit operator choice rather than something this worker grants silently.
///
/// Kept free of `@cloudflare/containers` imports so it is exercisable outside
/// the workers runtime.
export function withForwardedClientIdentity(request: Request): Request {
  const connectingIp = request.headers.get("cf-connecting-ip");
  const forwarded = new Request(request);

  if (connectingIp) {
    forwarded.headers.set("x-forwarded-for", connectingIp);
    forwarded.headers.set("x-real-ip", connectingIp);
    return forwarded;
  }

  // No edge-supplied identity: strip rather than pass through, so a
  // caller-supplied value can never be mistaken for one Cloudflare vouched for.
  forwarded.headers.delete("x-forwarded-for");
  forwarded.headers.delete("x-real-ip");
  return forwarded;
}
