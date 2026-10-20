//! Bounds on the shape of an admitted request.
//!
//! The policy kernel (`policy_eval`) refuses a context whose method, path or
//! host exceeds these so that evaluation has a work limit. Request admission
//! (`middleware::validate`) refuses the same inputs first, with a status code
//! that names the limit, so a request the gateway serves can never reach the
//! kernel's rejection and be denied by what would look like an internal error.
//! Both sides read the numbers from here rather than each stating its own: a
//! bound raised on one side and not the other reopens exactly the divergence
//! issue #488 closed.
//!
//! Principal bounds live beside `Principal` in `auth::principal`, and `Host`
//! parsing beside its consumers in `upstream_route`, on the same principle.
//! The tool lane's facts follow the same rule from different admission points:
//! a tool name is bounded where policy is validated, and a rendered request
//! where the tool executor renders it.

/// Longest HTTP method token admitted. The registered methods are at most
/// seven bytes; the bound leaves room for extension methods without letting a
/// method be a payload.
pub(crate) const MAX_REQUEST_METHOD_BYTES: usize = 64;

/// Longest request path admitted, and the ceiling the `MAX_REQUEST_PATH_BYTES`
/// setting may be raised to. The kernel bounds the path it evaluates at this
/// length, so an operator can admit shorter paths than evaluation accepts but
/// never longer.
pub(crate) const MAX_REQUEST_PATH_BYTES: usize = 8192;

/// Longest `Host` admitted, measured with its port and brackets removed. The
/// same bound applies to an HTTP/2 `:authority`, which serves as the host.
pub(crate) const MAX_REQUEST_HOST_BYTES: usize = 4096;

/// Longest dispatch fact -- route id, route host, route path prefix, upstream
/// origin -- the kernel evaluates. These are configuration, not request
/// input, so they are held to the bound at startup: route ids and hosts are
/// bounded well below it by their own grammars, and route path prefixes and
/// upstream URLs (from which the origin derives) are refused above it by
/// configuration validation.
pub(crate) const MAX_DISPATCH_FACT_BYTES: usize = 4096;

/// Longest tool name the tool lane evaluates. Policy validation refuses a
/// longer `tools` entry name or rule `tool_name`, so no policy can name a tool
/// the kernel cannot be asked about, and the tool-lane adapter refuses a longer
/// name before evaluation, which blocks the call as an unknown name would.
/// Discovered MCP and OpenAPI tool names are bounded far below it (128
/// characters). A `TOOLS_FILE` definition's name is bounded only by that file's
/// size cap, so a call to a local tool can carry a longer name; it is refused
/// with `tool_name_out_of_bounds`, and no policy entry could have named it.
///
/// A rendered tool request's method and path are held to
/// [`MAX_REQUEST_METHOD_BYTES`] and [`MAX_REQUEST_PATH_BYTES`] at rendering,
/// before its HTTP rule is evaluated: they never pass through inbound request
/// admission.
pub(crate) const MAX_TOOL_NAME_BYTES: usize = 4096;
