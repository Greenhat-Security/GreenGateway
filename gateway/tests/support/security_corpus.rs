//! Test-only entry point for the bounded local corpus controller.
//!
//! The controller builds this executable once. Each worker handles a bounded
//! job without starting `main`, a runtime, a resolver or an upstream connection.

use std::{collections::BTreeMap, fs::File, io::Read, panic::AssertUnwindSafe};

use http::{header, HeaderMap, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    auth::jwt::corpus::CorpusHarness,
    path_match::{
        exempt_path_matches, is_unsafe_request_path, path_prefix_matches, GATEWAY_EXACT_ROUTE_PATHS,
    },
    policy_eval::{
        CompiledPolicy, HostFact, HttpTarget, PolicyAuthority, PolicyEvaluationContext,
        PrincipalFact, CONTEXT_VERSION, MAX_TRACE_BYTES,
    },
    request_bounds::MAX_REQUEST_HOST_BYTES,
    upstream_route::{host_header, is_bare_host, request_host_without_port, HostHeader},
};

const MAX_INPUT_BYTES: usize = 16_384;
const MAX_CORPUS_BYTES: usize = 262_144;
const MAX_JOB_BYTES: u64 = 2_097_152;
const MAX_CASES: usize = 100_000;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Target {
    Jwt,
    Policy,
    Host,
    Path,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::Policy => "policy",
            Self::Host => "host",
            Self::Path => "path",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    target: Target,
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    schema_version: u8,
    seed: u64,
    mutations_per_seed: usize,
    replay_case: Option<usize>,
    inputs: Vec<Input>,
}

impl Job {
    fn validate(&self) -> Result<usize, &'static str> {
        if self.schema_version != 1 || self.inputs.is_empty() || self.inputs.len() > 64 {
            return Err("invalid corpus job");
        }
        let per_seed = self.mutations_per_seed.checked_add(1).ok_or("case limit")?;
        let count = self
            .inputs
            .len()
            .checked_mul(per_seed)
            .ok_or("case limit")?;
        if count > MAX_CASES || self.replay_case.is_some_and(|index| index >= count) {
            return Err("case limit");
        }
        let mut total = 0usize;
        let mut targets = BTreeMap::new();
        for input in &self.inputs {
            if input.bytes.is_empty() || input.bytes.len() > MAX_INPUT_BYTES {
                return Err("input limit");
            }
            total = total.checked_add(input.bytes.len()).ok_or("corpus limit")?;
            targets.insert(input.target.name(), ());
        }
        if total > MAX_CORPUS_BYTES || targets.len() != 4 {
            return Err("incomplete corpus");
        }
        Ok(count)
    }
}

#[derive(Serialize)]
struct Failure {
    case_index: usize,
    target: &'static str,
    input_sha256: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct Receipt {
    schema_version: u8,
    status: &'static str,
    executed: usize,
    targets: BTreeMap<&'static str, usize>,
    failure: Option<Failure>,
}

// SplitMix64 is explicitly specified here instead of depending on a runtime's
// default RNG. The controller records `splitmix64-byte-mutations-v1` with the
// seed and corpus digest. Every mutation starts from its committed seed input.
struct MutationRng(u64);

impl MutationRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, length: usize) -> usize {
        (self.next() % length as u64) as usize
    }
}

fn mutate(source: &[u8], rng: &mut MutationRng) -> Vec<u8> {
    let mut bytes = source.to_vec();
    for _ in 0..=rng.index(4) {
        match rng.index(7) {
            0 if !bytes.is_empty() => {
                let index = rng.index(bytes.len());
                bytes[index] ^= 1 << rng.index(8);
            }
            1 if !bytes.is_empty() => {
                let index = rng.index(bytes.len());
                bytes[index] = rng.next() as u8;
            }
            2 if bytes.len() < MAX_INPUT_BYTES => {
                let index = rng.index(bytes.len() + 1);
                bytes.insert(index, rng.next() as u8);
            }
            3 if !bytes.is_empty() => {
                bytes.remove(rng.index(bytes.len()));
            }
            4 => {
                let length = rng.index(bytes.len() + 1);
                bytes.truncate(length);
            }
            5 if !bytes.is_empty() && bytes.len() < MAX_INPUT_BYTES => {
                let start = rng.index(bytes.len());
                let length = (bytes.len() - start)
                    .min(16)
                    .min(MAX_INPUT_BYTES - bytes.len());
                let repeated = bytes[start..start + length].to_vec();
                bytes.extend_from_slice(&repeated);
            }
            _ => {
                let markers = b"\"%\\{}./[]\0";
                let marker = markers[rng.index(markers.len())];
                if bytes.is_empty() {
                    bytes.push(marker);
                } else {
                    let index = rng.index(bytes.len());
                    bytes[index] = marker;
                }
            }
        }
    }
    bytes
}

fn check_policy(input: &[u8]) -> Result<(), &'static str> {
    let first = CompiledPolicy::compile(input, PolicyAuthority::Standalone);
    let second = CompiledPolicy::compile(input, PolicyAuthority::Standalone);
    match (first, second) {
        (Err(left), Err(right)) if left == right => Ok(()),
        (Ok(left), Ok(right)) => {
            if left.snapshot() != right.snapshot() {
                return Err("policy snapshot determinism");
            }
            let context = PolicyEvaluationContext {
                version: CONTEXT_VERSION,
                snapshot: left.snapshot(),
                method: Some(Method::GET),
                path: Some("/corpus/item".to_owned()),
                principal: PrincipalFact::Anonymous,
                target: HttpTarget::Contextless,
                request_host: HostFact::Absent,
                dispatch: None,
            };
            let result = left
                .evaluate(&context)
                .map_err(|_| "valid policy evaluation")?;
            let repeated = right
                .evaluate(&context)
                .map_err(|_| "repeated policy evaluation")?;
            let trace = result.canonical_trace_bytes().map_err(|_| "trace bound")?;
            if result != repeated
                || trace.len() > MAX_TRACE_BYTES
                || !result.is_complete()
                || !result.reusable_for(&context)
                || trace
                    != repeated
                        .canonical_trace_bytes()
                        .map_err(|_| "trace bound")?
            {
                return Err("policy invariant");
            }
            let mut stale = context;
            stale.version = CONTEXT_VERSION.wrapping_add(1);
            if left.evaluate(&stale).is_ok() || result.reusable_for(&stale) {
                return Err("policy version binding");
            }
            Ok(())
        }
        _ => Err("policy classification determinism"),
    }
}

fn check_host(input: &[u8]) -> Result<(), &'static str> {
    let Ok(value) = HeaderValue::from_bytes(input) else {
        return Ok(()); // These bytes cannot enter the typed Host parser.
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, value.clone());
    let uri = Uri::from_static("/corpus");
    let first = host_header(&uri, &headers);
    if first != host_header(&uri, &headers) {
        return Err("host determinism");
    }
    match first {
        HostHeader::Present(host) => {
            if host.len() > MAX_REQUEST_HOST_BYTES
                || !host.is_ascii()
                || !is_bare_host(&host)
                || host.bytes().any(|byte| byte.is_ascii_uppercase())
                || request_host_without_port(&uri, &headers).as_ref() != Some(&host)
            {
                return Err("host output invariant");
            }
        }
        _ if request_host_without_port(&uri, &headers).is_some() => {
            return Err("host rejection projection");
        }
        _ => {}
    }
    headers.append(header::HOST, value);
    if host_header(&uri, &headers) != HostHeader::Malformed {
        return Err("duplicate host rejection");
    }
    Ok(())
}

fn check_path(input: &[u8]) -> Result<(), &'static str> {
    let Ok(path) = std::str::from_utf8(input) else {
        return Ok(()); // The production helper accepts str, not arbitrary bytes.
    };
    let expected = path == "/corpus" || path.starts_with("/corpus/");
    if path_prefix_matches(path, "/corpus") != expected
        || path_prefix_matches(path, "relative")
        || !is_unsafe_request_path(&format!("{path}/../tail"))
    {
        return Err("literal path invariant");
    }
    for probe in GATEWAY_EXACT_ROUTE_PATHS {
        if exempt_path_matches(path, probe) != (path == *probe) {
            return Err("exact probe exemption");
        }
    }
    Ok(())
}

fn run(job: &Job) -> Result<Receipt, &'static str> {
    job.validate()?;
    let jwt = CorpusHarness::new()?;
    let mut rng = MutationRng(job.seed);
    let mut receipt = Receipt {
        schema_version: 1,
        status: "passed",
        executed: 0,
        targets: ["jwt", "policy", "host", "path"]
            .into_iter()
            .map(|name| (name, 0))
            .collect(),
        failure: None,
    };
    let mut case_index = 0;
    for source in &job.inputs {
        for mutation in 0..=job.mutations_per_seed {
            let input = if mutation == 0 {
                source.bytes.clone()
            } else {
                mutate(&source.bytes, &mut rng)
            };
            if job
                .replay_case
                .is_none_or(|selected| selected == case_index)
            {
                receipt.executed += 1;
                *receipt
                    .targets
                    .get_mut(source.target.name())
                    .ok_or("unknown target")? += 1;
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| match source.target {
                    Target::Jwt => jwt.check(&input),
                    Target::Policy => check_policy(&input),
                    Target::Host => check_host(&input),
                    Target::Path => check_path(&input),
                }));
                let kind = match outcome {
                    Ok(Ok(())) => None,
                    Ok(Err(_)) => Some("invariant"),
                    Err(_) => Some("panic"),
                };
                if let Some(kind) = kind {
                    receipt.status = "failed";
                    receipt.failure = Some(Failure {
                        case_index,
                        target: source.target.name(),
                        input_sha256: hex::encode(Sha256::digest(&input)),
                        kind,
                    });
                    return Ok(receipt);
                }
                if job.replay_case.is_some() {
                    return Ok(receipt);
                }
            }
            case_index += 1;
        }
    }
    Ok(receipt)
}

fn worker() -> Result<bool, &'static str> {
    let job_path = std::env::var_os("GREENGATEWAY_CORPUS_JOB").ok_or("missing job")?;
    let result_path =
        std::env::var_os("GREENGATEWAY_CORPUS_RESULT").ok_or("missing result path")?;
    let mut bytes = Vec::new();
    File::open(job_path)
        .map_err(|_| "missing job")?
        .take(MAX_JOB_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable job")?;
    if bytes.len() as u64 > MAX_JOB_BYTES {
        return Err("job too large");
    }
    let job: Job = serde_json::from_slice(&bytes).map_err(|_| "invalid job")?;
    let receipt = run(&job)?;
    let encoded = serde_json::to_vec(&receipt).map_err(|_| "receipt encoding")?;
    std::fs::write(result_path, encoded).map_err(|_| "receipt write")?;
    Ok(receipt.status == "passed")
}

#[test]
#[ignore = "run through scripts/security_corpus.py for mandatory process resource limits"]
fn bounded_corpus_worker() {
    // Panic messages may contain parser input. The controller discards stdout
    // and stderr too; only the fixed-schema, hashed receipt is reportable.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = worker();
    std::panic::set_hook(previous);
    assert!(
        matches!(result, Ok(true)),
        "bounded corpus failed; inspect redacted report"
    );
}
