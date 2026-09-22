//! Fixed synthetic workloads for selected production security predicates.
//!
//! The controller copies this file beside an authenticated source projection.
//! Pattern compilation, validation, reporting, and timing are outside allocation
//! counting. Allocated bytes count requested sizes, including the full new size
//! of each realloc; this is not a live-memory or peak-memory measurement.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

// Isolate projected production code from the benchmark's allocator and helpers.
// A production dependency absent from its projection must fail compilation,
// rather than accidentally resolving a similarly named benchmark function.
mod selected_path {
    include!("path_match.rs");
}

mod selected_egress {
    include!("egress.rs");

    pub(super) fn microbench_host_matches(pattern: &str, host: &str) -> bool {
        host_glob_matches(pattern, host)
    }
}

mod selected_rule {
    include!("rule_path.rs");

    pub(super) struct MicrobenchPreparedPattern {
        pattern: PathPattern,
    }

    impl MicrobenchPreparedPattern {
        pub(super) fn new(pattern: &str) -> Self {
            Self {
                pattern: PathPattern::new(pattern),
            }
        }

        pub(super) fn matches(&self, path: &str) -> bool {
            self.pattern.matches(path)
        }
    }

    pub(super) fn microbench_validate_method_matcher() {
        // The contiguous production projection includes MethodMatcher. Exercise
        // both forms during setup instead of suppressing unused-code warnings.
        assert!(MethodMatcher::new(&[]).matches("GET"));
        let methods = [String::from("GET")];
        let matcher = MethodMatcher::new(&methods);
        assert!(matcher.matches("get"));
        assert!(!matcher.matches("POST"));
    }
}

use selected_path::{exempt_path_matches, is_unsafe_request_path, path_prefix_matches};
use selected_rule::MicrobenchPreparedPattern;

const WARMUP: u64 = 100;
const ITERATIONS: u64 = 1_000;
const SAMPLES: usize = 9;

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static COUNTER_OVERFLOW: AtomicBool = AtomicBool::new(false);

fn checked_counter_add(counter: &AtomicU64, amount: u64) {
    if counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(amount)
        })
        .is_err()
    {
        COUNTER_OVERFLOW.store(true, Ordering::Relaxed);
    }
}

fn record_allocation(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        checked_counter_add(&ALLOCATIONS, 1);
        match u64::try_from(size) {
            Ok(bytes) => checked_counter_add(&ALLOCATED_BYTES, bytes),
            Err(_) => COUNTER_OVERFLOW.store(true, Ordering::Relaxed),
        }
    }
}

// SAFETY: Every allocation operation delegates unchanged to System. The
// bookkeeping uses only atomics and cannot recursively invoke the allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The caller provides the valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: The caller provides the valid allocation layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        // SAFETY: The caller's pointer, original layout, and new size are
        // forwarded to the allocator that originally supplied the allocation.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller's pointer and layout are forwarded unchanged to
        // the same allocator that supplied the allocation.
        unsafe { System.dealloc(ptr, layout) }
    }
}

// These are public, synthetic paths and reserved example.test hosts. Fixed
// literals keep the dataset independent of the machine and its environment.
const LONG_PATH: &str = concat!(
    "/admin/segment01/segment02/segment03/segment04/segment05/segment06/",
    "segment07/segment08/segment09/segment10/segment11/segment12/segment13/",
    "segment14/segment15/segment16/segment17/segment18/segment19/segment20/file.json"
);
const LONG_HOST: &str = concat!(
    "one.two.three.four.five.six.seven.eight.nine.ten.eleven.twelve.",
    "thirteen.fourteen.fifteen.sixteen.seventeen.eighteen.nineteen.twenty.example.test"
);

struct RequestCase {
    path: &'static str,
    exempt: &'static str,
    unsafe_path: bool,
    exempt_match: bool,
}

const REQUEST_CASES: &[RequestCase] = &[
    RequestCase {
        path: "/",
        exempt: "/",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: "/health",
        exempt: "/health",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: "/health/orders",
        exempt: "/health",
        unsafe_path: false,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin/assets/app.js",
        exempt: "/admin",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: "/administrator",
        exempt: "/admin",
        unsafe_path: false,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin/",
        exempt: "/admin",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: "/%61dmin",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin%2Fassets",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin\\assets",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin//assets",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: true,
    },
    RequestCase {
        path: "//admin/assets",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: false,
    },
    RequestCase {
        path: "/admin/../private",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: true,
    },
    RequestCase {
        path: "/admin/./assets",
        exempt: "/admin",
        unsafe_path: true,
        exempt_match: true,
    },
    RequestCase {
        path: "/files/report.v1.json",
        exempt: "/files",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: LONG_PATH,
        exempt: "/admin",
        unsafe_path: false,
        exempt_match: true,
    },
    RequestCase {
        path: LONG_PATH,
        exempt: "/admin/absent",
        unsafe_path: false,
        exempt_match: false,
    },
];

struct MatchCase {
    pattern: &'static str,
    input: &'static str,
    expected: bool,
}

const PREFIX_CASES: &[MatchCase] = &[
    MatchCase {
        pattern: "/",
        input: "/",
        expected: true,
    },
    MatchCase {
        pattern: "/",
        input: "/orders/42",
        expected: true,
    },
    MatchCase {
        pattern: "/admin",
        input: "/admin",
        expected: true,
    },
    MatchCase {
        pattern: "/admin",
        input: "/admin/assets/app.js",
        expected: true,
    },
    MatchCase {
        pattern: "/admin",
        input: "/administrator",
        expected: false,
    },
    MatchCase {
        pattern: "/admin",
        input: "/admin-panel",
        expected: false,
    },
    MatchCase {
        pattern: "/admin/",
        input: "/admin/child",
        expected: true,
    },
    MatchCase {
        pattern: "/admin/",
        input: "/admin",
        expected: false,
    },
    MatchCase {
        pattern: "/Admin",
        input: "/admin",
        expected: false,
    },
    MatchCase {
        pattern: "admin",
        input: "/admin",
        expected: false,
    },
    MatchCase {
        pattern: "",
        input: "/admin",
        expected: false,
    },
    MatchCase {
        pattern: "/admin",
        input: "",
        expected: false,
    },
    MatchCase {
        pattern: "/admin",
        input: "//admin/child",
        expected: false,
    },
    MatchCase {
        pattern: "/admin",
        input: LONG_PATH,
        expected: true,
    },
    MatchCase {
        pattern: "/admin/segment01/segment02",
        input: LONG_PATH,
        expected: true,
    },
    MatchCase {
        pattern: LONG_PATH,
        input: "/admin/short",
        expected: false,
    },
];

const RULE_CASES: &[MatchCase] = &[
    MatchCase {
        pattern: "/",
        input: "/",
        expected: true,
    },
    MatchCase {
        pattern: "/orders/42",
        input: "/orders/42",
        expected: true,
    },
    MatchCase {
        pattern: "/orders/42",
        input: "/orders/420",
        expected: false,
    },
    MatchCase {
        pattern: "/orders/*",
        input: "/orders/42",
        expected: true,
    },
    MatchCase {
        pattern: "/orders/*",
        input: "/orders/42/items",
        expected: false,
    },
    MatchCase {
        pattern: "/orders/{id}",
        input: "/orders/42",
        expected: true,
    },
    MatchCase {
        pattern: "/orders/{id}",
        input: "/orders/",
        expected: false,
    },
    MatchCase {
        pattern: "/orders/{bad-name}",
        input: "/orders/42",
        expected: false,
    },
    MatchCase {
        pattern: "/orders/**",
        input: "/orders",
        expected: true,
    },
    MatchCase {
        pattern: "/orders/**",
        input: "/orders/42/items/7",
        expected: true,
    },
    MatchCase {
        pattern: "/**/file.json",
        input: LONG_PATH,
        expected: true,
    },
    MatchCase {
        pattern: "/**/absent.json",
        input: LONG_PATH,
        expected: false,
    },
    MatchCase {
        pattern: "/admin/*/**/file.json",
        input: LONG_PATH,
        expected: true,
    },
    MatchCase {
        pattern: LONG_PATH,
        input: LONG_PATH,
        expected: true,
    },
    MatchCase {
        pattern: "orders/*",
        input: "/orders/42",
        expected: false,
    },
    MatchCase {
        pattern: "/orders/*",
        input: "orders/42",
        expected: false,
    },
];

const HOST_CASES: &[MatchCase] = &[
    MatchCase {
        pattern: "example.test",
        input: "example.test",
        expected: true,
    },
    MatchCase {
        pattern: "EXAMPLE.TEST",
        input: "example.test",
        expected: true,
    },
    MatchCase {
        pattern: "example.test",
        input: "EXAMPLE.TEST",
        expected: true,
    },
    MatchCase {
        pattern: "api.example.test",
        input: "other.example.test",
        expected: false,
    },
    MatchCase {
        pattern: "*.example.test",
        input: "api.example.test",
        expected: true,
    },
    MatchCase {
        pattern: "*.example.test",
        input: "one.two.example.test",
        expected: true,
    },
    MatchCase {
        pattern: "*.example.test",
        input: "example.test",
        expected: false,
    },
    MatchCase {
        pattern: "*.api.example.test",
        input: "badapi.example.test",
        expected: false,
    },
    MatchCase {
        pattern: "*.EXAMPLE.TEST",
        input: "API.EXAMPLE.TEST",
        expected: true,
    },
    MatchCase {
        pattern: "*.example.test",
        input: "api.example.test.",
        expected: false,
    },
    MatchCase {
        pattern: "api.*.example.test",
        input: "api.one.example.test",
        expected: false,
    },
    MatchCase {
        pattern: "*.example.test",
        input: "",
        expected: false,
    },
    MatchCase {
        pattern: "*.example.test",
        input: LONG_HOST,
        expected: true,
    },
    MatchCase {
        pattern: LONG_HOST,
        input: LONG_HOST,
        expected: true,
    },
    MatchCase {
        pattern: "*.other.example.test",
        input: LONG_HOST,
        expected: false,
    },
    MatchCase {
        pattern: LONG_HOST,
        input: "short.example.test",
        expected: false,
    },
];

fn decision(value: bool) -> u64 {
    // This opt-in fixture deliberately adds one allocation per operation. It
    // exists only to demonstrate that the comparison rejects a real regression;
    // normal reports must never compile with this configuration.
    #[cfg(regression_fixture)]
    {
        let allocation = vec![black_box(0_u8); black_box(64_usize)];
        black_box(allocation);
    }
    u64::from(black_box(value))
}

fn request_iteration() -> u64 {
    let mut checksum = 0;
    for case in REQUEST_CASES {
        checksum += decision(is_unsafe_request_path(black_box(case.path)));
        checksum += decision(exempt_path_matches(
            black_box(case.path),
            black_box(case.exempt),
        ));
    }
    checksum
}

fn prefix_iteration() -> u64 {
    let mut checksum = 0;
    for case in PREFIX_CASES {
        checksum += decision(path_prefix_matches(
            black_box(case.input),
            black_box(case.pattern),
        ));
    }
    checksum
}

fn rule_iteration(patterns: &[MicrobenchPreparedPattern]) -> u64 {
    let mut checksum = 0;
    for (case, pattern) in RULE_CASES.iter().zip(patterns) {
        checksum += decision(black_box(pattern).matches(black_box(case.input)));
    }
    checksum
}

fn host_iteration() -> u64 {
    let mut checksum = 0;
    for case in HOST_CASES {
        checksum += decision(selected_egress::microbench_host_matches(
            black_box(case.pattern),
            black_box(case.input),
        ));
    }
    checksum
}

#[derive(Clone, Copy, Default)]
struct AllocationSample {
    allocations: u64,
    allocated_bytes: u64,
    checksum: u64,
}

struct Report {
    id: &'static str,
    input_cases: usize,
    input_bytes: usize,
    operations_per_iteration: usize,
    expected_checksum: u64,
    allocation_samples: [AllocationSample; SAMPLES],
    timing_samples_ns: [u128; SAMPLES],
}

fn measure(
    id: &'static str,
    input_cases: usize,
    input_bytes: usize,
    operations_per_iteration: usize,
    expected_per_iteration: u64,
    mut iteration: impl FnMut() -> u64,
) -> Report {
    let mut warmup_checksum = 0;
    for _ in 0..WARMUP {
        warmup_checksum += black_box(iteration());
    }
    assert_eq!(
        warmup_checksum,
        expected_per_iteration * WARMUP,
        "{id} warmup"
    );

    let expected_checksum = expected_per_iteration * ITERATIONS;
    let mut allocation_samples = [AllocationSample::default(); SAMPLES];
    for sample in &mut allocation_samples {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        ALLOCATED_BYTES.store(0, Ordering::Relaxed);
        COUNTER_OVERFLOW.store(false, Ordering::Relaxed);
        COUNTING.store(true, Ordering::SeqCst);
        let mut checksum = 0;
        for _ in 0..ITERATIONS {
            checksum += black_box(iteration());
        }
        COUNTING.store(false, Ordering::SeqCst);
        assert!(
            !COUNTER_OVERFLOW.load(Ordering::Relaxed),
            "allocation counter overflow"
        );
        assert_eq!(checksum, expected_checksum, "{id} allocation checksum");
        *sample = AllocationSample {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            checksum,
        };
    }

    // Timings use a separate pass with counter updates disabled. The allocator
    // wrapper still checks the disabled flag; compare like-for-like runs only.
    let mut timing_samples_ns = [0; SAMPLES];
    for elapsed in &mut timing_samples_ns {
        let start = Instant::now();
        let mut checksum = 0;
        for _ in 0..ITERATIONS {
            checksum += black_box(iteration());
        }
        *elapsed = start.elapsed().as_nanos();
        assert_eq!(checksum, expected_checksum, "{id} timing checksum");
    }

    Report {
        id,
        input_cases,
        input_bytes,
        operations_per_iteration,
        expected_checksum,
        allocation_samples,
        timing_samples_ns,
    }
}

fn case_bytes(cases: &[MatchCase]) -> usize {
    cases
        .iter()
        .map(|case| case.pattern.len() + case.input.len())
        .sum()
}

fn expected(cases: &[MatchCase]) -> u64 {
    cases.iter().map(|case| u64::from(case.expected)).sum()
}

fn main() {
    let patterns: Vec<MicrobenchPreparedPattern> = RULE_CASES
        .iter()
        .map(|case| MicrobenchPreparedPattern::new(case.pattern))
        .collect();

    // Validate every expected decision individually before measuring, so two
    // opposite semantic mistakes cannot cancel out in the aggregate checksum.
    for case in REQUEST_CASES {
        assert_eq!(
            is_unsafe_request_path(case.path),
            case.unsafe_path,
            "request path preflight"
        );
        assert_eq!(
            exempt_path_matches(case.path, case.exempt),
            case.exempt_match,
            "exemption preflight"
        );
    }
    for case in PREFIX_CASES {
        assert_eq!(
            path_prefix_matches(case.input, case.pattern),
            case.expected,
            "prefix preflight"
        );
    }
    for (case, pattern) in RULE_CASES.iter().zip(&patterns) {
        assert_eq!(pattern.matches(case.input), case.expected, "rule preflight");
    }
    for case in HOST_CASES {
        assert_eq!(
            selected_egress::microbench_host_matches(case.pattern, case.input),
            case.expected,
            "host preflight"
        );
    }
    selected_rule::microbench_validate_method_matcher();

    let reports = [
        measure(
            "request_path",
            REQUEST_CASES.len(),
            REQUEST_CASES
                .iter()
                .map(|case| case.path.len() + case.exempt.len())
                .sum(),
            REQUEST_CASES.len() * 2,
            REQUEST_CASES
                .iter()
                .map(|case| u64::from(case.unsafe_path) + u64::from(case.exempt_match))
                .sum(),
            request_iteration,
        ),
        measure(
            "path_prefix",
            PREFIX_CASES.len(),
            case_bytes(PREFIX_CASES),
            PREFIX_CASES.len(),
            expected(PREFIX_CASES),
            prefix_iteration,
        ),
        measure(
            "rule_path",
            RULE_CASES.len(),
            case_bytes(RULE_CASES),
            RULE_CASES.len(),
            expected(RULE_CASES),
            || rule_iteration(&patterns),
        ),
        measure(
            "egress_host",
            HOST_CASES.len(),
            case_bytes(HOST_CASES),
            HOST_CASES.len(),
            expected(HOST_CASES),
            host_iteration,
        ),
    ];

    print!("{{\"schema_version\":1,\"warmup\":{WARMUP},\"iterations\":{ITERATIONS},\"samples\":{SAMPLES},\"targets\":[");
    for (index, report) in reports.iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        print!("{{\"id\":\"{}\",\"input_cases\":{},\"input_bytes\":{},\"operations_per_iteration\":{},\"expected_checksum\":{},\"allocation_samples\":[", report.id, report.input_cases, report.input_bytes, report.operations_per_iteration, report.expected_checksum);
        for (index, sample) in report.allocation_samples.iter().enumerate() {
            if index != 0 {
                print!(",");
            }
            print!(
                "{{\"allocations\":{},\"allocated_bytes\":{},\"checksum\":{}}}",
                sample.allocations, sample.allocated_bytes, sample.checksum
            );
        }
        print!("],\"timing_samples_ns\":[");
        for (index, elapsed) in report.timing_samples_ns.iter().enumerate() {
            if index != 0 {
                print!(",");
            }
            print!("{elapsed}");
        }
        print!("]}}");
    }
    println!("]}}");
}
