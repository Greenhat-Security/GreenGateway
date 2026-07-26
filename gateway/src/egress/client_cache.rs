use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use reqwest::Client;

use super::EgressError;
use crate::metrics::{
    EGRESS_CLIENT_CACHE_ENTRIES, EGRESS_CLIENT_CACHE_EVICTIONS_TOTAL,
    EGRESS_CLIENT_CACHE_REQUESTS_TOTAL, LOCK_POISON_RECOVERIES_TOTAL,
};

pub(super) const CLIENT_CACHE_MAX_ENTRIES: usize = 128;
pub(super) const CLIENT_CACHE_IDLE_TTL: Duration = Duration::from_secs(5 * 60);
pub(super) const CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub(super) const CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 8;
pub(super) const CLIENT_TCP_KEEPALIVE: Duration = Duration::from_secs(30);

const CLIENT_CACHE_SHARDS: usize = 16;
const CACHE_LOCK_COMPONENT: &str = "egress_client_cache";

static PROCESS_CACHE_ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct PinnedClientCacheKey {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub pinned_addr: SocketAddr,
    pub egress_generation: [u8; 32],
    pub request_timeout: Duration,
    pub response_idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub tls_root_set_fingerprint: [u8; 32],
    pub client_identity_fingerprint: Option<[u8; 32]>,
    pub protocol_profile: ProtocolProfile,
    pub outbound_proxy_policy: OutboundProxyPolicy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum ProtocolProfile {
    Http1AndHttp2,
    Sse,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum OutboundProxyPolicy {
    Disabled,
}

#[derive(Clone)]
struct CacheEntry {
    client: Client,
    last_used: Duration,
}

struct CacheShard {
    capacity: usize,
    entries: Mutex<HashMap<PinnedClientCacheKey, CacheEntry>>,
}

trait CacheClock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemCacheClock {
    started_at: Instant,
}

impl Default for SystemCacheClock {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl CacheClock for SystemCacheClock {
    fn now(&self) -> Duration {
        self.started_at.elapsed()
    }
}

pub(super) struct PinnedClientCache {
    shards: Vec<CacheShard>,
    idle_ttl: Duration,
    clock: Arc<dyn CacheClock>,
}

impl PinnedClientCache {
    pub(super) fn new() -> Self {
        Self::with_limits(
            CLIENT_CACHE_MAX_ENTRIES,
            CLIENT_CACHE_IDLE_TTL,
            Arc::new(SystemCacheClock::default()),
        )
    }

    fn with_limits(max_entries: usize, idle_ttl: Duration, clock: Arc<dyn CacheClock>) -> Self {
        assert!(max_entries > 0, "client cache capacity must be positive");
        assert!(
            !idle_ttl.is_zero(),
            "client cache idle lifetime must be positive"
        );

        let shard_count = CLIENT_CACHE_SHARDS.min(max_entries);
        let base_capacity = max_entries / shard_count;
        let extra_capacity = max_entries % shard_count;
        let shards = (0..shard_count)
            .map(|index| CacheShard {
                capacity: base_capacity + usize::from(index < extra_capacity),
                entries: Mutex::new(HashMap::new()),
            })
            .collect();

        Self {
            shards,
            idle_ttl,
            clock,
        }
    }

    pub(super) fn get_or_build<F>(
        &self,
        key: PinnedClientCacheKey,
        build: F,
    ) -> Result<Client, EgressError>
    where
        F: FnOnce() -> Result<Client, EgressError>,
    {
        let now = self.clock.now();
        let shard = self.shard_for(&key);
        let mut entries = lock_entries(shard);
        self.prune_idle(&mut entries, now);

        if let Some(entry) = entries.get_mut(&key) {
            entry.last_used = now;
            ::metrics::counter!(
                EGRESS_CLIENT_CACHE_REQUESTS_TOTAL,
                "result" => "hit"
            )
            .increment(1);
            return Ok(entry.client.clone());
        }

        // Client construction is synchronous and bounded. Holding only this
        // key's shard lock coordinates identical misses while unrelated
        // destination shards continue independently.
        let client = match build() {
            Ok(client) => client,
            Err(error) => {
                ::metrics::counter!(
                    EGRESS_CLIENT_CACHE_REQUESTS_TOTAL,
                    "result" => "build_error"
                )
                .increment(1);
                return Err(error);
            }
        };

        if entries.len() >= shard.capacity {
            if let Some(eviction_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&eviction_key);
                decrement_process_entry_count(1);
                ::metrics::counter!(
                    EGRESS_CLIENT_CACHE_EVICTIONS_TOTAL,
                    "reason" => "capacity"
                )
                .increment(1);
            }
        }

        entries.insert(
            key,
            CacheEntry {
                client: client.clone(),
                last_used: now,
            },
        );
        increment_process_entry_count(1);
        ::metrics::counter!(
            EGRESS_CLIENT_CACHE_REQUESTS_TOTAL,
            "result" => "miss"
        )
        .increment(1);

        Ok(client)
    }

    fn shard_for(&self, key: &PinnedClientCacheKey) -> &CacheShard {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.shards.len();
        &self.shards[index]
    }

    fn prune_idle(&self, entries: &mut HashMap<PinnedClientCacheKey, CacheEntry>, now: Duration) {
        let previous_len = entries.len();
        entries.retain(|_, entry| now.saturating_sub(entry.last_used) < self.idle_ttl);
        let removed = previous_len.saturating_sub(entries.len());
        if removed == 0 {
            return;
        }

        decrement_process_entry_count(removed);
        ::metrics::counter!(
            EGRESS_CLIENT_CACHE_EVICTIONS_TOTAL,
            "reason" => "idle"
        )
        .increment(removed as u64);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| lock_entries(shard).len())
            .sum()
    }
}

impl Drop for PinnedClientCache {
    fn drop(&mut self) {
        let entry_count: usize = self
            .shards
            .iter()
            .map(|shard| lock_entries(shard).len())
            .sum();
        decrement_process_entry_count(entry_count);
    }
}

fn lock_entries(shard: &CacheShard) -> MutexGuard<'_, HashMap<PinnedClientCacheKey, CacheEntry>> {
    match shard.entries.lock() {
        Ok(entries) => entries,
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => CACHE_LOCK_COMPONENT,
                "lock" => "shard"
            )
            .increment(1);
            tracing::error!("egress client cache shard lock poisoned; recovering");
            poisoned.into_inner()
        }
    }
}

fn increment_process_entry_count(count: usize) {
    if count == 0 {
        return;
    }
    let total = PROCESS_CACHE_ENTRY_COUNT
        .fetch_add(count, Ordering::Relaxed)
        .saturating_add(count);
    ::metrics::gauge!(EGRESS_CLIENT_CACHE_ENTRIES).set(total as f64);
}

fn decrement_process_entry_count(count: usize) {
    if count == 0 {
        return;
    }

    let mut current = PROCESS_CACHE_ENTRY_COUNT.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(count);
        match PROCESS_CACHE_ENTRY_COUNT.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                ::metrics::gauge!(EGRESS_CLIENT_CACHE_ENTRIES).set(next as f64);
                break;
            }
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ptr,
        sync::{atomic::AtomicU64, Barrier},
        thread,
    };

    use super::*;

    #[derive(Default)]
    struct FakeCacheClock {
        millis: AtomicU64,
    }

    impl FakeCacheClock {
        fn advance(&self, duration: Duration) {
            self.millis.fetch_add(
                u64::try_from(duration.as_millis()).expect("test duration should fit u64"),
                Ordering::SeqCst,
            );
        }
    }

    impl CacheClock for FakeCacheClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
    }

    fn key(id: u8) -> PinnedClientCacheKey {
        PinnedClientCacheKey {
            scheme: "https".to_owned(),
            host: format!("endpoint-{id}.example.test"),
            port: 443,
            pinned_addr: SocketAddr::from(([8, 8, 8, id], 443)),
            egress_generation: [id; 32],
            request_timeout: Duration::from_secs(30),
            response_idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            tls_root_set_fingerprint: [0; 32],
            client_identity_fingerprint: None,
            protocol_profile: ProtocolProfile::Http1AndHttp2,
            outbound_proxy_policy: OutboundProxyPolicy::Disabled,
        }
    }

    fn client() -> Client {
        Client::builder()
            .no_proxy()
            .build()
            .expect("test client should build")
    }

    #[test]
    fn identical_key_reuses_one_client_build() {
        let clock = Arc::new(FakeCacheClock::default());
        let cache = PinnedClientCache::with_limits(4, Duration::from_secs(30), clock.clone());
        let builds = AtomicUsize::new(0);

        let first = cache
            .get_or_build(key(1), || {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(client())
            })
            .expect("first client should build");
        let second = cache
            .get_or_build(key(1), || {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(client())
            })
            .expect("second client should reuse");

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
        drop((first, second));
    }

    #[test]
    fn capacity_is_hard_and_evicts_least_recently_used_entry() {
        let clock = Arc::new(FakeCacheClock::default());
        let cache = PinnedClientCache::with_limits(2, Duration::from_secs(30), clock.clone());

        cache
            .get_or_build(key(1), || Ok(client()))
            .expect("first client should build");
        clock.advance(Duration::from_millis(1));
        cache
            .get_or_build(key(2), || Ok(client()))
            .expect("second client should build");
        clock.advance(Duration::from_millis(1));
        cache
            .get_or_build(key(3), || Ok(client()))
            .expect("third client should build after eviction");

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn idle_entries_are_removed_before_reuse() {
        let clock = Arc::new(FakeCacheClock::default());
        let cache = PinnedClientCache::with_limits(2, Duration::from_secs(5), clock.clone());
        let builds = AtomicUsize::new(0);

        cache
            .get_or_build(key(1), || {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(client())
            })
            .expect("first client should build");
        clock.advance(Duration::from_secs(5));
        cache
            .get_or_build(key(1), || {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(client())
            })
            .expect("expired client should rebuild");

        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn concurrent_identical_misses_build_once() {
        let clock = Arc::new(FakeCacheClock::default());
        let cache = Arc::new(PinnedClientCache::with_limits(
            16,
            Duration::from_secs(30),
            clock,
        ));
        let start = Arc::new(Barrier::new(3));
        let builds = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();

        for _ in 0..2 {
            let cache = Arc::clone(&cache);
            let start = Arc::clone(&start);
            let builds = Arc::clone(&builds);
            workers.push(thread::spawn(move || {
                start.wait();
                cache
                    .get_or_build(key(1), || {
                        builds.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(25));
                        Ok(client())
                    })
                    .expect("concurrent identical client should build or reuse");
            }));
        }

        start.wait();
        for worker in workers {
            worker.join().expect("cache worker should finish");
        }

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn unrelated_shards_do_not_share_one_build_lock() {
        let clock = Arc::new(FakeCacheClock::default());
        let cache = Arc::new(PinnedClientCache::with_limits(
            16,
            Duration::from_secs(30),
            clock,
        ));
        let first_key = key(1);
        let second_key = (2..=u8::MAX)
            .map(key)
            .find(|candidate| !ptr::eq(cache.shard_for(&first_key), cache.shard_for(candidate)))
            .expect("test should find a key in another shard");
        let start = Arc::new(Barrier::new(3));
        let active_builds = Arc::new(AtomicUsize::new(0));
        let maximum_active_builds = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();

        for cache_key in [first_key, second_key] {
            let cache = Arc::clone(&cache);
            let start = Arc::clone(&start);
            let active_builds = Arc::clone(&active_builds);
            let maximum_active_builds = Arc::clone(&maximum_active_builds);
            workers.push(thread::spawn(move || {
                start.wait();
                cache
                    .get_or_build(cache_key, || {
                        let active = active_builds.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum_active_builds.fetch_max(active, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        active_builds.fetch_sub(1, Ordering::SeqCst);
                        Ok(client())
                    })
                    .expect("unrelated client should build");
            }));
        }

        start.wait();
        for worker in workers {
            worker.join().expect("cache worker should finish");
        }

        assert_eq!(
            maximum_active_builds.load(Ordering::SeqCst),
            2,
            "unrelated shards must build independently"
        );
    }
}
