//! Dedicated advisory-lock sessions (issue #241, PR 13, section 5).
//!
//! A [`DedicatedSession`] is one pooled connection held for the lifetime
//! of a piece of singleton work, with a session-scoped advisory lock
//! (`pg_try_advisory_lock`) taken on it at the start and released at the
//! end. It is the belt alongside the lease's braces: the maintenance
//! lease (`execution_leases`, scope `maintenance`) already admits one
//! leader, and the fence on every ledger write already refuses a stale
//! one; the advisory lock adds a database-enforced guarantee that two
//! processes cannot run the same singleton work at the same instant even
//! if a lease were ever mis-adjudicated, and that losing the connection
//! is noticed rather than silently ignored.
//!
//! That guarantee holds only for statements that run *on this
//! connection* ([`DedicatedSession::client`]): a session lock is released
//! when the session ends, and the server ends a session only once the
//! statement it is running has finished, so a step run here is covered
//! for as long as it runs even if the client side is cancelled mid-way.
//! A statement run on some other pooled connection is not covered at all
//! -- the lock could be released while it runs -- which is why the
//! maintenance runner hands every job the session's client rather than
//! the pool.
//!
//! What is stored: nothing. The lock lives in the server's lock table for
//! as long as the session does. What is held: the connection, which is
//! why the helper is strict about how the connection leaves:
//!
//! - **A clean end** ([`DedicatedSession::release`]) unlocks and lets the
//!   connection return to the pool.
//! - **Any failure** -- the lock statement, a probe, the unlock -- marks
//!   the session broken and *detaches* the connection from the pool
//!   (`deadpool_postgres::Object::take`) so it closes instead of being
//!   recycled while possibly still holding the lock. A session-scoped
//!   advisory lock on a recycled connection would be held by whichever
//!   request checked that connection out next, invisibly and for as long
//!   as the pool kept it; closing the connection is the only release the
//!   server guarantees.
//! - **A drop without release** (the job's future was cancelled: the
//!   lease was lost, or the lifecycle is draining) detaches the connection
//!   for the same reason. Nothing is remembered, nothing dangles.
//!
//! The last of those is the one that has to be *structural* rather than
//! remembered, because cancellation is not a path anybody writes: it is
//! every `await`, at once. So the connection is owned by a
//! [`DedicatedSession`] -- the thing whose [`Drop`] detaches -- from the
//! moment it is checked out until the server has answered an unlock, and
//! never sits in a local across an `await` in between. A connection in a
//! local is returned to the pool by deadpool's own `Drop`, and the pool
//! recycles with `ROLLBACK` (see `postgres::build_pool`), which ends a
//! transaction and releases nothing else: a connection recycled while
//! holding a session lock holds it for as long as the pool lives, and
//! every later pass is answered `Conflict` for ever. That is the wedge
//! the two cancellation tests below exist to keep shut.
//!
//! The lock is *tried*, never waited for: a session that finds the key
//! held answers [`RepositoryErrorKind::Conflict`], and the caller runs
//! nothing. Waiting would only be correct if the lease had failed, and in
//! that case running second is exactly the wrong outcome.
//!
//! Lock keys are derived from a name the same way the migration and audit
//! stream locks are (`SHA-256(name)[..8]`, sign bit cleared), pinned by
//! tests so two binaries cannot drift onto different keys.

use sha2::{Digest, Sha256};

use super::{
    log_classified,
    postgres::{checkout, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_LOCK: &str = "dedicated_session_lock";
const OPERATION_PROBE: &str = "dedicated_session_probe";
const OPERATION_UNLOCK: &str = "dedicated_session_unlock";

/// Derive a session advisory-lock key from a name: the first eight bytes
/// of `SHA-256(name)` with the sign bit cleared, as the migration and audit
/// stream locks do.
pub(crate) fn advisory_lock_key(name: &str) -> i64 {
    let digest = Sha256::digest(name.as_bytes());
    let mut value = [0_u8; 8];
    value.copy_from_slice(&digest[..8]);
    value[0] &= 0x7f;
    i64::from_be_bytes(value)
}

/// One pooled connection holding one session advisory lock.
pub struct DedicatedSession {
    /// `None` once the connection has left (released to the pool, or
    /// detached and closed).
    client: Option<deadpool_postgres::Object>,
    key: i64,
}

impl DedicatedSession {
    /// Check a connection out and try the lock on it. `Conflict` means
    /// another session holds the key -- the caller must not run.
    ///
    /// The connection is put inside a session *before* the lock statement
    /// is sent, and not for tidiness: the statement is an `await`, and a
    /// caller that is cancelled there (the maintenance runner races every
    /// pass against its lease, and opening the session is the pass's first
    /// act) drops this future wherever it is parked. Held in a local, the
    /// connection would then go back to the pool by its ordinary `Drop` --
    /// possibly with the lock already granted by the server and the answer
    /// still on the wire. Held by a session, every such drop goes through
    /// [`Drop`] and detaches instead.
    pub async fn acquire(
        pool: &deadpool_postgres::Pool,
        key: i64,
    ) -> Result<Self, RepositoryError> {
        let client = checkout(pool, CheckoutClass::Maintenance).await?;
        // From here to the end of this function the connection has exactly
        // one owner, and that owner detaches it on every path out but the
        // two that are provably clean.
        let mut session = Self {
            client: Some(client),
            key,
        };
        let row = {
            let client = session
                .client
                .as_ref()
                .expect("the session was just given its connection");
            client
                .query_one("SELECT pg_try_advisory_lock($1) AS locked", &[&key])
                .await
        };
        let row = match row {
            Ok(row) => row,
            // Dropping `session` detaches: the statement may have taken
            // the lock before it failed.
            Err(error) => return Err(classify_query(error, OPERATION_LOCK)),
        };
        let locked: bool = match row.try_get("locked") {
            Ok(locked) => locked,
            Err(_) => {
                return Err(RepositoryError::new(
                    RepositoryErrorKind::InvalidData,
                    OPERATION_LOCK,
                ))
            }
        };
        if !locked {
            // Nothing was taken -- the server said so -- and there is no
            // await between here and the return, so the connection is as
            // clean as it came and goes back to the pool.
            drop(session.client.take());
            return Err(RepositoryError::new(
                RepositoryErrorKind::Conflict,
                OPERATION_LOCK,
            ));
        }
        Ok(session)
    }

    /// The connection holding the lock, for the work the lock protects to
    /// run its statements on. A statement that runs here is covered by the
    /// lock for as long as it runs -- the server releases a session lock
    /// only when the session ends, and a session ends only once its
    /// statement in flight has -- and losing the connection fails that
    /// statement rather than going unnoticed. `None` once the session is
    /// broken.
    pub fn client(&self) -> Option<&tokio_postgres::Client> {
        self.client
            .as_ref()
            .map(|client| -> &tokio_postgres::Client { client })
    }

    /// Confirm the connection (and so the lock) is still alive. An error
    /// breaks the session: the connection is detached, and the caller
    /// must cancel the work the lock was protecting.
    pub async fn probe(&mut self) -> Result<(), RepositoryError> {
        let Some(client) = self.client.as_ref() else {
            return Err(RepositoryError::new(
                RepositoryErrorKind::Unavailable,
                OPERATION_PROBE,
            ));
        };
        if let Err(error) = client.simple_query("SELECT 1").await {
            if let Some(client) = self.client.take() {
                detach(client);
            }
            return Err(classify_query(error, OPERATION_PROBE));
        }
        Ok(())
    }

    /// Unlock and return the connection to the pool. On a failed unlock
    /// the connection is closed instead, which releases the lock anyway.
    ///
    /// The connection stays inside `self` for the whole round trip and
    /// leaves only once the server has answered the unlock. Taking it out
    /// first would put it in a local across an `await`, and a release
    /// cancelled there -- the runner's `select!` can drop the pass at its
    /// last act as readily as at its first -- would hand a connection that
    /// is still holding the lock back to the pool.
    pub async fn release(mut self) -> Result<(), RepositoryError> {
        if self.client.is_none() {
            return Ok(());
        }
        let unlocked = {
            let client = self
                .client
                .as_ref()
                .expect("the session still holds its connection");
            client
                .execute("SELECT pg_advisory_unlock($1)", &[&self.key])
                .await
        };
        match unlocked {
            Ok(_) => {
                // The server has released the lock, so the connection is
                // clean and may be recycled.
                drop(self.client.take());
                Ok(())
            }
            // Dropping `self` detaches: the unlock did not land.
            Err(error) => Err(classify_query(error, OPERATION_UNLOCK)),
        }
    }
}

impl Drop for DedicatedSession {
    fn drop(&mut self) {
        // Reached only when `release` was not called: the work was
        // cancelled mid-flight. The lock may still be held on this
        // connection, so it must not go back into the pool.
        if let Some(client) = self.client.take() {
            detach(client);
        }
    }
}

/// Take the connection out of the pool for good: dropping the bare client
/// closes the session, and the server releases every lock it held.
fn detach(client: deadpool_postgres::Object) {
    drop(deadpool_postgres::Object::take(client));
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

// `pub(crate)` so the migrator's tests (`storage::migrations`) place their
// cancellation windows with the same reply gate and ask the server the same
// questions, instead of carrying a second copy of this harness.
#[cfg(test)]
pub(crate) mod tests {
    use super::advisory_lock_key;

    #[test]
    fn lock_keys_are_derived_from_the_name_and_never_negative() {
        let key = advisory_lock_key("greengateway.maintenance");
        assert!(key >= 0);
        assert_eq!(key, advisory_lock_key("greengateway.maintenance"));
        assert_ne!(key, advisory_lock_key("greengateway.audit-stream"));
        // The audit stream key is derived the same way (postgres_audit.rs).
        assert_eq!(
            advisory_lock_key("greengateway.audit-stream"),
            *crate::storage::postgres_audit::AUDIT_STREAM_LOCK_KEY
        );
    }

    // --- real-database tests ------------------------------------------
    //
    // Cancellation safety cannot be argued from the client's side: the
    // only authority on whether a session lock is still held is the
    // server's own lock table. These tests cancel a session's future at a
    // named point and then ask `pg_locks` -- and, when the key is still
    // held, `pg_stat_activity` -- what the server thinks. Gated on the
    // same harness locator as the rest of the storage suite; a checkout
    // without a database skips rather than fails.
    //
    // The named point is placed, not raced for. A cancellation window is
    // the time between the client sending a statement and hearing the
    // answer, and on a real connection that is however long the network
    // and two schedulers happen to take: a test that polls for the window
    // and hopes to stop inside it reaches it on a quiet machine and
    // overshoots it on a loaded one. So the test pool's connections run
    // behind a [`ReplyGate`]. The client's messages reach the server
    // unchanged; once the test arms the gate for a message type, nothing
    // the server says after the client sends that message reaches the
    // client. The statement runs on the server for real -- the lock is
    // granted, or the unlock is never sent -- and the future under test
    // cannot hear about it, so it stays parked in the window for exactly
    // as long as the test decides.

    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{ready, Context, Poll, Waker},
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::DedicatedSession;

    /// How long a cancelled session's key may still be held. A detached
    /// connection closes as soon as the statement it had in flight ends,
    /// and these statements are a lock and an unlock: milliseconds. The
    /// budget is generous only so a loaded CI box does not fail on
    /// scheduling.
    pub(crate) const RELEASE_BUDGET: Duration = Duration::from_secs(15);

    /// How long the server may take to answer the statement whose answer
    /// the gate is withholding. Generous for the same reason; it bounds a
    /// gate that never closes, not the window, which lasts as long as the
    /// test holds it.
    pub(crate) const ANSWER_BUDGET: Duration = Duration::from_secs(20);

    /// PostgreSQL wire-protocol message types the gate acts on. From the
    /// client: `Parse` (the first half of a prepared statement), `Bind`
    /// (the second half, sent with `Execute` only once `Parse` has been
    /// answered), and the two messages each answered by exactly one
    /// `ReadyForQuery`: a simple `Query` and a `Sync`. From the server:
    /// `ReadyForQuery`, sent once everything up to that point is done.
    pub(crate) const PARSE: u8 = b'P';
    pub(crate) const BIND: u8 = b'B';
    pub(crate) const QUERY: u8 = b'Q';
    pub(crate) const SYNC: u8 = b'S';
    pub(crate) const READY_FOR_QUERY: u8 = b'Z';

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GatePhase {
        /// The server's replies pass.
        Open,
        /// The server's replies pass until a client sends a message of
        /// type `tag` with `skip` such messages already behind it: the
        /// `skip + 1`-th one from the moment the gate was armed.
        Armed { tag: u8, skip: usize },
        /// A client has sent it; nothing the server says reaches the
        /// client. `answered` once the server has finished the statement
        /// that message began.
        Holding { answered: bool },
    }

    /// The switch every connection of a gated pool shares.
    #[derive(Clone)]
    pub(crate) struct ReplyGate {
        phase: Arc<tokio::sync::watch::Sender<GatePhase>>,
        /// Connection tasks waiting for the gate to open.
        parked: Arc<Mutex<Vec<Waker>>>,
    }

    impl ReplyGate {
        pub(crate) fn new() -> Self {
            Self {
                phase: Arc::new(tokio::sync::watch::channel(GatePhase::Open).0),
                parked: Arc::default(),
            }
        }

        /// Withhold the server's replies from the moment a client next
        /// sends a message of type `tag`.
        pub(crate) fn hold_replies_from(&self, tag: u8) {
            self.hold_replies_from_nth(tag, 1);
        }

        /// Withhold the server's replies from the moment a client sends
        /// the `nth` message of type `tag` from now (1-based), for a
        /// statement that follows others of the same kind -- a simple
        /// `Query` after the session setup that precedes it. The messages
        /// before it are answered as usual.
        pub(crate) fn hold_replies_from_nth(&self, tag: u8, nth: usize) {
            assert!(nth > 0, "the first message is the 1st");
            self.phase
                .send_replace(GatePhase::Armed { tag, skip: nth - 1 });
        }

        /// Let everything withheld through, and everything after it.
        pub(crate) fn open(&self) {
            self.phase.send_replace(GatePhase::Open);
            let parked = std::mem::take(
                &mut *self
                    .parked
                    .lock()
                    .expect("the gate's waker list is never poisoned"),
            );
            for waker in parked {
                waker.wake();
            }
        }

        /// Resolves once the server has finished the statement whose
        /// answer is being withheld.
        pub(crate) async fn answered(&self) {
            self.phase
                .subscribe()
                .wait_for(|phase| matches!(phase, GatePhase::Holding { answered: true }))
                .await
                .expect("the gate outlives every wait on it");
        }

        fn holding(&self) -> bool {
            matches!(*self.phase.borrow(), GatePhase::Holding { .. })
        }

        /// A client is sending a message of type `tag`; true if that is
        /// the message the gate was armed for, which closes it.
        fn client_sends(&self, tag: u8) -> bool {
            self.phase.send_if_modified(|phase| {
                let GatePhase::Armed { tag: armed, skip } = phase else {
                    return false;
                };
                if *armed != tag {
                    return false;
                }
                if *skip > 0 {
                    // An earlier message of the same type: it and its
                    // answer pass. Nobody waits on the count, so nobody
                    // is told.
                    *skip -= 1;
                    return false;
                }
                *phase = GatePhase::Holding { answered: false };
                true
            })
        }

        /// The withheld replies now include the server's answer.
        fn server_answered(&self) {
            self.phase.send_if_modified(|phase| {
                let first = matches!(phase, GatePhase::Holding { answered: false });
                if first {
                    *phase = GatePhase::Holding { answered: true };
                }
                first
            });
        }

        /// Wake `waker` when the gate opens. The phase is checked again
        /// after parking, so an `open` racing the caller is not missed.
        fn park(&self, waker: &Waker) {
            {
                let mut parked = self
                    .parked
                    .lock()
                    .expect("the gate's waker list is never poisoned");
                if !parked.iter().any(|known| known.will_wake(waker)) {
                    parked.push(waker.clone());
                }
            }
            if !self.holding() {
                waker.wake_by_ref();
            }
        }
    }

    /// Message boundaries in one direction of a PostgreSQL connection.
    /// Every message is a type byte and a big-endian length that counts
    /// itself but not the type byte -- except the client's first message
    /// (startup), which has no type byte.
    struct Framing {
        untyped_first: bool,
        header: Vec<u8>,
        remaining: usize,
    }

    impl Framing {
        fn client() -> Self {
            Self {
                untyped_first: true,
                header: Vec::with_capacity(5),
                remaining: 0,
            }
        }

        fn server() -> Self {
            Self {
                untyped_first: false,
                ..Self::client()
            }
        }

        /// Walk the next `bytes` of the stream, reporting the type of every
        /// message that starts in them, in order.
        fn scan(&mut self, mut bytes: &[u8], mut started: impl FnMut(u8)) {
            while !bytes.is_empty() {
                if self.remaining > 0 {
                    let body = self.remaining.min(bytes.len());
                    self.remaining -= body;
                    bytes = &bytes[body..];
                    continue;
                }
                let header_len = if self.untyped_first { 4 } else { 5 };
                let take = (header_len - self.header.len()).min(bytes.len());
                self.header.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.header.len() < header_len {
                    return;
                }
                let (tag, length) = self.header.split_at(header_len - 4);
                let length = u32::from_be_bytes(length.try_into().expect("a length is four bytes"));
                self.remaining = usize::try_from(length)
                    .expect("a u32 fits in a usize")
                    .saturating_sub(4);
                if let Some(&tag) = tag.first() {
                    started(tag);
                }
                self.untyped_first = false;
                self.header.clear();
            }
        }
    }

    /// One pooled connection's socket, behind the gate.
    struct GatedStream {
        socket: tokio::net::TcpStream,
        gate: ReplyGate,
        sent: Framing,
        received: Framing,
        /// `ReadyForQuery` messages the client has asked for (one for
        /// startup, one per `Query` or `Sync`), and those that arrived.
        ready_owed: u64,
        ready_arrived: u64,
        /// The `ReadyForQuery` that completes the answer this connection's
        /// gate is withholding -- the one owed for the first `Sync` or
        /// `Query` from the gated message on, so an earlier statement's
        /// late `ReadyForQuery` is not mistaken for it.
        answer_at: Option<u64>,
        /// What the server said while the gate was holding.
        withheld: Vec<u8>,
    }

    impl GatedStream {
        fn new(socket: tokio::net::TcpStream, gate: ReplyGate) -> Self {
            Self {
                socket,
                gate,
                sent: Framing::client(),
                received: Framing::server(),
                ready_owed: 1,
                ready_arrived: 0,
                answer_at: None,
                withheld: Vec::new(),
            }
        }

        fn note_received(&mut self, bytes: &[u8]) {
            let Self {
                received,
                gate,
                ready_arrived,
                answer_at,
                ..
            } = self;
            received.scan(bytes, |tag| {
                if tag != READY_FOR_QUERY {
                    return;
                }
                *ready_arrived += 1;
                if answer_at.is_some_and(|at| *ready_arrived >= at) {
                    *answer_at = None;
                    gate.server_answered();
                }
            });
        }
    }

    impl AsyncRead for GatedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            loop {
                if !this.gate.holding() {
                    if !this.withheld.is_empty() {
                        let given = this.withheld.len().min(buf.remaining());
                        buf.put_slice(&this.withheld[..given]);
                        this.withheld.drain(..given);
                        return Poll::Ready(Ok(()));
                    }
                    let before = buf.filled().len();
                    ready!(Pin::new(&mut this.socket).poll_read(cx, buf))?;
                    this.note_received(&buf.filled()[before..]);
                    return Poll::Ready(Ok(()));
                }
                // Holding: keep reading, so the answer is noticed when it
                // arrives, but give the client none of it.
                let mut space = [0_u8; 1024];
                let mut chunk = ReadBuf::new(&mut space);
                match Pin::new(&mut this.socket).poll_read(cx, &mut chunk) {
                    Poll::Ready(Ok(())) if !chunk.filled().is_empty() => {
                        this.withheld.extend_from_slice(chunk.filled());
                        this.note_received(chunk.filled());
                    }
                    // Nothing more for now, or the server hung up: either
                    // way the client hears of it once the gate opens.
                    Poll::Ready(Ok(())) | Poll::Pending => {
                        this.gate.park(cx.waker());
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }
        }
    }

    impl AsyncWrite for GatedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let written = ready!(Pin::new(&mut this.socket).poll_write(cx, buf))?;
            // The bytes are on their way to the server, and the gate
            // closes before this task can next read: nothing the server
            // says to them reaches the client while it holds.
            let Self {
                sent,
                gate,
                ready_owed,
                answer_at,
                ..
            } = this;
            sent.scan(&buf[..written], |tag| {
                if gate.client_sends(tag) {
                    *answer_at = Some(*ready_owed + 1);
                }
                if tag == QUERY || tag == SYNC {
                    *ready_owed += 1;
                }
            });
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().socket).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
        }
    }

    type Connecting<'a> = Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (tokio_postgres::Client, tokio::task::JoinHandle<()>),
                        tokio_postgres::Error,
                    >,
                > + Send
                + 'a,
        >,
    >;

    /// Opens a pool's connections the way `tokio_postgres` does for a TCP
    /// host, with each socket behind the gate.
    struct GatedConnect(ReplyGate);

    impl deadpool_postgres::Connect for GatedConnect {
        fn connect(&self, config: &tokio_postgres::Config) -> Connecting<'_> {
            let gate = self.0.clone();
            let config = config.clone();
            Box::pin(async move {
                let Some(tokio_postgres::config::Host::Tcp(host)) = config.get_hosts().first()
                else {
                    panic!("the reply gate wraps a TCP socket; the test DSN must name a TCP host");
                };
                let port = config.get_ports().first().copied().unwrap_or(5432);
                let socket = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .expect("the test database accepts a gated connection");
                let (client, connection) = config
                    .connect_raw(GatedStream::new(socket, gate), tokio_postgres::NoTls)
                    .await?;
                let task = tokio::spawn(async move {
                    let _ = connection.await;
                });
                Ok((client, task))
            })
        }
    }

    fn real_dsn() -> Option<String> {
        // Read through a runtime key, exactly as `postgres.rs` and
        // `contract_tests.rs` do: the configuration-drift test walks the
        // `env::var` literals under `gateway/src` to keep the operator's
        // reference complete, and this locator is harness plumbing, not
        // an operator setting.
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    /// A pool that recycles the way the production pool does
    /// (`RecyclingMethod::Custom("ROLLBACK")`, see `postgres::build_pool`),
    /// over connections behind `gate`. The recycling detail is the whole
    /// point: `ROLLBACK` ends a transaction and releases nothing else, so a
    /// connection handed back to the pool while it holds a session advisory
    /// lock keeps holding it for as long as the pool keeps the connection
    /// -- which is for ever.
    pub(crate) fn gated_pool(dsn: &str, gate: &ReplyGate) -> deadpool_postgres::Pool {
        let config: tokio_postgres::Config = dsn.parse().expect("the test DSN parses");
        let manager = deadpool_postgres::Manager::from_connect(
            config,
            GatedConnect(gate.clone()),
            deadpool_postgres::ManagerConfig {
                recycling_method: deadpool_postgres::RecyclingMethod::Custom("ROLLBACK".to_owned()),
            },
        );
        deadpool_postgres::Pool::builder(manager)
            .max_size(4)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .expect("the test pool builds")
    }

    /// A connection outside the pool, so the observation is never made by
    /// the thing being observed.
    pub(crate) async fn observer(dsn: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .expect("the observer connects");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    /// What the server says about every backend granted `key` as a
    /// session advisory lock in the observer's database: pid, backend
    /// state, wait event, and the query it last ran. A holder that is
    /// `active` on a statement is a pass still running; a holder that is
    /// `idle` on `ClientRead` is a connection sitting in the pool with the
    /// lock on it.
    pub(crate) async fn holders(observer: &tokio_postgres::Client, key: i64) -> Vec<String> {
        advisory_backends(observer, key, true).await
    }

    /// The same for every backend queued for `key` and not yet granted it:
    /// a blocking `pg_advisory_lock` waiting behind a holder.
    pub(crate) async fn waiters(observer: &tokio_postgres::Client, key: i64) -> Vec<String> {
        advisory_backends(observer, key, false).await
    }

    async fn advisory_backends(
        observer: &tokio_postgres::Client,
        key: i64,
        granted: bool,
    ) -> Vec<String> {
        // The bigint form of an advisory lock is stored split across
        // `classid` (high half) and `objid` (low half), with
        // `objsubid = 1`. An advisory lock belongs to a database, and the
        // observer's is the one under test: a fixed key such as the
        // migrator's is taken in every other test database as well.
        let rows = observer
            .query(
                "SELECT l.pid, \
                        coalesce(a.state, '<gone>'), \
                        coalesce(a.wait_event_type || ':' || a.wait_event, '<none>'), \
                        coalesce(a.query, '<none>') \
                 FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
                 WHERE l.locktype = 'advisory' AND l.granted = $2 AND l.objsubid = 1 \
                   AND l.database = (SELECT oid FROM pg_database \
                                     WHERE datname = current_database()) \
                   AND ((l.classid::bigint << 32) | l.objid::bigint) = $1",
                &[&key, &granted],
            )
            .await
            .expect("pg_locks is readable");
        rows.iter()
            .map(|row| {
                format!(
                    "pid {} state={} wait={} query={:?}",
                    row.get::<_, i32>(0),
                    row.get::<_, &str>(1),
                    row.get::<_, &str>(2),
                    row.get::<_, &str>(3),
                )
            })
            .collect()
    }

    /// Wait for `key` to be free the way the next pass would find it, by
    /// asking for it: the server grants the observer's blocking
    /// `pg_advisory_lock` the instant the last holder lets go -- here, the
    /// instant a detached connection's session ends -- and refuses it
    /// once `RELEASE_BUDGET` has gone by, at which point the server is
    /// asked what is holding the key.
    pub(crate) async fn assert_released(
        observer: &tokio_postgres::Client,
        key: i64,
        what: &str,
    ) -> Duration {
        let started = Instant::now();
        observer
            .batch_execute(&format!(
                "SET lock_timeout = {}",
                RELEASE_BUDGET.as_millis()
            ))
            .await
            .expect("the observer bounds its wait");
        match observer
            .execute("SELECT pg_advisory_lock($1)", &[&key])
            .await
        {
            Ok(_) => {
                let elapsed = started.elapsed();
                observer
                    .execute("SELECT pg_advisory_unlock($1)", &[&key])
                    .await
                    .expect("the observer gives the key back");
                elapsed
            }
            Err(error) => {
                let refusal = error.as_db_error().map_or_else(
                    || error.to_string(),
                    |db| format!("{}: {}", db.code().code(), db.message()),
                );
                let held = holders(observer, key).await;
                panic!(
                    "the advisory key was still held {:?} after {what} ({refusal}); the server \
                     says: {}\n\
                     A holder that is idle on ClientRead is a pooled connection that went back \
                     into the pool with the lock on it: every later pass is answered Conflict, \
                     for ever, and the deployment's housekeeping stops.",
                    started.elapsed(),
                    held.join(" | ")
                );
            }
        }
    }

    /// Drive `future` until the server has finished the statement whose
    /// answer the gate is withholding. The future cannot complete first --
    /// that would mean it heard an answer the gate is holding -- so when
    /// this returns it is parked in the window: its statement has run on
    /// the server, and it does not know.
    pub(crate) async fn drive_into_window<F: Future>(
        gate: &ReplyGate,
        future: Pin<&mut F>,
        what: &str,
    ) {
        let parked = tokio::time::timeout(ANSWER_BUDGET, async {
            tokio::select! {
                biased;
                _ = future => false,
                () = gate.answered() => true,
            }
        })
        .await;
        match parked {
            Ok(true) => {}
            Ok(false) => panic!(
                "{what} completed without needing an answer the gate was holding: it never sent \
                 the message the gate was armed for, so this test is not stopping where it says"
            ),
            Err(_) => panic!(
                "the server did not answer {what}'s withheld statement within {ANSWER_BUDGET:?}"
            ),
        }
    }

    /// Cancelling a pass in the window where the server has granted the
    /// lock but the client has not yet been told must not leave the key
    /// held.
    ///
    /// This is the window a lost lease actually lands in: `run_pass`
    /// opens its dedicated session as its first act, and the `select!`
    /// that races the pass against `lost.cancelled()` drops the pass
    /// future wherever it happens to be parked. The test does not wait
    /// for luck: the gate withholds the answer to the lock statement, so
    /// the acquire is parked in the window from the moment the server
    /// grants the lock until the test drops it there.
    #[tokio::test]
    async fn a_cancelled_acquire_does_not_leave_the_key_held() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let gate = ReplyGate::new();
        let pool = gated_pool(&dsn, &gate);
        let observer = observer(&dsn).await;
        let key = advisory_lock_key(&format!(
            "greengateway.test.cancelled-acquire.{}",
            uuid::Uuid::new_v4().simple()
        ));

        // Warm the pool, so the acquire recycles a connection the way a
        // pass does.
        drop(pool.get().await.expect("the pool reaches the database"));

        // The lock statement is prepared first and then bound and run:
        // holding the replies from its `Bind` lets the statement run and
        // keeps its answer from the client.
        gate.hold_replies_from(BIND);
        // `Box::pin`, not `tokio::pin!`: the macro shadows the future with
        // a `Pin<&mut _>`, and dropping *that* drops a reference and
        // cancels nothing. This test's whole subject is the drop.
        let mut acquire = Box::pin(DedicatedSession::acquire(&pool, key));
        drive_into_window(&gate, acquire.as_mut(), "the acquire").await;
        assert!(
            !holders(&observer, key).await.is_empty(),
            "the server has answered the lock statement, so it must be holding the key; \
             the gate stopped the acquire somewhere other than the window this test covers"
        );

        drop(acquire);
        // The answer was delayed, not lost: let it arrive, as the network
        // would, at whatever is still listening.
        gate.open();
        let elapsed = assert_released(&observer, key, "the acquiring future was cancelled").await;
        eprintln!("cancelled acquire: key released after {elapsed:?}");
        assert_eq!(
            pool.status().size,
            0,
            "the cancelled acquire's connection must be closed, not recycled into the pool"
        );

        // The consequence, stated directly: the next pass must be able to
        // take the key rather than be told Conflict for ever.
        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("a later pass must be able to take the key a cancelled one left behind");
        session.release().await.expect("the unlock succeeds");
    }

    /// Cancelling a pass while it is unlocking must not hand the
    /// connection back to the pool with the lock still on it.
    ///
    /// `run_pass` releases its session as its last act, inside the same
    /// `select!`, so this window is as reachable as the first. The unlock
    /// is a prepared statement: the client sends its `Parse` and waits for
    /// the answer before it sends the unlock itself. The gate withholds
    /// that answer, so the release is parked where the unlock has not been
    /// sent -- and, the future being dropped there, never will be.
    #[tokio::test]
    async fn a_cancelled_release_does_not_leave_the_key_held() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let gate = ReplyGate::new();
        let pool = gated_pool(&dsn, &gate);
        let observer = observer(&dsn).await;
        let key = advisory_lock_key(&format!(
            "greengateway.test.cancelled-release.{}",
            uuid::Uuid::new_v4().simple()
        ));

        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("the session takes the key");
        assert!(
            !holders(&observer, key).await.is_empty(),
            "the server must show the key held once the session has it"
        );

        gate.hold_replies_from(PARSE);
        // `Box::pin` for the same reason as above: the drop is the test.
        let mut release = Box::pin(session.release());
        drive_into_window(&gate, release.as_mut(), "the release").await;
        assert!(
            !holders(&observer, key).await.is_empty(),
            "the unlock was never sent, so the server must still be holding the key; \
             the gate stopped the release somewhere other than the window this test covers"
        );

        drop(release);
        gate.open();
        let elapsed = assert_released(&observer, key, "the releasing future was cancelled").await;
        eprintln!("cancelled release: key released after {elapsed:?}");
        assert_eq!(
            pool.status().size,
            0,
            "the cancelled release's connection must be closed, not recycled into the pool"
        );

        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("a later pass must be able to take the key a cancelled unlock left behind");
        session.release().await.expect("the unlock succeeds");
    }
}
