//! A minimal Server-Sent Events client, for the durable audit stream.
//!
//! Two things it must do that the harness's ordinary request helpers
//! cannot.
//!
//! **Not buffer the body.** An SSE response never ends, so anything that
//! reads it to completion (the shared client's `bytes()`, and the test
//! balancer's forwarder) hangs. This reads frames as they arrive and stops
//! when the caller drops the stream — which is also how a test says "the
//! client disconnected here", the precondition every reconnect assertion
//! needs. For the same reason a stream is opened **directly against a
//! replica**, never through the balancer.
//!
//! **Carry `Last-Event-ID`.** The durable stream's resume protocol is the
//! SSE standard's: every frame's `id:` is its stream position, and a
//! reconnecting client sends the last one it saw back. A reconnect through
//! the *other* replica is exactly the cluster claim, so the cursor has to
//! be a first-class parameter rather than something a client library hides.
//!
//! Frames are parsed to the extent the assertions need: `id`, `event` and
//! the concatenated `data` payload. Comment lines (the keep-alive `:`
//! heartbeat) are skipped, as the standard requires.

use std::time::Duration;

use futures_util::StreamExt as _;

/// One parsed SSE frame.
#[derive(Clone, Debug)]
pub struct Frame {
    /// The `id:` field — a stream position for the durable transport.
    pub id: Option<String>,
    /// The `event:` field.
    pub event: Option<String>,
    /// The concatenated `data:` lines, decoded as JSON where they are JSON.
    pub data: serde_json::Value,
    /// The raw `data:` text, for a suite that greps rather than decodes.
    pub raw: String,
}

impl Frame {
    /// The frame's `id` as the stream position it is.
    pub fn position(&self) -> i64 {
        self.id
            .as_deref()
            .unwrap_or_else(|| panic!("a durable stream frame carries its position as its id"))
            .parse()
            .unwrap_or_else(|error| panic!("a stream frame id should be an integer: {error}"))
    }

    pub fn event_id(&self) -> &str {
        self.data["event_id"]
            .as_str()
            .unwrap_or_else(|| panic!("a streamed audit event carries an event_id: {}", self.raw))
    }
}

/// An open stream. Dropping it disconnects.
pub struct Stream {
    body: std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>,
    buffer: String,
}

/// How long [`Request::open_ok`] re-asks a replica that answered `503`.
///
/// A `503` from the stream endpoint is the replica saying it could not
/// consult the authority — "cannot judge" — not an answer to "may I
/// stream?". Re-asking within a bound is the honest reading, and the bound
/// is what keeps a genuinely unavailable authority a failure rather than a
/// hang. It is generous because this suite shares its PostgreSQL server
/// with the rest of the build.
const AUTHORITY_RETRY_BUDGET: Duration = Duration::from_secs(20);

/// How the stream request is built.
#[derive(Clone)]
pub struct Request {
    url: String,
    bearer: String,
    last_event_id: Option<i64>,
}

impl Request {
    /// Stream `path` from a replica's own base URL.
    pub fn new(replica_base_url: &str, path: &str, bearer: &str) -> Self {
        Self {
            url: format!("{replica_base_url}{path}"),
            bearer: bearer.to_owned(),
            last_event_id: None,
        }
    }

    /// Resume after this position: the SSE standard's `Last-Event-ID`.
    pub fn resume_after(mut self, position: i64) -> Self {
        self.last_event_id = Some(position);
        self
    }

    /// Open the stream, answering the response status and, when the
    /// server accepted it, the frames.
    pub async fn open(self) -> (u16, serde_json::Value, Option<Stream>) {
        let mut builder = client()
            .get(&self.url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .bearer_auth(&self.bearer);
        if let Some(position) = self.last_event_id {
            builder = builder.header("last-event-id", position.to_string());
        }
        let response = builder
            .send()
            .await
            .unwrap_or_else(|error| panic!("the stream request to {} failed: {error}", self.url));
        let status = response.status().as_u16();
        if status != 200 {
            let bytes = response.bytes().await.unwrap_or_default();
            return (
                status,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
                None,
            );
        }
        (
            status,
            serde_json::Value::Null,
            Some(Stream {
                body: Box::pin(response.bytes_stream()),
                buffer: String::new(),
            }),
        )
    }

    /// Open, insisting the server accepted the stream.
    ///
    /// A `503` is re-asked within [`AUTHORITY_RETRY_BUDGET`] rather than
    /// failed on: see that constant. Every other refusal fails at once,
    /// because it is an answer.
    pub async fn open_ok(self) -> Stream {
        let deadline = std::time::Instant::now() + AUTHORITY_RETRY_BUDGET;
        loop {
            let (status, body, stream) = self.clone().open().await;
            if let Some(stream) = stream {
                return stream;
            }
            assert!(
                status == 503 && std::time::Instant::now() < deadline,
                "streaming {} answered {status}: {body}",
                self.url
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

impl Stream {
    /// The next frame, or `None` if the budget elapsed first.
    ///
    /// A bounded wait on an observable, not a sleep: it returns the moment
    /// a frame completes. `None` is a real answer for the assertions that
    /// are about *nothing more* arriving.
    pub async fn next_frame(&mut self, budget: Duration) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if let Some(frame) = self.take_frame() {
                return Some(frame);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let chunk = match tokio::time::timeout(remaining, self.body.next()).await {
                Err(_) => return None,
                Ok(None) => return None,
                Ok(Some(Err(error))) => panic!("the audit stream broke mid-frame: {error}"),
                Ok(Some(Ok(chunk))) => chunk,
            };
            self.buffer.push_str(&String::from_utf8_lossy(&chunk));
        }
    }

    /// The next `count` frames, failing with what did arrive when fewer
    /// do.
    pub async fn next_frames(&mut self, count: usize, budget: Duration) -> Vec<Frame> {
        let deadline = std::time::Instant::now() + budget;
        let mut frames = Vec::with_capacity(count);
        while frames.len() < count {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let Some(frame) = self.next_frame(remaining).await else {
                panic!(
                    "the audit stream delivered {} of {count} frames within {budget:?}",
                    frames.len()
                );
            };
            frames.push(frame);
        }
        frames
    }

    fn take_frame(&mut self) -> Option<Frame> {
        loop {
            let end = self.buffer.find("\n\n")?;
            let block: String = self.buffer.drain(..end + 2).collect();
            let mut id = None;
            let mut event = None;
            let mut data = String::new();
            for line in block.lines() {
                // A comment (the keep-alive heartbeat) has an empty field
                // name and is discarded, per the SSE grammar.
                let Some((field, value)) = line.split_once(':') else {
                    continue;
                };
                if field.is_empty() {
                    continue;
                }
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "id" => id = Some(value.to_owned()),
                    "event" => event = Some(value.to_owned()),
                    "data" => {
                        if !data.is_empty() {
                            data.push('\n');
                        }
                        data.push_str(value);
                    }
                    _ => {}
                }
            }
            if data.is_empty() && id.is_none() && event.is_none() {
                continue;
            }
            return Some(Frame {
                id,
                event,
                data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
                raw: data,
            });
        }
    }
}

/// A client with no response timeout: an idle SSE stream is the normal
/// case, not a failure, and every wait in this module is bounded by the
/// caller's own budget instead.
fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("the harness stream client should build")
    })
}
