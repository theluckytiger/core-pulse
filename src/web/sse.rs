//! Server-sent events: a tick every few seconds tells open dashboards to
//! reload their live panel.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::IntervalStream;

const TICK: Duration = Duration::from_secs(5);
/// Streams end after this many ticks. The browser reconnects at once, and
/// the reconnect checks the session again.
const TICKS_PER_STREAM: usize = 120;

pub async fn events() -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let ticks = IntervalStream::new(tokio::time::interval(TICK))
        .skip(1)
        .take(TICKS_PER_STREAM)
        .map(|_| Ok(Event::default().event("tick").data("")));
    Sse::new(ticks).keep_alive(KeepAlive::default())
}
