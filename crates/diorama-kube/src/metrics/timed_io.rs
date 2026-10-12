//! Bound inactivity and response writes without requiring unsafe pin projection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct TimedIo<T> {
    inner: T,
    read_deadline: Pin<Box<Sleep>>,
    write_deadline: Option<Pin<Box<Sleep>>>,
}

impl<T> TimedIo<T> {
    pub(super) fn new(inner: T) -> Self {
        Self {
            inner,
            read_deadline: Box::pin(tokio::time::sleep(IDLE_TIMEOUT)),
            write_deadline: None,
        }
    }

    fn poll_write_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let deadline = self
            .write_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(WRITE_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
        } else {
            Poll::Pending
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.read_deadline
                .as_mut()
                .reset(Instant::now() + IDLE_TIMEOUT);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TimedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Ready(Err(error)) = self.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(Err(error)) = self.poll_write_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if result.is_ready() {
            self.write_deadline = None;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::TimedIo;
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn stalled_peer_reads_and_writes_expire() {
        let (stream, _peer) = tokio::io::duplex(1);
        let mut stream = TimedIo::new(stream);
        stream.write_all(b"a").await.unwrap();
        let error = stream.write_all(b"b").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let (stream, _peer) = tokio::io::duplex(1);
        let mut stream = TimedIo::new(stream);
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
