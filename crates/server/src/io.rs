//! The client side of a connection: plain TCP, TLS, or the in-memory pipe an
//! HTTP/2 stream is served through.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_openssl::SslStream;

pub(crate) enum Stream {
    Tcp(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
    /// One HTTP/2 stream, bridged as an HTTP/1.1 exchange (see `h2`).
    Pipe(DuplexStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
            Self::Pipe(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
            Self::Pipe(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
            Self::Pipe(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
            Self::Pipe(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Writes all of `data` unless a single write stalls for `t`.
pub(crate) async fn write_timeout<S: AsyncWrite + Unpin>(
    s: &mut S,
    data: &[u8],
    t: Duration,
) -> io::Result<()> {
    match timeout(t, s.write_all(data)).await {
        Ok(r) => r,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}
