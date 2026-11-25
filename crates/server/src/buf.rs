//! A growable read buffer that is reused for every request on a connection.

use std::io;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Bytes `data[..end]` are filled. `data` stays fully initialized so reads go
/// straight into it; it grows on demand and never shrinks.
pub(crate) struct Buf {
    pub data: Vec<u8>,
    pub end: usize,
}

impl Buf {
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            end: 0,
        }
    }

    pub fn filled(&self) -> &[u8] {
        &self.data[..self.end]
    }

    /// Drops the first `n` filled bytes.
    pub fn consume(&mut self, n: usize) {
        self.data.copy_within(n..self.end, 0);
        self.end -= n;
    }

    /// Reads once into the free space, doubling the buffer from `initial` up
    /// to `max` when it is full. Returns 0 at end of stream.
    pub async fn fill(
        &mut self,
        s: &mut TcpStream,
        initial: usize,
        max: usize,
    ) -> io::Result<usize> {
        if self.end == self.data.len() {
            let grown = if self.data.is_empty() {
                initial
            } else {
                self.data.len() * 2
            };
            self.data.resize(grown.min(max).max(self.end + 1), 0);
        }
        let n = s.read(&mut self.data[self.end..]).await?;
        self.end += n;
        Ok(n)
    }
}
