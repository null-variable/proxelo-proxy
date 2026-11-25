//! Finds the end of a chunked body without copying it.
//!
//! The proxy forwards chunked bodies byte for byte, so it only needs to know
//! where the body ends and that its framing is well formed. Line endings must
//! be CRLF: accepting bare LF here while a downstream parser does not is a
//! classic smuggling vector.

use crate::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Size,
    Ext,
    SizeLf,
    Data,
    DataCr,
    DataLf,
    TrailerStart,
    Trailer,
    TrailerLf,
    FinalLf,
    Done,
}

#[derive(Clone, Debug, Default)]
pub struct ChunkedDecoder {
    state: State,
    size: u64,
    digits: u8,
    /// Bytes of the current chunk not yet consumed.
    remaining: u64,
}

impl ChunkedDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Consumes body bytes from `buf`. Returns how many bytes belong to the
    /// body; when the body ends inside `buf` the decoder is done and the rest
    /// of `buf` is the next message.
    pub fn advance(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.advance_with(buf, |_| {})
    }

    /// Like [`advance`](Self::advance), and calls `on_data` with each range of
    /// `buf` that holds chunk data. Used to strip chunked framing for clients
    /// that cannot receive it.
    pub fn advance_with(
        &mut self,
        buf: &[u8],
        mut on_data: impl FnMut(std::ops::Range<usize>),
    ) -> Result<usize, Error> {
        let mut i = 0;
        while i < buf.len() {
            let c = buf[i];
            match self.state {
                State::Size => match c {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        if self.digits == 15 {
                            return Err(Error::BadRequest);
                        }
                        let d = (c as char).to_digit(16).unwrap_or(0);
                        self.size = self.size << 4 | u64::from(d);
                        self.digits += 1;
                    }
                    b';' | b' ' | b'\t' if self.digits > 0 => self.state = State::Ext,
                    b'\r' if self.digits > 0 => self.state = State::SizeLf,
                    _ => return Err(Error::BadRequest),
                },
                State::Ext => match c {
                    b'\r' => self.state = State::SizeLf,
                    0..=0x08 | 0x0a..=0x1f | 0x7f => return Err(Error::BadRequest),
                    _ => {}
                },
                State::SizeLf => {
                    if c != b'\n' {
                        return Err(Error::BadRequest);
                    }
                    if self.size == 0 {
                        self.state = State::TrailerStart;
                    } else {
                        self.remaining = self.size;
                        self.state = State::Data;
                    }
                    self.size = 0;
                    self.digits = 0;
                }
                State::Data => {
                    let take = self.remaining.min((buf.len() - i) as u64) as usize;
                    self.remaining -= take as u64;
                    on_data(i..i + take);
                    i += take;
                    if self.remaining == 0 {
                        self.state = State::DataCr;
                    }
                    continue;
                }
                State::DataCr => {
                    if c != b'\r' {
                        return Err(Error::BadRequest);
                    }
                    self.state = State::DataLf;
                }
                State::DataLf => {
                    if c != b'\n' {
                        return Err(Error::BadRequest);
                    }
                    self.state = State::Size;
                }
                State::TrailerStart => match c {
                    b'\r' => self.state = State::FinalLf,
                    b' ' | b'\t' | b'\n' => return Err(Error::BadRequest),
                    _ => self.state = State::Trailer,
                },
                State::Trailer => match c {
                    b'\r' => self.state = State::TrailerLf,
                    b'\n' => return Err(Error::BadRequest),
                    _ => {}
                },
                State::TrailerLf => {
                    if c != b'\n' {
                        return Err(Error::BadRequest);
                    }
                    self.state = State::TrailerStart;
                }
                State::FinalLf => {
                    if c != b'\n' {
                        return Err(Error::BadRequest);
                    }
                    self.state = State::Done;
                    return Ok(i + 1);
                }
                State::Done => return Ok(i),
            }
            i += 1;
        }
        Ok(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(input: &[u8]) -> Result<(usize, bool), Error> {
        let mut d = ChunkedDecoder::new();
        let n = d.advance(input)?;
        Ok((n, d.is_done()))
    }

    #[test]
    fn decodes_complete_body() {
        let body = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(whole(body), Ok((body.len(), true)));
    }

    #[test]
    fn stops_at_body_end() {
        let body = b"1\r\na\r\n0\r\nX-T: 1\r\n\r\nGET / HTTP/1.1";
        let end = body.len() - b"GET / HTTP/1.1".len();
        assert_eq!(whole(body), Ok((end, true)));
    }

    #[test]
    fn same_result_byte_by_byte() {
        let body = b"a\r\n0123456789\r\n0\r\n\r\n";
        let mut d = ChunkedDecoder::new();
        for (i, b) in body.iter().enumerate() {
            assert!(!d.is_done(), "done early at {i}");
            assert_eq!(d.advance(std::slice::from_ref(b)), Ok(1));
        }
        assert!(d.is_done());
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &b"\r\n"[..],
            b"g\r\n",
            b"5\nhello\r\n",
            b"5\r\nhelloX\r\n",
            b"5\r\nhello\n0\r\n\r\n",
            b"0\r\n\n",
            b"0\r\n trailer\r\n\r\n",
            b"1000000000000000\r\n",
            b"5;a\nb\r\n",
        ] {
            assert_eq!(
                whole(bad),
                Err(Error::BadRequest),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn reports_data_ranges() {
        let body = b"3\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n";
        let mut data = Vec::new();
        let mut d = ChunkedDecoder::new();
        for part in body.chunks(4) {
            d.advance_with(part, |r| data.extend_from_slice(&part[r]))
                .unwrap();
        }
        assert!(d.is_done());
        assert_eq!(data, b"abcde");
    }

    #[test]
    fn accepts_max_size_digits() {
        let mut d = ChunkedDecoder::new();
        assert_eq!(d.advance(b"fffffffffffffff\r\nab"), Ok(19));
        assert!(!d.is_done());
    }
}
