//! L4 proxying (nginx stream): TCP connections and UDP sessions relayed to
//! an upstream, with TLS termination or a ClientHello preread.
//!
//! A session runs on the snapshot it started with to the end, and its end is
//! logged with the nginx stream variables ($status, $bytes_sent,
//! $bytes_received, $session_time, $upstream_*).

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use proxelo_snapshot::Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::exchange::Exchange;
use crate::io::Stream as Client;
use crate::limits::Hold;
use crate::upstream::{Choice, Picked, UpStream};
use crate::{Active, HANDSHAKE_TIMEOUT, Server, log, metrics, tls};

/// nginx preread_timeout and preread_buffer_size.
const PREREAD_TIMEOUT: Duration = Duration::from_secs(30);
const PREREAD_MAX: usize = 16 * 1024;
/// nginx proxy_buffer_size.
const COPY_BUF: usize = 16 * 1024;
const DATAGRAM: usize = 65_535;
/// Client datagrams queued for a UDP session before new ones are dropped.
const UDP_QUEUE: usize = 64;

/// UDP sessions of one socket, by client address.
type Sessions = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

/// What the stream variables know about a session.
#[derive(Debug, Default)]
pub(crate) struct Session {
    pub udp: bool,
    /// Bytes from the client.
    pub received: u64,
    pub upstream_sent: u64,
    pub upstream_received: u64,
    pub preread_server_name: Vec<u8>,
    /// Comma separated, as nginx.
    pub preread_alpn: Vec<u8>,
    /// SSL_get_version() style; empty when the preread saw no TLS.
    pub preread_protocol: &'static str,
}

/// The ClientHello fields ssl_preread reports.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    /// More bytes are needed.
    Partial,
    /// Not a TLS ClientHello, or a malformed one: nothing to report.
    NotTls,
    Done {
        name: Vec<u8>,
        alpn: Vec<u8>,
        version: &'static str,
    },
}

fn version_name(major: u8, minor: u8) -> &'static str {
    match (major, minor) {
        (3, 0) => "SSLv3",
        (3, 1) => "TLSv1",
        (3, 2) => "TLSv1.1",
        (3, 3) => "TLSv1.2",
        (3, 4) => "TLSv1.3",
        _ => "",
    }
}

/// Reads a ClientHello from the start of a TCP stream, possibly split over
/// several records, as nginx ssl_preread does.
fn client_hello(buf: &[u8]) -> Hello {
    // Handshake bytes of the complete records so far.
    let mut hs = Vec::new();
    let mut p = buf;
    loop {
        if p.len() < 5 {
            break;
        }
        if p[0] != 0x16 || p[1] != 3 {
            return Hello::NotTls;
        }
        let len = usize::from(u16::from_be_bytes([p[3], p[4]]));
        if p.len() < 5 + len {
            break;
        }
        hs.extend_from_slice(&p[5..5 + len]);
        p = &p[5 + len..];
        if hs.len() >= 4 {
            let need =
                4 + (usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]));
            if hs.len() >= need {
                return parse_hello(&hs[..need]).unwrap_or(Hello::NotTls);
            }
        }
    }
    if buf.len() >= 5 && (buf[0] != 0x16 || buf[1] != 3) {
        return Hello::NotTls;
    }
    Hello::Partial
}

/// A cursor over handshake bytes; `None` on truncation.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

fn parse_hello(hs: &[u8]) -> Option<Hello> {
    let mut r = Reader(hs);
    if r.u8()? != 1 {
        return None;
    }
    r.take(3)?;
    let v = r.take(2)?;
    let mut version = version_name(v[0], v[1]);
    r.take(32)?;
    r.vec8()?;
    r.vec16()?;
    r.vec8()?;
    let mut name = Vec::new();
    let mut alpn = Vec::new();
    if !r.0.is_empty() {
        let mut ext = Reader(r.vec16()?);
        while !ext.0.is_empty() {
            let kind = ext.u16()?;
            let mut data = Reader(ext.vec16()?);
            match kind {
                0 => {
                    let mut list = Reader(data.vec16()?);
                    while !list.0.is_empty() {
                        let t = list.u8()?;
                        let n = list.vec16()?;
                        if t == 0 && name.is_empty() {
                            name = n.to_ascii_lowercase();
                        }
                    }
                }
                16 => {
                    let mut list = Reader(data.vec16()?);
                    while !list.0.is_empty() {
                        let p = list.vec8()?;
                        if !alpn.is_empty() {
                            alpn.push(b',');
                        }
                        alpn.extend_from_slice(p);
                    }
                }
                43 => {
                    let list = data.vec8()?;
                    if list.as_chunks::<2>().0.contains(&[3, 4]) {
                        version = "TLSv1.3";
                    }
                }
                _ => {}
            }
        }
    }
    Some(Hello::Done {
        name,
        alpn,
        version,
    })
}

/// The PROXY protocol v1 header for a session from `src` to `dst`.
fn proxy_header(out: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr) {
    let canon = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let (src, dst) = (canon(src), canon(dst));
    let family = match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
        (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
        _ => {
            out.extend_from_slice(b"PROXY UNKNOWN\r\n");
            return;
        }
    };
    _ = write!(
        out,
        "PROXY {family} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    );
}

/// A session's exchange: the stream variables over the snapshot's lookups.
fn exchange(active: &Active, local: SocketAddr, peer: SocketAddr, udp: bool) -> Exchange {
    let mut x = Exchange::new(local, peer);
    x.conn_id = crate::conn::next_id();
    x.lookups = Arc::clone(&active.rt.lookups);
    x.lookup_vals.resize(x.lookups.len(), None);
    x.session = Some(Session {
        udp,
        ..Session::default()
    });
    x
}

fn session(x: &mut Exchange) -> &mut Session {
    x.session.get_or_insert_with(Session::default)
}

/// Access rules and connection limits; `Err` is the $status to end with.
fn admit(x: &mut Exchange, active: &Active, s: &Stream, holds: &mut Vec<Hold>) -> Result<(), u16> {
    if !proxelo_snapshot::allowed(&s.rules, x.peer.ip()) {
        return Err(403);
    }
    crate::limits::conn(x, &active.rt, &active.zones, &s.conn_limits, holds)
}

fn finish(active: &Active, s: &Stream, x: &mut Exchange, status: u16) {
    x.sent.status = status;
    if let Some(i) = s.access_log {
        log::write(&active.logs, &active.rt.access_logs, i, x);
    }
}

/// The upstream of the session's SNI name, or 500 when no route matches.
fn route(s: &Stream, x: &Exchange) -> Result<u32, u16> {
    let name = x
        .tls
        .as_ref()
        .map(|t| &*t.server_name)
        .filter(|n| !n.is_empty())
        .or_else(|| {
            x.session
                .as_ref()
                .map(|s| &s.preread_server_name[..])
                .filter(|n| !n.is_empty())
        });
    match s.upstream(name) {
        Ok(Some(u)) => Ok(u),
        _ => Err(500),
    }
}

/// Picks a target of `upstream` and connects, trying the next one on
/// failure as nginx proxy_next_upstream does.
async fn connect<'a>(
    x: &mut Exchange,
    active: &'a Active,
    s: &Stream,
    upstream: u32,
) -> Result<(UpStream, Picked<'a>), u16> {
    let ups = &active.upstreams[upstream as usize];
    crate::proxy::balancing_key(x, &active.rt.upstreams[upstream as usize]);
    let mut choice = Choice::default();
    let mut tries = 0;
    loop {
        if s.tries != 0 && tries >= s.tries {
            return Err(502);
        }
        let Some(picked) = ups.pick(&mut choice, &x.tmpl) else {
            return Err(502);
        };
        tries += 1;
        let i = picked.index;
        x.sent.upstream_addr = Some(ups.pools()[i].addr);
        let started = Instant::now();
        match ups.connect(i, s.connect_timeout).await {
            Ok(up) => {
                x.sent.upstream_connect = Some(started.elapsed().as_secs_f64());
                ups.succeeded(i);
                return Ok((up, picked));
            }
            Err(_) => {
                ups.failed(i);
                active.metrics.upstream_failure(upstream, i);
                if !s.next_upstream {
                    return Err(502);
                }
            }
        }
    }
}

/// Relays bytes both ways until either side ends or neither sends for
/// `idle`, as nginx without proxy_half_close.
async fn relay<C, U>(client: C, up: U, idle: Duration, x: &mut Exchange)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    enum Side {
        Client(std::io::Result<usize>),
        Up(std::io::Result<usize>),
    }
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(up);
    let mut cb = vec![0u8; COPY_BUF];
    let mut ub = vec![0u8; COPY_BUF];
    loop {
        let read = timeout(idle, async {
            tokio::select! {
                n = cr.read(&mut cb) => Side::Client(n),
                n = ur.read(&mut ub) => Side::Up(n),
            }
        })
        .await;
        match read {
            Err(_) | Ok(Side::Client(Ok(0) | Err(_)) | Side::Up(Ok(0) | Err(_))) => break,
            Ok(Side::Client(Ok(n))) => {
                if !matches!(timeout(idle, uw.write_all(&cb[..n])).await, Ok(Ok(()))) {
                    break;
                }
                let s = session(x);
                s.received += n as u64;
                s.upstream_sent += n as u64;
            }
            Ok(Side::Up(Ok(n))) => {
                if !matches!(timeout(idle, cw.write_all(&ub[..n])).await, Ok(Ok(()))) {
                    break;
                }
                session(x).upstream_received += n as u64;
                x.sent.bytes += n as u64;
            }
        }
    }
    let _ = timeout(idle, cw.shutdown()).await;
    let _ = timeout(idle, uw.shutdown()).await;
}

impl Server {
    /// Accepts connections of a TCP stream on `listener` forever.
    pub(crate) async fn accept_stream(
        self: Arc<Self>,
        addr: SocketAddr,
        listener: std::net::TcpListener,
    ) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tokio::spawn(self.clone().stream_connection(addr, stream, peer));
                }
                // Out of descriptors or memory: back off instead of spinning.
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    async fn stream_connection(
        self: Arc<Self>,
        addr: SocketAddr,
        stream: TcpStream,
        peer: SocketAddr,
    ) {
        metrics::connection_opened();
        let _closed = crate::scopeguard(metrics::connection_closed);
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let active = self.active();
        let Some(si) = active
            .rt
            .streams
            .iter()
            .position(|s| !s.udp && s.addrs.contains(&addr))
        else {
            return;
        };
        let s = &active.rt.streams[si];
        let mut x = exchange(&active, local, peer, false);
        let status = tcp_session(&active, si, stream, &mut x).await;
        finish(&active, s, &mut x, status);
    }

    /// Serves the UDP stream bound to `socket` forever.
    pub(crate) async fn serve_udp(
        self: Arc<Self>,
        addr: SocketAddr,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let local = socket.local_addr()?;
        let sessions: Sessions = Arc::default();
        let mut buf = vec![0u8; DATAGRAM];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let data = buf[..n].to_vec();
            let mut map = sessions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&peer) {
                match tx.try_send(data) {
                    // Over the queue: dropped, as a full socket buffer would.
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                    // The session is ending: start a new one.
                    Err(mpsc::error::TrySendError::Closed(d)) => {
                        map.remove(&peer);
                        let tx = self
                            .clone()
                            .udp_session(addr, local, peer, &socket, &sessions);
                        let _ = tx.try_send(d);
                        map.insert(peer, tx);
                    }
                }
                continue;
            }
            let tx = self
                .clone()
                .udp_session(addr, local, peer, &socket, &sessions);
            let _ = tx.try_send(data);
            map.insert(peer, tx);
        }
    }

    /// Starts the session of `peer` and returns where its datagrams go.
    fn udp_session(
        self: Arc<Self>,
        addr: SocketAddr,
        local: SocketAddr,
        peer: SocketAddr,
        socket: &Arc<UdpSocket>,
        sessions: &Sessions,
    ) -> mpsc::Sender<Vec<u8>> {
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        let socket = Arc::clone(socket);
        let sessions = Arc::clone(sessions);
        let me = tx.clone();
        tokio::spawn(async move {
            let active = self.active();
            if let Some(si) = active
                .rt
                .streams
                .iter()
                .position(|s| s.udp && s.addrs.contains(&addr))
            {
                let s = &active.rt.streams[si];
                let mut x = exchange(&active, local, peer, true);
                let status = udp_session(&active, s, &socket, rx, &mut x).await;
                finish(&active, s, &mut x, status);
            }
            // Forget this session unless a new one took the address.
            let mut map = sessions.lock().unwrap_or_else(|e| e.into_inner());
            if map.get(&peer).is_some_and(|t| t.same_channel(&me)) {
                map.remove(&peer);
            }
        });
        tx
    }
}

async fn tcp_session(active: &Active, si: usize, stream: TcpStream, x: &mut Exchange) -> u16 {
    let s = &active.rt.streams[si];
    let mut holds = Vec::new();
    if let Err(status) = admit(x, active, s, &mut holds) {
        return status;
    }
    let mut early = Vec::new();
    let client = if let Some(ctx) = &active.stream_tls[si] {
        let Ok(ssl) = openssl::ssl::Ssl::new(ctx) else {
            return 500;
        };
        let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
            return 500;
        };
        let ok = matches!(
            timeout(HANDSHAKE_TIMEOUT, std::pin::Pin::new(&mut tls).accept()).await,
            Ok(Ok(()))
        );
        if !ok {
            metrics::tls_handshake_error();
            return 400;
        }
        let mode = s
            .tls
            .as_ref()
            .and_then(|t| t.client_auth.as_ref())
            .map(|c| c.mode);
        let info = tls::TlsInfo::of(tls.ssl(), mode);
        // nginx stream ssl_verify_client closes the session.
        let rejected = info.client_error().is_some();
        x.tls = Some(info);
        if rejected {
            return 400;
        }
        Client::Tls(Box::new(tls))
    } else {
        let mut stream = stream;
        if s.ssl_preread {
            match preread(&mut stream, &mut early).await {
                Ok(Hello::Done {
                    name,
                    alpn,
                    version,
                }) => {
                    let sess = session(x);
                    sess.preread_server_name = name;
                    sess.preread_alpn = alpn;
                    sess.preread_protocol = version;
                }
                Ok(_) => {}
                Err(status) => return status,
            }
            session(x).received = early.len() as u64;
        }
        Client::Tcp(stream)
    };
    let upstream = match route(s, x) {
        Ok(u) => u,
        Err(status) => return status,
    };
    let (mut up, _picked) = match connect(x, active, s, upstream).await {
        Ok(c) => c,
        Err(status) => return status,
    };
    let mut first = Vec::new();
    if s.proxy_protocol {
        proxy_header(&mut first, x.peer, x.local);
    }
    first.extend_from_slice(&early);
    if !first.is_empty() {
        if !matches!(timeout(s.timeout, up.write_all(&first)).await, Ok(Ok(()))) {
            return 502;
        }
        session(x).upstream_sent += early.len() as u64;
    }
    relay(client, up, s.timeout, x).await;
    200
}

/// Reads until the ClientHello is complete or is not one. The bytes stay
/// in `buf` for the upstream. `Err` is the $status to end with.
async fn preread(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<Hello, u16> {
    let deadline = tokio::time::Instant::now() + PREREAD_TIMEOUT;
    let mut chunk = [0u8; 4096];
    loop {
        match client_hello(buf) {
            Hello::Partial => {}
            done => return Ok(done),
        }
        if buf.len() >= PREREAD_MAX {
            return Err(400);
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            // nginx goes on without the preread result.
            Err(_) => return Ok(Hello::NotTls),
            Ok(Ok(0) | Err(_)) => return Err(400),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Relays the datagrams of one client until the session times out or got
/// the responses it expects (nginx proxy_responses).
async fn udp_session(
    active: &Active,
    s: &Stream,
    socket: &UdpSocket,
    mut rx: mpsc::Receiver<Vec<u8>>,
    x: &mut Exchange,
) -> u16 {
    let mut holds = Vec::new();
    if let Err(status) = admit(x, active, s, &mut holds) {
        return status;
    }
    let upstream = match route(s, x) {
        Ok(u) => u,
        Err(status) => return status,
    };
    let ups = &active.upstreams[upstream as usize];
    crate::proxy::balancing_key(x, &active.rt.upstreams[upstream as usize]);
    let mut choice = Choice::default();
    let Some(picked) = ups.pick(&mut choice, &x.tmpl) else {
        return 502;
    };
    let target = ups.pools()[picked.index].addr;
    x.sent.upstream_addr = Some(target);
    let any = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let up = match UdpSocket::bind(any).await {
        Ok(u) if u.connect(target).await.is_ok() => u,
        _ => {
            ups.failed(picked.index);
            return 502;
        }
    };
    x.sent.upstream_connect = Some(0.0);
    let mut buf = vec![0u8; DATAGRAM];
    // Responses still expected; None: until the timeout.
    let mut expected: Option<u64> = None;
    let mut got = 0u64;
    loop {
        if let (Some(want), Some(_)) = (expected, s.responses)
            && got >= want
        {
            return 200;
        }
        let next = timeout(s.timeout, async {
            tokio::select! {
                d = rx.recv() => Ok(d),
                r = up.recv(&mut buf) => Err(r),
            }
        })
        .await;
        match next {
            // Idle: nginx ends a UDP session with 200 too.
            Err(_) | Ok(Ok(None)) => return 200,
            Ok(Ok(Some(d))) => {
                if up.send(&d).await.is_err() {
                    ups.failed(picked.index);
                    return 502;
                }
                let sess = session(x);
                sess.received += d.len() as u64;
                sess.upstream_sent += d.len() as u64;
                if let Some(r) = s.responses {
                    *expected.get_or_insert(0) += u64::from(r);
                }
            }
            Ok(Err(Ok(n))) => {
                let peer = x.peer;
                let _ = socket.send_to(&buf[..n], peer).await;
                session(x).upstream_received += n as u64;
                x.sent.bytes += n as u64;
                got += 1;
            }
            // ICMP unreachable and the like.
            Ok(Err(Err(_))) => {
                ups.failed(picked.index);
                active.metrics.upstream_failure(upstream, picked.index);
                return 502;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello with SNI "Example.COM", ALPN h2,http/1.1 and
    /// supported_versions 1.3, split over two records.
    fn hello() -> Vec<u8> {
        let mut ext = Vec::new();
        let name = b"Example.COM";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        let alpn = b"\x02h2\x08http/1.1";
        ext.extend_from_slice(&[0, 16]);
        ext.extend_from_slice(&((alpn.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
        ext.extend_from_slice(alpn);
        ext.extend_from_slice(&[0, 43, 0, 5, 4, 3, 4, 3, 3]);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let (a, b) = hs.split_at(10);
        let mut out = Vec::new();
        for part in [a, b] {
            out.extend_from_slice(&[0x16, 3, 1]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn reads_client_hello() {
        let h = hello();
        assert_eq!(
            client_hello(&h),
            Hello::Done {
                name: b"example.com".to_vec(),
                alpn: b"h2,http/1.1".to_vec(),
                version: "TLSv1.3",
            }
        );
        for cut in [0, 3, 5, 14, h.len() - 1] {
            assert_eq!(client_hello(&h[..cut]), Hello::Partial, "cut {cut}");
        }
        assert_eq!(client_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
    }

    #[test]
    fn proxy_protocol_v1() {
        let mut out = Vec::new();
        proxy_header(
            &mut out,
            "192.0.2.1:5000".parse().unwrap(),
            "198.51.100.2:443".parse().unwrap(),
        );
        assert_eq!(out, b"PROXY TCP4 192.0.2.1 198.51.100.2 5000 443\r\n");
        out.clear();
        proxy_header(
            &mut out,
            "[::ffff:192.0.2.1]:1".parse().unwrap(),
            "[2001:db8::1]:2".parse().unwrap(),
        );
        assert_eq!(out, b"PROXY UNKNOWN\r\n");
    }
}
