//! Passing listening sockets to a successor process, for binary upgrades that
//! drop no connections (the nginx USR2 upgrade).
//!
//! A running proxy listens on a Unix socket. A new process started on the
//! same data directory connects to it and says `upgrade`; the old process
//! sends every listening socket with SCM_RIGHTS, one `<kind> <address>` line
//! per descriptor, then `end`. The new process starts serving on them and
//! says `ready`; the old one stops accepting, answers `done` and lets its
//! connections finish. Both accept on the same sockets in between, so no
//! connection is refused and none queued in a listen backlog is lost. If the
//! new process gives up before `ready`, the old one carries on unchanged.

use std::collections::HashMap;
use std::io::{self, IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

use crate::listeners::{Kind, Socket};

/// How long either side waits for the other. The successor loads its
/// snapshot, TLS contexts included, before it says `ready`.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Descriptors per message, well under the kernel limits.
const BATCH: usize = 32;

pub(crate) type Key = (SocketAddr, Kind);

/// Duplicates of the sockets a [`crate::Listeners`] serves, kept to hand
/// over. Shared, so the upgrade socket can serve them while the listeners
/// are borrowed elsewhere.
#[derive(Clone, Default)]
pub struct Handoff(Arc<Mutex<HashMap<Key, Vec<OwnedFd>>>>);

impl Handoff {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Vec<OwnedFd>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn insert(&self, key: Key, fds: Vec<OwnedFd>) {
        self.map().insert(key, fds);
    }

    pub(crate) fn retain(&self, keep: impl Fn(&Key) -> bool) {
        self.map().retain(|k, _| keep(k));
    }

    /// Fresh duplicates, so the lock is not held while they are sent.
    fn dup(&self) -> io::Result<Vec<(Key, OwnedFd)>> {
        let map = self.map();
        let mut v = Vec::new();
        for (key, fds) in map.iter() {
            for fd in fds {
                v.push((*key, fd.try_clone()?));
            }
        }
        Ok(v)
    }
}

/// Sockets taken over from the previous process, by address and kind.
pub struct Inherited(pub(crate) HashMap<Key, Vec<Socket>>);

impl Inherited {
    /// Number of sockets.
    pub fn len(&self) -> usize {
        self.0.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The upgrade socket of a running proxy.
pub struct UpgradeListener(tokio::net::UnixListener);

/// Binds the upgrade socket at `path`, replacing a stale one. Must run inside
/// a Tokio runtime.
pub fn listen(path: &Path) -> io::Result<UpgradeListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    tokio::net::UnixListener::bind(path).map(UpgradeListener)
}

impl UpgradeListener {
    /// Hands the sockets in `handoff` to each process that asks, until one
    /// says it is serving on them. Failed attempts are logged and change
    /// nothing.
    pub async fn successor(self, handoff: &Handoff) -> io::Result<Successor> {
        loop {
            let (s, _) = self.0.accept().await?;
            let s = s.into_std()?;
            let handoff = handoff.clone();
            match tokio::task::spawn_blocking(move || offer(s, &handoff)).await {
                Ok(Ok(s)) => return Ok(Successor(s)),
                Ok(Err(e)) => eprintln!("binary upgrade: {e}; still serving"),
                Err(e) => eprintln!("binary upgrade: {e}; still serving"),
            }
        }
    }
}

fn offer(s: UnixStream, handoff: &Handoff) -> io::Result<UnixStream> {
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    expect(&s, b"upgrade\n")?;
    send_sockets(&s, &handoff.dup()?)?;
    expect(&s, b"ready\n")?;
    Ok(s)
}

/// A process that took over the sockets and serves on them.
pub struct Successor(UnixStream);

impl Successor {
    /// Tells the successor this process stopped accepting.
    pub fn done(self) {
        let _ = (&self.0).write_all(b"done\n");
    }
}

/// The running process sockets were taken from.
pub struct Predecessor(UnixStream);

/// Takes the listening sockets of the proxy whose upgrade socket is `path`.
/// `None` when no proxy listens there.
pub fn take_over(path: &Path) -> io::Result<Option<(Predecessor, Inherited)>> {
    let s = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    (&s).write_all(b"upgrade\n")?;
    let inherited = receive_sockets(&s)?;
    Ok(Some((Predecessor(s), inherited)))
}

impl Predecessor {
    /// Tells the old process this one serves, and waits until it stopped
    /// accepting.
    pub fn ready(self) -> io::Result<()> {
        (&self.0).write_all(b"ready\n")?;
        expect(&self.0, b"done\n")
    }
}

fn expect(s: &UnixStream, want: &[u8]) -> io::Result<()> {
    let mut got = [0u8; 16];
    let got = &mut got[..want.len()];
    let mut r: &UnixStream = s;
    r.read_exact(got)?;
    if got != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected message on the upgrade socket",
        ));
    }
    Ok(())
}

fn send_sockets(s: &UnixStream, all: &[(Key, OwnedFd)]) -> io::Result<()> {
    let mut w: &UnixStream = s;
    for chunk in all.chunks(BATCH) {
        let mut text = String::new();
        for ((addr, kind), _) in chunk {
            text.push_str(kind.name());
            text.push(' ');
            text.push_str(&addr.to_string());
            text.push('\n');
        }
        let fds: Vec<BorrowedFd<'_>> = chunk.iter().map(|(_, fd)| fd.as_fd()).collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(BATCH))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(io::Error::other("descriptor batch too large"));
        }
        let bytes = text.as_bytes();
        let n = sendmsg(s, &[IoSlice::new(bytes)], &mut control, SendFlags::empty())?;
        w.write_all(&bytes[n..])?;
    }
    w.write_all(b"end\n")
}

fn receive_sockets(s: &UnixStream) -> io::Result<Inherited> {
    let mut text = Vec::new();
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut buf = [0u8; 4096];
    while !(text == b"end\n" || text.ends_with(b"\nend\n")) {
        // Room for two batches, in case a read spans the descriptors of
        // two messages.
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2 * BATCH))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let msg = recvmsg(
            s,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::empty(),
        )?;
        for m in control.drain() {
            if let RecvAncillaryMessage::ScmRights(got) = m {
                fds.extend(got);
            }
        }
        if msg.flags.contains(ReturnFlags::CTRUNC) {
            return Err(io::Error::other("descriptors truncated"));
        }
        if msg.bytes == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        text.extend_from_slice(&buf[..msg.bytes]);
        if text.len() > 1 << 20 {
            return Err(io::Error::other("socket list too long"));
        }
    }
    let text = std::str::from_utf8(&text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "socket list is not text"))?;
    let lines: Vec<&str> = text.lines().filter(|l| *l != "end").collect();
    if lines.len() != fds.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} sockets listed, {} received", lines.len(), fds.len()),
        ));
    }
    let mut map: HashMap<Key, Vec<Socket>> = HashMap::new();
    for (line, fd) in lines.into_iter().zip(fds) {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, format!("bad socket {line:?}"));
        let (kind, addr) = line.split_once(' ').ok_or_else(bad)?;
        let kind = Kind::parse(kind).ok_or_else(bad)?;
        let addr: SocketAddr = addr.parse().map_err(|_| bad())?;
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        let socket = match kind {
            Kind::Udp | Kind::Quic => Socket::Udp(std::net::UdpSocket::from(fd)),
            Kind::Http | Kind::Tcp => Socket::Tcp(std::net::TcpListener::from(fd)),
        };
        socket.set_nonblocking()?;
        map.entry((addr, kind)).or_default().push(socket);
    }
    Ok(Inherited(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets_cross_a_unix_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut all = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..(BATCH + 3) {
            let l = crate::bind("127.0.0.1:0".parse().unwrap(), false, 0).unwrap();
            let addr = l.local_addr().unwrap();
            addrs.push(addr);
            all.push(((addr, Kind::Http), OwnedFd::from(l)));
        }
        let u = crate::bind_udp("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let uaddr = u.local_addr().unwrap();
        all.push(((uaddr, Kind::Udp), OwnedFd::from(u)));
        let sender = std::thread::spawn(move || send_sockets(&a, &all));
        let got = receive_sockets(&b).unwrap();
        sender.join().unwrap().unwrap();
        assert_eq!(got.len(), BATCH + 4);
        for addr in addrs {
            let Some([Socket::Tcp(l)]) = got.0.get(&(addr, Kind::Http)).map(Vec::as_slice) else {
                panic!("{addr} missing");
            };
            assert_eq!(l.local_addr().unwrap(), addr);
        }
        assert!(matches!(
            got.0.get(&(uaddr, Kind::Udp)).map(Vec::as_slice),
            Some([Socket::Udp(_)])
        ));
    }
}
