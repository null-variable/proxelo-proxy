//! Access logs. Lines are formatted on the request
//! task into a reused buffer and handed to one writer thread per process, so
//! a slow disk never blocks a worker. When the queue is full the line is
//! dropped and counted, nginx's behaviour under a stuck buffer being to
//! block, which a proxy serving traffic should not.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, LazyLock, Mutex};

use proxelo_snapshot::AccessLog;

use crate::exchange::Exchange;
use crate::metrics;
use crate::vars::{Escape, expand_into};

/// Lines waiting for the writer thread.
const QUEUE: usize = 64 * 1024;

struct Line {
    path: Arc<str>,
    bytes: Vec<u8>,
}

static WRITER: LazyLock<SyncSender<Line>> = LazyLock::new(|| {
    let (tx, rx) = sync_channel::<Line>(QUEUE);
    std::thread::Builder::new()
        .name("access-log".into())
        .spawn(move || {
            let mut files: HashMap<Arc<str>, File> = HashMap::new();
            let mut out = std::io::stdout();
            let mut err = std::io::stderr();
            while let Ok(line) = rx.recv() {
                if line.path.is_empty() {
                    files.clear();
                    continue;
                }
                let w: &mut dyn Write = match &*line.path {
                    "stdout" => &mut out,
                    "stderr" => &mut err,
                    path => {
                        if !files.contains_key(path) {
                            match OpenOptions::new().create(true).append(true).open(path) {
                                Ok(f) => {
                                    files.insert(line.path.clone(), f);
                                }
                                Err(e) => {
                                    eprintln!("access log {path}: {e}");
                                    continue;
                                }
                            }
                        }
                        files.get_mut(path).expect("inserted")
                    }
                };
                let _ = w.write_all(&line.bytes);
                RECYCLE
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(line.bytes);
            }
        })
        .expect("spawn access log thread");
    tx
});

/// Line buffers returned by the writer, reused by requests.
static RECYCLE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Paths of the current snapshot's logs, so a line carries an `Arc` instead
/// of a copy of the path.
pub(crate) struct Logs {
    paths: Box<[Arc<str>]>,
}

impl Logs {
    pub fn new(logs: &[AccessLog]) -> Self {
        Self {
            paths: logs.iter().map(|l| Arc::from(&*l.path)).collect(),
        }
    }
}

/// Reopens log files, for rotation (SIGUSR1 in nginx).
pub fn reopen() {
    // Files are opened lazily by the writer; a marker path drops them.
    let _ = WRITER.try_send(Line {
        path: Arc::from(""),
        bytes: Vec::new(),
    });
}

/// Writes the access log line for a finished request.
pub(crate) fn write(logs: &Logs, cfg: &[AccessLog], index: u32, x: &mut Exchange) {
    let Some(log) = cfg.get(index as usize) else {
        return;
    };
    let mut bytes = RECYCLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop()
        .unwrap_or_default();
    bytes.clear();
    expand_into(
        x,
        &log.format,
        &mut bytes,
        Some(if log.escape_json {
            Escape::Json
        } else {
            Escape::Default
        }),
    );
    bytes.push(b'\n');
    match WRITER.try_send(Line {
        path: logs.paths[index as usize].clone(),
        bytes,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => metrics::log_dropped(),
    }
}

#[cfg(test)]
mod tests {
    use crate::vars::{Escape, escape};

    #[test]
    fn escapes() {
        let mut b = b"ok a\"b\x01\xc3\xa9".to_vec();
        escape(&mut b, 3, Escape::Default);
        assert_eq!(b, b"ok a\\x22b\\x01\\xC3\\xA9");
        let mut b = b"a\"b\\\n\xc3\xa9".to_vec();
        escape(&mut b, 0, Escape::Json);
        assert_eq!(b, b"a\\\"b\\\\\\n\xc3\xa9");
    }
}
