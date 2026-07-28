//! Low-level tty discovery, permission checks and message delivery.

use std::{
    collections::HashSet,
    io::Error,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use chrono::Timelike;
use nix::{
    errno::Errno,
    fcntl::{self, OFlag},
    sys::stat::{Mode, SFlag, stat},
    unistd,
};
use tokio::{io::unix::AsyncFd, time};
use uucore::utmpx::Utmpx;

const TERM_WIDTH: usize = 79;

#[derive(Debug, thiserror::Error)]
pub enum TtyError {
    #[error("invalid tty name: {0:?}")]
    InvalidName(String),
    #[error("{0}: no such tty")]
    NotFound(String),
    #[error("{0}: not a character device")]
    NotCharacterDevice(String),
    #[error("{0}: messages are disabled on this tty")]
    MessagesDisabled(String),
    #[error("{0}: device is busy or not accessible")]
    Unavailable(String),
    #[error("timed out writing to {0}")]
    Timeout(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: Error,
    },
}

fn validate_tty_name(name: &str) -> Result<(), TtyError> {
    if name.is_empty()
        || name.starts_with(':')
        || name.starts_with('/')
        || name.split('/').any(|part| part == ".." || part.is_empty())
    {
        return Err(TtyError::InvalidName(name.to_string()));
    }
    Ok(())
}

pub fn tty_device_path(name: &str) -> Result<PathBuf, TtyError> {
    validate_tty_name(name)?;
    Ok(Path::new("/dev").join(name))
}

pub struct TtyInfo {
    /// Whether the tty currently accepts unsolicited writes (`mesg y`), signalled by the
    /// group-write bit on the device node.
    pub writable: bool,
    pub atime: SystemTime,
}

pub fn stat_tty(name: &str) -> Result<TtyInfo, TtyError> {
    let path = tty_device_path(name)?;

    let st = stat(&path).map_err(|e| match e {
        Errno::ENOENT => TtyError::NotFound(name.to_string()),
        other => TtyError::Io {
            path: path.display().to_string(),
            source: other.into(),
        },
    })?;

    let file_type = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT;
    if file_type != SFlag::S_IFCHR {
        return Err(TtyError::NotCharacterDevice(name.to_string()));
    }

    let mode = Mode::from_bits_truncate(st.st_mode);
    let atime = SystemTime::UNIX_EPOCH + Duration::from_secs(st.st_atime.max(0) as u64);

    Ok(TtyInfo {
        writable: mode.contains(Mode::S_IWGRP),
        atime,
    })
}

/// A single logged-in session, as reported by utmpx (systemd-logind)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub tty: String,
}

fn utmpx_sessions() -> impl Iterator<Item = Session> {
    Utmpx::iter_all_records().filter_map(|record| {
        if !record.is_user_process() {
            return None;
        }
        let tty = record.tty_device();
        // Skip empty ttys and X11/Wayland sessions (":0", ":1", etc.).
        if tty.is_empty() || tty.starts_with(':') {
            return None;
        }
        Some(Session {
            user: record.user(),
            tty,
        })
    })
}

/// All distinct (user, tty) sessions, optionally restricted to members of `group`,
/// deduplicated by tty.
pub fn all_sessions(group: Option<&str>) -> Vec<Session> {
    let mut seen = HashSet::new();
    utmpx_sessions()
        .filter(|s| group.is_none_or(|g| is_group_member(&s.user, g)))
        .filter(|s| seen.insert(s.tty.clone()))
        .collect()
}

/// Distinct ttys that `user` is currently logged in on.
pub fn sessions_for_user(user: &str) -> Vec<Session> {
    let mut seen = HashSet::new();
    utmpx_sessions()
        .filter(|s| s.user == user)
        .filter(|s| seen.insert(s.tty.clone()))
        .collect()
}

/// Whether `username` is a member of `group`, by primary or supplementary group.
pub fn is_group_member(username: &str, group: &str) -> bool {
    let Some(target_group) = users::get_group_by_name(group) else {
        return false;
    };
    let Some(user) = users::get_user_by_name(username) else {
        return false;
    };
    if user.primary_group_id() == target_group.gid() {
        return true;
    }
    users::get_user_groups(username, user.primary_group_id())
        .is_some_and(|groups| groups.iter().any(|g| g.gid() == target_group.gid()))
}

/// - Escape non-printable characters as `^X`
/// - Rewrite LF TO CRLF
/// - Wrap at `wrap_width` columns if given.
pub fn escape_and_wrap_content(input: &str, wrap_width: Option<usize>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut col = 0usize;

    for ch in input.chars() {
        if ch == '\n' {
            out.push_str("\r\n");
            col = 0;
            continue;
        }

        let rendered = if ch.is_control() {
            format!("^{}", (ch as u8 ^ 0x40) as char)
        } else {
            ch.to_string()
        };

        if let Some(width) = wrap_width
            && col > 0
            && col + rendered.len() > width
        {
            out.push_str("\r\n");
            col = 0;
        }

        out.push_str(&rendered);
        col += rendered.len();
    }

    out
}

fn pad_or_truncate(s: &str, width: usize) -> String {
    let truncated: String = s.chars().take(width).collect();
    format!("{truncated:<width$}")
}

pub fn format_wall_message(
    from_user: &str,
    from_host: &str,
    from_tty: Option<&str>,
    message: &str,
    nobanner: bool,
) -> Vec<u8> {
    let mut out = String::new();

    if !nobanner {
        let location = from_tty.unwrap_or("somewhere");
        let now = chrono::Local::now().format("%a %b %e %H:%M:%S %Y");
        out.push('\r');
        out.push_str(&" ".repeat(TERM_WIDTH));
        out.push_str("\r\n");

        let banner =
            format!("Broadcast message from {from_user}@{from_host} ({location}) ({now}):");
        out.push_str(&pad_or_truncate(&banner, TERM_WIDTH));
        out.push_str("\x07\x07\r\n");
    }

    out.push_str(&" ".repeat(TERM_WIDTH));
    out.push_str("\r\n");

    out.push_str(&escape_and_wrap_content(message, Some(TERM_WIDTH)));
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }

    out.push_str(&" ".repeat(TERM_WIDTH));
    out.push_str("\r\n");

    out.into_bytes()
}

pub fn format_write_message(
    from_user: &str,
    from_host: &str,
    from_tty: Option<&str>,
    message: &str,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("\r\n\x07\x07\x07");

    let now = chrono::Local::now();
    let tty = from_tty.unwrap_or("<no tty>");
    out.push_str(&format!(
        "Message from {from_user}@{from_host} on {tty} at {:02}:{:02} ...\r\n",
        now.hour(),
        now.minute(),
    ));

    out.push_str(&escape_and_wrap_content(message, None));
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out.push_str("EOF\r\n");

    out.into_bytes()
}

/// Open `tty` and write `message` to it, giving up after `timeout`.
pub async fn deliver_message(
    tty_name: &str,
    message: &[u8],
    timeout: Duration,
) -> Result<(), TtyError> {
    let path = tty_device_path(tty_name)?;

    let fd = match fcntl::open(
        &path,
        OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_NOCTTY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT | Errno::EACCES | Errno::EBUSY) => {
            return Err(TtyError::Unavailable(tty_name.to_string()));
        }
        Err(e) => {
            return Err(TtyError::Io {
                path: path.display().to_string(),
                source: e.into(),
            });
        }
    };

    let async_fd = AsyncFd::new(fd).map_err(|source| TtyError::Io {
        path: path.display().to_string(),
        source,
    })?;

    let write_all = async {
        let mut written = 0usize;
        while written < message.len() {
            let mut guard = async_fd.writable().await?;
            match guard.try_io(|inner| {
                unistd::write(inner.get_ref(), &message[written..]).map_err(Error::from)
            }) {
                Ok(Ok(n)) => written += n,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok::<(), Error>(())
    };

    time::timeout(timeout, write_all)
        .await
        .map_err(|_| TtyError::Timeout(tty_name.to_string()))?
        .map_err(|source| TtyError::Io {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::{
        pty::openpty,
        sys::termios::{self, SetArg},
    };

    #[test]
    fn validate_tty_name_rejects_traversal() {
        assert!(validate_tty_name("pts/3").is_ok());
        assert!(validate_tty_name("").is_err());
        assert!(validate_tty_name(":0").is_err());
        assert!(validate_tty_name("/etc/passwd").is_err());
        assert!(validate_tty_name("../etc/passwd").is_err());
        assert!(validate_tty_name("foo/../../bar").is_err());
    }

    #[test]
    fn careful_escape_handles_control_chars_and_wrapping() {
        assert_eq!(escape_and_wrap_content("hi\nthere", None), "hi\r\nthere");
        assert_eq!(escape_and_wrap_content("a\x01b", None), "a^Ab");

        let wrapped = escape_and_wrap_content("aaaa bbbb", Some(4));
        assert!(wrapped.contains("\r\n"));
    }

    #[test]
    fn wall_message_contains_banner_and_body() {
        let msg = format_wall_message("alice", "host", Some("pts/0"), "hello there", false);
        let msg = String::from_utf8(msg).unwrap();
        assert!(msg.contains("Broadcast message from alice@host (pts/0)"));
        assert!(msg.contains("hello there"));
    }

    #[test]
    fn wall_message_without_banner_omits_it() {
        let msg = format_wall_message("alice", "host", Some("pts/0"), "hello there", true);
        let msg = String::from_utf8(msg).unwrap();
        assert!(!msg.contains("Broadcast message"));
        assert!(msg.contains("hello there"));
    }

    #[test]
    fn write_message_has_eof_marker() {
        let msg = format_write_message("bob", "host", Some("pts/1"), "yo");
        let msg = String::from_utf8(msg).unwrap();
        assert!(msg.contains("Message from bob@host on pts/1"));
        assert!(msg.ends_with("EOF\r\n"));
    }

    fn open_fake_tty() -> (nix::pty::OpenptyResult, String) {
        let pty = openpty(None, None).expect("openpty");
        let name = nix::unistd::ttyname(&pty.slave)
            .expect("ttyname")
            .to_str()
            .unwrap()
            .trim_start_matches("/dev/")
            .to_string();

        // Put the slave side in raw mode so the line discipline doesn't rewrite the
        // `\r\n` we send before we get to assert on it.
        let mut termios = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        termios::cfmakeraw(&mut termios);
        termios::tcsetattr(&pty.slave, SetArg::TCSANOW, &termios).expect("tcsetattr");

        (pty, name)
    }

    #[test]
    fn stat_tty_reports_character_device() {
        let (pty, name) = open_fake_tty();
        let info = stat_tty(&name).expect("stat_tty");
        let _ = info.writable;
        drop(pty);
    }

    #[tokio::test]
    async fn deliver_message_writes_to_pty() {
        let (pty, name) = open_fake_tty();

        deliver_message(&name, b"hello pty\r\n", Duration::from_secs(2))
            .await
            .expect("deliver_message");

        let mut buf = [0u8; 64];
        let n = nix::unistd::read(&pty.master, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"hello pty\r\n");
    }

    #[tokio::test]
    async fn deliver_message_to_missing_tty_is_unavailable() {
        let err = deliver_message("this-tty-does-not-exist", b"x", Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, TtyError::Unavailable(_)));
    }
}
