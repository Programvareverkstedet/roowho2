use std::array;

use bytes::{Buf, BufMut, BytesMut};
use chrono::{DateTime, Duration, Utc};

/// Classic C struct for utmp data for a single user session.
///
/// This struct is used in the rwhod protocol by being interpreted as raw bytes to be sent over UDP.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Outmp {
    /// tty name
    pub out_line: [u8; Self::MAX_TTY_NAME_LEN],
    /// user id
    pub out_name: [u8; Self::MAX_USER_ID_LEN],
    /// time on
    pub out_time: i32,
}

impl Outmp {
    pub const MAX_TTY_NAME_LEN: usize = 8;
    pub const MAX_USER_ID_LEN: usize = 8;
}

/// Classic C struct for a single user session.
///
/// This struct is used in the rwhod protocol by being interpreted as raw bytes to be sent over UDP.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Whoent {
    /// active tty info
    pub we_utmp: Outmp,
    /// tty idle time
    pub we_idle: i32,
}

impl Whoent {
    pub const SIZE: usize = std::mem::size_of::<Self>();

    fn zeroed() -> Self {
        Self {
            we_utmp: Outmp {
                out_line: [0u8; Outmp::MAX_TTY_NAME_LEN],
                out_name: [0u8; Outmp::MAX_USER_ID_LEN],
                out_time: 0,
            },
            we_idle: 0,
        }
    }

    fn is_zeroed(&self) -> bool {
        self.we_utmp.out_line.iter().all(|&b| b == 0)
            && self.we_utmp.out_name.iter().all(|&b| b == 0)
            && self.we_utmp.out_time == 0
            && self.we_idle == 0
    }
}

/// Classic C struct for a rwhod status update.
///
/// This struct is used in the rwhod protocol by being interpreted as raw bytes to be sent over UDP.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Whod {
    /// protocol version
    pub wd_vers: u8,
    /// packet type, see below
    pub wd_type: u8,
    pub wd_pad: [u8; 2],
    /// time stamp by sender
    pub wd_sendtime: i32,
    /// time stamp applied by receiver
    pub wd_recvtime: i32,
    /// host's name
    pub wd_hostname: [u8; Self::MAX_HOSTNAME_LEN],
    /// load average as in uptime
    pub wd_loadav: [i32; 3],
    /// time system booted
    pub wd_boottime: i32,
    pub wd_we: [Whoent; Self::MAX_WHOENTRIES],
}

impl Whod {
    pub const HEADER_SIZE: usize = 1 + 1 + 2 + 4 + 4 + Self::MAX_HOSTNAME_LEN + 4 * 3 + 4;
    pub const MAX_SIZE: usize = std::mem::size_of::<Self>();

    pub const MAX_HOSTNAME_LEN: usize = 32;
    pub const MAX_WHOENTRIES: usize = 1024 / std::mem::size_of::<Whoent>();

    pub const WHODVERSION: u8 = 1;

    // NOTE: there was probably meant to be more packet types, but only status is defined.
    pub const WHODTYPE_STATUS: u8 = 1;

    pub fn new(
        sendtime: i32,
        recvtime: i32,
        hostname: [u8; Self::MAX_HOSTNAME_LEN],
        loadav: [i32; 3],
        boottime: i32,
        whoentries: [Whoent; Self::MAX_WHOENTRIES],
    ) -> Self {
        debug_assert!(
            whoentries
                .iter()
                .skip_while(|entry| !entry.is_zeroed())
                .all(|entry| entry.is_zeroed())
        );

        Self {
            wd_vers: Self::WHODVERSION,
            wd_type: Self::WHODTYPE_STATUS,
            wd_pad: [0u8; 2],
            wd_sendtime: sendtime,
            wd_recvtime: recvtime,
            wd_hostname: hostname,
            wd_loadav: loadav,
            wd_boottime: boottime,
            wd_we: whoentries,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(Whod::MAX_SIZE);
        buf.put_u8(self.wd_vers);
        buf.put_u8(self.wd_type);
        buf.put_slice(&self.wd_pad);
        buf.put_i32(self.wd_sendtime);
        buf.put_i32(self.wd_recvtime);
        buf.put_slice(&self.wd_hostname);
        buf.put_i32(self.wd_loadav[0]);
        buf.put_i32(self.wd_loadav[1]);
        buf.put_i32(self.wd_loadav[2]);
        buf.put_i32(self.wd_boottime);

        for whoent in self.wd_we.iter().take_while(|entry| !entry.is_zeroed()) {
            buf.put_slice(&whoent.we_utmp.out_line);
            buf.put_slice(&whoent.we_utmp.out_name);
            buf.put_i32(whoent.we_utmp.out_time);
            buf.put_i32(whoent.we_idle);
        }

        buf.to_vec()
    }

    pub fn from_bytes(input: &[u8]) -> anyhow::Result<Self> {
        if input.len() < Self::HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Not enough bytes to parse packet header: {} < {}",
                input.len(),
                Self::HEADER_SIZE
            ));
        }

        if input.len() > Self::MAX_SIZE {
            return Err(anyhow::anyhow!(
                "Too many bytes to parse packet: {} > {}",
                input.len(),
                Self::MAX_SIZE
            ));
        }

        if !(input.len() - Self::HEADER_SIZE).is_multiple_of(Whoent::SIZE) {
            return Err(anyhow::anyhow!(
                "Invalid packet length: {} (not aligned with struct sizes, should be {} + N * {})",
                input.len(),
                Self::HEADER_SIZE,
                Whoent::SIZE,
            ));
        }

        let mut bytes = bytes::Bytes::copy_from_slice(input);

        let wd_vers = bytes.get_u8();
        debug_assert!(wd_vers == Self::WHODVERSION);

        let wd_type = bytes.get_u8();
        debug_assert!(wd_type == Self::WHODTYPE_STATUS);

        bytes.advance(2); // skip wd_pad

        let wd_sendtime = bytes.get_i32();
        let wd_recvtime = bytes.get_i32();
        let mut wd_hostname = [0u8; Self::MAX_HOSTNAME_LEN];
        bytes.copy_to_slice(&mut wd_hostname);
        let wd_loadav = [bytes.get_i32(), bytes.get_i32(), bytes.get_i32()];
        let wd_boottime = bytes.get_i32();

        debug_assert!(bytes.remaining() + Self::HEADER_SIZE == input.len());

        let mut wd_we = array::from_fn(|_| Whoent::zeroed());

        for (byte_chunk, whoent) in bytes.chunks_exact(Whoent::SIZE).zip(wd_we.iter_mut()) {
            let mut chunk_bytes = bytes::Bytes::copy_from_slice(byte_chunk);

            let mut out_line = [0u8; Outmp::MAX_TTY_NAME_LEN];
            chunk_bytes.copy_to_slice(&mut out_line);
            let mut out_name = [0u8; Outmp::MAX_USER_ID_LEN];
            chunk_bytes.copy_to_slice(&mut out_name);
            let out_time = chunk_bytes.get_i32();

            let we_utmp = Outmp {
                out_line,
                out_name,
                out_time,
            };
            let we_idle = chunk_bytes.get_i32();

            *whoent = Whoent { we_utmp, we_idle };
        }

        let result = Whod::new(
            wd_sendtime,
            wd_recvtime,
            wd_hostname,
            wd_loadav,
            wd_boottime,
            wd_we,
        );

        Ok(result)
    }
}

// ------------------------------------------------

/// High-level representation of a rwhod status update.
///
/// This struct is intended for easier use in Rust code, with proper types and dynamic arrays.
/// It can be converted to and from the low-level [`Whod`] struct used for network transmission.
#[derive(Debug, Clone)]
pub struct WhodStatusUpdate {
    // NOTE: there is only one defined packet type, so we just omit it here
    /// Timestamp by sender
    pub sendtime: DateTime<Utc>,

    /// Timestamp applied by receiver
    pub recvtime: Option<DateTime<Utc>>,

    /// Name of the host sending the status update (max 32 characters)
    pub hostname: String,

    /// load average over 5 minutes multiplied by 100
    pub load_average_5_min: i32,
    /// load average over 10 minutes multiplied by 100
    pub load_average_10_min: i32,
    /// load average over 15 minutes multiplied by 100
    pub load_average_15_min: i32,

    /// Which time the system was booted
    pub boot_time: DateTime<Utc>,

    /// List of users currently logged in to the host (max 42 entries)
    pub users: Vec<WhodUserEntry>,
}

impl WhodStatusUpdate {
    pub fn new(
        sendtime: DateTime<Utc>,
        recvtime: Option<DateTime<Utc>>,
        hostname: String,
        load_average_5_min: i32,
        load_average_10_min: i32,
        load_average_15_min: i32,
        boot_time: DateTime<Utc>,
        users: Vec<WhodUserEntry>,
    ) -> Self {
        Self {
            sendtime,
            recvtime,
            hostname,
            load_average_5_min,
            load_average_10_min,
            load_average_15_min,
            boot_time,
            users,
        }
    }
}

/// High-level representation of a single user session in a rwhod status update.
///
/// This struct is intended for easier use in Rust code, with proper types.
/// It can be converted to and from the low-level [`Whoent`] struct used for network transmission.
#[derive(Debug, Clone)]
pub struct WhodUserEntry {
    /// TTY name (max 8 characters)
    pub tty: String,

    /// User ID (max 8 characters)
    pub user_id: String,

    /// Time when the user logged in
    pub login_time: DateTime<Utc>,

    /// How long since the user last typed on the TTY
    pub idle_time: Duration,
}

impl WhodUserEntry {
    pub fn new(
        tty: String,
        user_id: String,
        login_time: DateTime<Utc>,
        idle_time: Duration,
    ) -> Self {
        Self {
            tty,
            user_id,
            login_time,
            idle_time,
        }
    }
}

impl TryFrom<Whoent> for WhodUserEntry {
    type Error = String;

    fn try_from(value: Whoent) -> Result<Self, Self::Error> {
        let tty_end = value
            .we_utmp
            .out_line
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(value.we_utmp.out_line.len());
        let tty = String::from_utf8(value.we_utmp.out_line[..tty_end].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in TTY name: {}", e))?;

        let user_id_end = value
            .we_utmp
            .out_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(value.we_utmp.out_name.len());
        let user_id = String::from_utf8(value.we_utmp.out_name[..user_id_end].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in user ID: {}", e))?;

        let login_time = DateTime::from_timestamp_secs(value.we_utmp.out_time as i64).ok_or(
            format!("Invalid login time timestamp: {}", value.we_utmp.out_time),
        )?;

        Ok(WhodUserEntry {
            tty,
            user_id,
            login_time,
            idle_time: Duration::seconds(value.we_idle as i64),
        })
    }
}

impl TryFrom<Whod> for WhodStatusUpdate {
    type Error = String;

    fn try_from(value: Whod) -> Result<Self, Self::Error> {
        if value.wd_vers != Whod::WHODVERSION {
            return Err(format!(
                "Unsupported whod protocol version: {}",
                value.wd_vers
            ));
        }

        let sendtime = DateTime::from_timestamp_secs(value.wd_sendtime as i64).ok_or(format!(
            "Invalid send time timestamp: {}",
            value.wd_sendtime
        ))?;

        let recvtime = if value.wd_recvtime == 0 {
            None
        } else {
            Some(
                DateTime::from_timestamp_secs(value.wd_recvtime as i64).ok_or(format!(
                    "Invalid receive time timestamp: {}",
                    value.wd_recvtime
                ))?,
            )
        };

        let hostname_end = value
            .wd_hostname
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(value.wd_hostname.len());
        let hostname = String::from_utf8(value.wd_hostname[..hostname_end].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in hostname: {}", e))?;

        let boot_time = DateTime::from_timestamp_secs(value.wd_boottime as i64).ok_or(format!(
            "Invalid boot time timestamp: {}",
            value.wd_boottime
        ))?;

        let users = value
            .wd_we
            .iter()
            .take_while(|whoent| !whoent.is_zeroed())
            .cloned()
            .map(WhodUserEntry::try_from)
            .collect::<Result<Vec<WhodUserEntry>, String>>()?;

        Ok(WhodStatusUpdate {
            sendtime,
            recvtime,
            hostname,
            load_average_5_min: value.wd_loadav[0],
            load_average_10_min: value.wd_loadav[1],
            load_average_15_min: value.wd_loadav[2],
            boot_time,
            users,
        })
    }
}

impl TryFrom<WhodUserEntry> for Whoent {
    type Error = String;

    fn try_from(value: WhodUserEntry) -> Result<Self, Self::Error> {
        let mut out_line = [0u8; Outmp::MAX_TTY_NAME_LEN];
        let tty_bytes = value.tty.as_bytes();
        out_line[..tty_bytes.len().min(Outmp::MAX_TTY_NAME_LEN)].copy_from_slice(tty_bytes);

        let mut out_name = [0u8; Outmp::MAX_USER_ID_LEN];
        let user_id_bytes = value.user_id.as_bytes();
        out_name[..user_id_bytes.len().min(Outmp::MAX_USER_ID_LEN)].copy_from_slice(user_id_bytes);

        let out_time = value
            .login_time
            .timestamp()
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32;

        let we_idle = value
            .idle_time
            .num_seconds()
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32;

        Ok(Whoent {
            we_utmp: Outmp {
                out_line,
                out_name,
                out_time,
            },
            we_idle,
        })
    }
}

impl TryFrom<WhodStatusUpdate> for Whod {
    type Error = String;

    fn try_from(value: WhodStatusUpdate) -> Result<Self, Self::Error> {
        let mut wd_hostname = [0u8; Whod::MAX_HOSTNAME_LEN];
        let hostname_bytes = value.hostname.as_bytes();
        wd_hostname[..hostname_bytes.len().min(Whod::MAX_HOSTNAME_LEN)]
            .copy_from_slice(hostname_bytes);

        let wd_sendtime = value
            .sendtime
            .timestamp()
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32;

        let wd_recvtime = value.recvtime.map_or(0, |dt| {
            dt.timestamp().clamp(i32::MIN as i64, i32::MAX as i64) as i32
        });

        let wd_boottime = value
            .boot_time
            .timestamp()
            .clamp(i32::MIN as i64, i32::MAX as i64) as i32;

        let wd_we = value
            .users
            .into_iter()
            .map(Whoent::try_from)
            .chain(std::iter::repeat(Ok(Whoent::zeroed())))
            .take(Whod::MAX_WHOENTRIES)
            .collect::<Result<Vec<Whoent>, String>>()?
            .try_into()
            .expect("Length mismatch, this should never happen");

        Ok(Whod {
            wd_vers: Whod::WHODVERSION,
            wd_type: Whod::WHODTYPE_STATUS,
            wd_pad: [0u8; 2],
            wd_sendtime,
            wd_recvtime,
            wd_hostname,
            wd_loadav: [
                value.load_average_5_min,
                value.load_average_10_min,
                value.load_average_15_min,
            ],
            wd_boottime,
            wd_we,
        })
    }
}
