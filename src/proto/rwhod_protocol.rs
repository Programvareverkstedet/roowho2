mod time_codec;

use std::array;

use bytes::{Buf, BufMut, BytesMut};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use time_codec::{decode_rwhod_timestamp_near_time, decode_rwhod_timestamp_not_after};

use crate::proto::rwhod_protocol::time_codec::{
    decode_rwhod_timestamp, encode_rwhod_timestamp, rwhod_time_correction,
};

/// Classic C struct for utmp data for a single user session.
///
/// This struct is used in the rwhod protocol by being interpreted as raw bytes to be sent over UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        if wd_vers != Self::WHODVERSION {
            return Err(anyhow::anyhow!(
                "Unsupported whod protocol version: {}",
                wd_vers
            ));
        }

        let wd_type = bytes.get_u8();
        if wd_type != Self::WHODTYPE_STATUS {
            return Err(anyhow::anyhow!("Unsupported whod packet type: {}", wd_type));
        }

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

/// Load average representation: (5 min, 10 min, 15 min)
/// All values are multiplied by 100.
pub type LoadAverage = (i32, i32, i32);

/// High-level representation of a rwhod status update.
///
/// This struct is intended for easier use in Rust code, with proper types and dynamic arrays.
/// It can be converted to and from the low-level [`Whod`] struct used for network transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhodStatusUpdate {
    // NOTE: there is only one defined packet type, so we just omit it here
    /// Timestamp by sender
    pub sendtime: DateTime<Utc>,

    /// Timestamp applied by receiver
    pub recvtime: Option<DateTime<Utc>>,

    /// Name of the host sending the status update (max 32 characters)
    pub hostname: String,

    /// load average over 5, 10, and 15 minutes multiplied by 100
    pub load_average: LoadAverage,

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
        load_average: LoadAverage,
        boot_time: DateTime<Utc>,
        users: Vec<WhodUserEntry>,
    ) -> Self {
        Self {
            sendtime,
            recvtime,
            hostname,
            load_average,
            boot_time,
            users,
        }
    }
}

/// High-level representation of a single user session in a rwhod status update.
///
/// This struct is intended for easier use in Rust code, with proper types.
/// It can be converted to and from the low-level [`Whoent`] struct used for network transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

        let now = Utc::now();
        let login_time = decode_rwhod_timestamp_near_time(value.we_utmp.out_time, now)?;

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

        let now = Utc::now();
        let recvtime_correction = rwhod_time_correction(now, value.wd_recvtime);

        let recvtime = if value.wd_recvtime == 0 {
            None
        } else {
            Some(decode_rwhod_timestamp(
                value.wd_recvtime,
                recvtime_correction,
            )?)
        };

        let recvtime_upper_bound = recvtime.unwrap_or(now);

        let sendtime = if recvtime.is_some() {
            decode_rwhod_timestamp_not_after(
                value.wd_sendtime,
                recvtime_correction,
                recvtime_upper_bound,
            )?
        } else {
            decode_rwhod_timestamp_near_time(value.wd_sendtime, now)?
        };

        let hostname_end = value
            .wd_hostname
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(value.wd_hostname.len());
        let hostname = String::from_utf8(value.wd_hostname[..hostname_end].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in hostname: {}", e))?;

        let boot_time = if recvtime.is_some() {
            decode_rwhod_timestamp_not_after(value.wd_boottime, recvtime_correction, sendtime)?
        } else {
            decode_rwhod_timestamp_not_after(
                value.wd_boottime,
                rwhod_time_correction(sendtime, value.wd_boottime),
                sendtime,
            )?
        };

        let users = value
            .wd_we
            .iter()
            .take_while(|whoent| !whoent.is_zeroed())
            .map(|whoent| {
                let mut user = WhodUserEntry::try_from(whoent.clone())?;
                user.login_time = if recvtime.is_some() {
                    decode_rwhod_timestamp_not_after(
                        whoent.we_utmp.out_time,
                        recvtime_correction,
                        recvtime_upper_bound,
                    )?
                } else {
                    decode_rwhod_timestamp_not_after(
                        whoent.we_utmp.out_time,
                        rwhod_time_correction(sendtime, whoent.we_utmp.out_time),
                        sendtime,
                    )?
                };
                Ok(user)
            })
            .collect::<Result<Vec<WhodUserEntry>, String>>()?;

        Ok(WhodStatusUpdate {
            sendtime,
            recvtime,
            hostname,
            load_average: value.wd_loadav.into(),
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
        let tty_len = tty_bytes.len().min(Outmp::MAX_TTY_NAME_LEN);
        out_line[..tty_len].copy_from_slice(&tty_bytes[..tty_len]);

        let mut out_name = [0u8; Outmp::MAX_USER_ID_LEN];
        let user_id_bytes = value.user_id.as_bytes();
        let user_id_len = user_id_bytes.len().min(Outmp::MAX_USER_ID_LEN);
        out_name[..user_id_len].copy_from_slice(&user_id_bytes[..user_id_len]);

        let out_time = encode_rwhod_timestamp(value.login_time);

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
        let hostname_len = hostname_bytes.len().min(Whod::MAX_HOSTNAME_LEN);
        wd_hostname[..hostname_len].copy_from_slice(&hostname_bytes[..hostname_len]);

        let wd_sendtime = encode_rwhod_timestamp(value.sendtime);
        let wd_recvtime = value.recvtime.map_or(0, encode_rwhod_timestamp);
        let wd_boottime = encode_rwhod_timestamp(value.boot_time);

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
            wd_loadav: value.load_average.into(),
            wd_boottime,
            wd_we,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_whod_serialization_roundtrip() {
        let original_status = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2024, 6, 1, 12, 5, 0).unwrap()),
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2024, 5, 31, 8, 0, 0).unwrap(),
            vec![
                WhodUserEntry::new(
                    "tty1".to_string(),
                    "user1".to_string(),
                    Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap(),
                    Duration::minutes(5),
                ),
                WhodUserEntry::new(
                    "tty2".to_string(),
                    "user2".to_string(),
                    Utc.with_ymd_and_hms(2024, 6, 1, 11, 0, 0).unwrap(),
                    Duration::minutes(10),
                ),
            ],
        );

        let whod_struct =
            Whod::try_from(original_status.clone()).expect("Conversion to Whod failed");
        let bytes = whod_struct.to_bytes();
        let parsed_whod = Whod::from_bytes(&bytes).expect("Parsing from bytes failed");
        let final_status =
            WhodStatusUpdate::try_from(parsed_whod).expect("Conversion from Whod failed");

        assert_eq!(original_status, final_status);
    }

    #[test]
    fn test_parser_invalid_bytes() {
        // Too short
        let short_bytes = vec![0u8; Whod::HEADER_SIZE - 1];
        assert!(Whod::from_bytes(&short_bytes).is_err());

        // Too long
        let long_bytes = vec![0u8; Whod::MAX_SIZE + 1];
        assert!(Whod::from_bytes(&long_bytes).is_err());

        // Misaligned length
        let misaligned_bytes = vec![0u8; Whod::HEADER_SIZE + 1];
        assert!(Whod::from_bytes(&misaligned_bytes).is_err());

        // Invalid version
        let mut invalid_version_bytes = vec![0u8; Whod::HEADER_SIZE];
        invalid_version_bytes[0] = 99; // invalid version
        assert!(Whod::from_bytes(&invalid_version_bytes).is_err());

        // Invalid packet type
        let mut invalid_type_bytes = vec![0u8; Whod::HEADER_SIZE];
        invalid_type_bytes[0] = Whod::WHODVERSION;
        invalid_type_bytes[1] = 99; // invalid type
        assert!(Whod::from_bytes(&invalid_type_bytes).is_err());
    }

    #[test]
    fn test_whod_user_entry_conversion() {
        let user_entry = WhodUserEntry::new(
            "tty1".to_string(),
            "user1".to_string(),
            Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap(),
            Duration::minutes(5),
        );

        let whoent = Whoent::try_from(user_entry.clone()).expect("Conversion to Whoent failed");
        let converted_back =
            WhodUserEntry::try_from(whoent).expect("Conversion from Whoent failed");

        assert_eq!(user_entry, converted_back);
    }

    #[test]
    fn test_whod_status_update_conversion() {
        let status_update = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2024, 6, 1, 12, 5, 0).unwrap()),
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2024, 5, 31, 8, 0, 0).unwrap(),
            vec![
                WhodUserEntry::new(
                    "tty1".to_string(),
                    "user1".to_string(),
                    Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap(),
                    Duration::minutes(5),
                ),
                WhodUserEntry::new(
                    "tty2".to_string(),
                    "user2".to_string(),
                    Utc.with_ymd_and_hms(2024, 6, 1, 11, 0, 0).unwrap(),
                    Duration::minutes(10),
                ),
            ],
        );

        let whod_struct = Whod::try_from(status_update.clone()).expect("Conversion to Whod failed");
        let converted_back =
            WhodStatusUpdate::try_from(whod_struct).expect("Conversion from Whod failed");

        assert_eq!(status_update, converted_back);
    }

    #[test]
    fn test_whod_user_entry_invalid_utf8() {
        let mut whoent = Whoent::zeroed();
        whoent.we_utmp.out_line = [0xff, 0xfe, 0xfd, 0, 0, 0, 0, 0]; // Invalid UTF-8
        whoent.we_utmp.out_name = [0xff, 0xfe, 0xfd, 0, 0, 0, 0, 0]; // Invalid UTF-8
        whoent.we_utmp.out_time = 1_700_000_000; // Some valid timestamp
        whoent.we_idle = 60; // 1 minute

        let result = WhodUserEntry::try_from(whoent);
        assert!(result.is_err());
    }

    #[test]
    fn test_whod_user_entry_conversion_username_gets_truncated() {
        let mut whoent = Whoent::zeroed();
        whoent.we_utmp.out_name = [b'a'; Outmp::MAX_USER_ID_LEN];
        whoent.we_utmp.out_time = 1_700_000_000;
        whoent.we_idle = 60;

        let result = WhodUserEntry::try_from(whoent);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().user_id,
            [b'a'; Outmp::MAX_USER_ID_LEN]
                .iter()
                .map(|&c| c as char)
                .collect::<String>()
        );
    }

    #[test]
    fn test_whod_user_entry_conversion_tty_gets_truncated() {
        let mut whoent = Whoent::zeroed();
        whoent.we_utmp.out_line = [b'b'; Outmp::MAX_TTY_NAME_LEN];
        whoent.we_utmp.out_time = 1_700_000_000;
        whoent.we_idle = 60;

        let result = WhodUserEntry::try_from(whoent);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().tty,
            [b'b'; Outmp::MAX_TTY_NAME_LEN]
                .iter()
                .map(|&c| c as char)
                .collect::<String>()
        );
    }

    #[test]
    fn test_whod_status_update_hostname_gets_truncated() {
        let long_hostname = "a".repeat(Whod::MAX_HOSTNAME_LEN + 10);
        let status_update = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2024, 6, 1, 12, 5, 0).unwrap()),
            long_hostname.clone(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2024, 5, 31, 8, 0, 0).unwrap(),
            vec![],
        );

        let whod_struct = Whod::try_from(status_update.clone()).expect("Conversion to Whod failed");
        let converted_back =
            WhodStatusUpdate::try_from(whod_struct).expect("Conversion from Whod failed");

        assert_eq!(
            converted_back.hostname,
            long_hostname[..Whod::MAX_HOSTNAME_LEN].to_string()
        );
    }

    #[test]
    fn test_whod_status_update_users_get_truncated() {
        let users = (0..(Whod::MAX_WHOENTRIES + 10))
            .map(|i| {
                WhodUserEntry::new(
                    format!("tty{}", i),
                    format!("user{}", i),
                    Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap(),
                    Duration::minutes(i as i64),
                )
            })
            .collect::<Vec<_>>();

        let status_update = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2024, 6, 1, 12, 5, 0).unwrap()),
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2024, 5, 31, 8, 0, 0).unwrap(),
            users,
        );

        let whod_struct = Whod::try_from(status_update.clone()).expect("Conversion to Whod failed");
        let converted_back =
            WhodStatusUpdate::try_from(whod_struct).expect("Conversion from Whod failed");

        assert_eq!(converted_back.users.len(), Whod::MAX_WHOENTRIES);

        for (i, user) in converted_back.users.iter().enumerate() {
            assert_eq!(user.tty, format!("tty{}", i));
            assert_eq!(user.user_id, format!("user{}", i));
        }
    }

    #[test]
    fn test_whod_status_update_usernames_and_ttys_get_truncated() {
        let long_tty = "a".repeat(Outmp::MAX_TTY_NAME_LEN + 10);
        let long_user_id = "b".repeat(Outmp::MAX_USER_ID_LEN + 10);

        let user_entry = WhodUserEntry::new(
            long_tty.clone(),
            long_user_id.clone(),
            Utc.with_ymd_and_hms(2024, 6, 1, 10, 0, 0).unwrap(),
            Duration::minutes(5),
        );

        let whoent = Whoent::try_from(user_entry.clone()).expect("Conversion to Whoent failed");
        let converted_back =
            WhodUserEntry::try_from(whoent).expect("Conversion from Whoent failed");

        assert_eq!(
            converted_back.tty,
            long_tty[..Outmp::MAX_TTY_NAME_LEN].to_string()
        );
        assert_eq!(
            converted_back.user_id,
            long_user_id[..Outmp::MAX_USER_ID_LEN].to_string()
        );
    }

    #[test]
    fn test_whod_status_update_roundtrip_corrects_wrapped_timestamps() {
        let original = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2044, 12, 31, 23, 0, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap()),
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2044, 12, 30, 0, 0, 0).unwrap(),
            vec![WhodUserEntry::new(
                "tty1".to_string(),
                "user".to_string(),
                Utc.with_ymd_and_hms(2044, 12, 31, 22, 0, 0).unwrap(),
                Duration::seconds(60),
            )],
        );

        let whod = Whod::try_from(original.clone()).expect("Conversion to Whod failed");
        let converted = WhodStatusUpdate::try_from(whod).expect("Conversion from Whod failed");

        assert_eq!(converted, original);
    }

    #[test]
    fn test_whod_status_update_roundtrip_sendtime_before_wrap_recvtime_after_wrap() {
        let original = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2038, 1, 19, 3, 13, 0).unwrap(),
            Some(Utc.with_ymd_and_hms(2038, 1, 19, 3, 14, 30).unwrap()),
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2038, 1, 18, 0, 0, 0).unwrap(),
            vec![WhodUserEntry::new(
                "tty1".to_string(),
                "user".to_string(),
                Utc.with_ymd_and_hms(2038, 1, 19, 3, 12, 0).unwrap(),
                Duration::seconds(60),
            )],
        );

        let whod = Whod::try_from(original.clone()).expect("Conversion to Whod failed");
        let converted = WhodStatusUpdate::try_from(whod).expect("Conversion from Whod failed");

        assert_eq!(converted, original);
    }

    #[test]
    fn test_whod_status_update_roundtrip_corrects_wrapped_timestamps_without_recvtime() {
        let original = WhodStatusUpdate::new(
            Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap(),
            None,
            "testhost".to_string(),
            (25, 20, 18),
            Utc.with_ymd_and_hms(2044, 12, 30, 0, 0, 0).unwrap(),
            vec![WhodUserEntry::new(
                "tty1".to_string(),
                "user".to_string(),
                Utc.with_ymd_and_hms(2044, 12, 31, 22, 0, 0).unwrap(),
                Duration::seconds(60),
            )],
        );

        let whod = Whod::try_from(original.clone()).expect("Conversion to Whod failed");
        let converted = WhodStatusUpdate::try_from(whod).expect("Conversion from Whod failed");

        assert_eq!(converted, original);
    }

    #[test]
    fn test_whod_user_entry_roundtrip_corrects_wrapped_timestamp() {
        let original = WhodUserEntry::new(
            "tty1".to_string(),
            "user".to_string(),
            Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap(),
            Duration::seconds(60),
        );

        let whoent = Whoent::try_from(original.clone()).expect("Conversion to Whoent failed");
        let converted_back =
            WhodUserEntry::try_from(whoent).expect("Conversion from Whoent failed");

        assert_eq!(converted_back, original);
    }

    #[test]
    fn test_encode_rwhod_timestamp_wraps_like_i32_cast() {
        let timestamp = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(
            encode_rwhod_timestamp(timestamp),
            timestamp.timestamp() as i32
        );
    }
}
