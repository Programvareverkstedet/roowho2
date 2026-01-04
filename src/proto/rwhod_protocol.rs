use std::array;

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

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Whoent {
    /// active tty info
    pub we_utmp: Outmp,
    /// tty idle time
    pub we_idle: i32,
}

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
    pub const SIZE: usize = std::mem::size_of::<Whod>();
    pub const MAX_HOSTNAME_LEN: usize = 32;
    pub const MAX_WHOENTRIES: usize = 1024 / std::mem::size_of::<Whoent>();

    pub const WHODVERSION: u8 = 1;

    // NOTE: there was probably meant to be more packet types, but only status is defined.
    pub const WHODTYPE_STATUS: u8 = 1;

    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<Whod>()] {
        unsafe { std::mem::transmute_copy(self) }
    }

    // TODO: we should probably make a safer parser.
    pub fn from_bytes(bytes: &[u8; std::mem::size_of::<Whod>()]) -> Self {
        unsafe { std::mem::transmute_copy(bytes) }
    }
}

// ------------------------------------------------

#[derive(Debug, Clone)]
pub struct WhodStatusUpdate {
    // NOTE: there is only one defined packet type, so we just omit it here
    /// Timestamp by sender
    sendtime: chrono::DateTime<chrono::Utc>,

    /// Timestamp applied by receiver
    recvtime: Option<chrono::DateTime<chrono::Utc>>,

    /// Name of the host sending the status update (max 32 characters)
    hostname: String,

    /// load average over 5 minutes multiplied by 100
    load_average_5_min: i32,
    /// load average over 10 minutes multiplied by 100
    load_average_10_min: i32,
    /// load average over 15 minutes multiplied by 100
    load_average_15_min: i32,

    /// Which time the system was booted
    boot_time: chrono::DateTime<chrono::Utc>,

    /// List of users currently logged in to the host (max 42 entries)
    users: Vec<WhodUserEntry>,
}

impl WhodStatusUpdate {
    pub fn new(
        sendtime: chrono::DateTime<chrono::Utc>,
        recvtime: Option<chrono::DateTime<chrono::Utc>>,
        hostname: String,
        load_average_5_min: i32,
        load_average_10_min: i32,
        load_average_15_min: i32,
        boot_time: chrono::DateTime<chrono::Utc>,
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

#[derive(Debug, Clone)]
pub struct WhodUserEntry {
    /// TTY name (max 8 characters)
    tty: String,

    /// User ID (max 8 characters)
    user_id: String,

    /// Time when the user logged in
    login_time: chrono::DateTime<chrono::Utc>,

    /// Idle time in seconds
    idle_time_seconds: i32,
}

impl WhodUserEntry {
    pub fn new(
        tty: String,
        user_id: String,
        login_time: chrono::DateTime<chrono::Utc>,
        idle_time_seconds: i32,
    ) -> Self {
        Self {
            tty,
            user_id,
            login_time,
            idle_time_seconds,
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

        let login_time = chrono::DateTime::from_timestamp_secs(value.we_utmp.out_time as i64)
            .ok_or(format!(
                "Invalid login time timestamp: {}",
                value.we_utmp.out_time
            ))?;

        Ok(WhodUserEntry {
            tty,
            user_id,
            login_time,
            idle_time_seconds: value.we_idle,
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

        let sendtime = chrono::DateTime::from_timestamp_secs(value.wd_sendtime as i64).ok_or(
            format!("Invalid send time timestamp: {}", value.wd_sendtime),
        )?;

        let recvtime = if value.wd_recvtime == 0 {
            None
        } else {
            Some(
                chrono::DateTime::from_timestamp_secs(value.wd_recvtime as i64).ok_or(format!(
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

        let boot_time = chrono::DateTime::from_timestamp_secs(value.wd_boottime as i64).ok_or(
            format!("Invalid boot time timestamp: {}", value.wd_boottime),
        )?;

        let mut users = Vec::new();
        for whoent in &value.wd_we {
            let user_entry = WhodUserEntry::try_from(whoent.clone())?;
            users.push(user_entry);
        }

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

// TODO: support less strict conversions with truncation

impl TryFrom<WhodUserEntry> for Whoent {
    type Error = String;

    fn try_from(value: WhodUserEntry) -> Result<Self, Self::Error> {
        let mut out_line = [0u8; 8];
        let tty_bytes = value.tty.as_bytes();
        if tty_bytes.len() > out_line.len() {
            return Err(format!(
                "TTY name too long: {} (max {})",
                value.tty,
                out_line.len()
            ));
        }
        out_line[..tty_bytes.len()].copy_from_slice(tty_bytes);

        let mut out_name = [0u8; 8];
        let user_id_bytes = value.user_id.as_bytes();
        if user_id_bytes.len() > out_name.len() {
            return Err(format!(
                "User ID too long: {} (max {})",
                value.user_id,
                out_name.len()
            ));
        }
        out_name[..user_id_bytes.len()].copy_from_slice(user_id_bytes);

        Ok(Whoent {
            we_utmp: Outmp {
                out_line,
                out_name,
                out_time: value.login_time.timestamp() as i32,
            },
            we_idle: value.idle_time_seconds,
        })
    }
}

// TODO: support less strict conversions with truncation

impl TryFrom<WhodStatusUpdate> for Whod {
    type Error = String;

    fn try_from(value: WhodStatusUpdate) -> Result<Self, Self::Error> {
        let mut wd_hostname = [0u8; Whod::MAX_HOSTNAME_LEN];
        let hostname_bytes = value.hostname.as_bytes();
        if hostname_bytes.len() > wd_hostname.len() {
            return Err(format!(
                "Hostname too long: {} (max {})",
                value.hostname,
                wd_hostname.len()
            ));
        }
        wd_hostname[..hostname_bytes.len()].copy_from_slice(hostname_bytes);

        let mut wd_we = array::from_fn(|_| Whoent {
            we_utmp: Outmp {
                out_line: [0u8; Outmp::MAX_TTY_NAME_LEN],
                out_name: [0u8; Outmp::MAX_USER_ID_LEN],
                out_time: 0,
            },
            we_idle: 0,
        });

        for (i, user_entry) in value.users.into_iter().enumerate() {
            if i >= Whod::MAX_WHOENTRIES {
                break;
            }
            wd_we[i] = Whoent::try_from(user_entry)?;
        }

        Ok(Whod {
            wd_vers: Whod::WHODVERSION,
            wd_type: Whod::WHODTYPE_STATUS,
            wd_pad: [0u8; 2],
            wd_sendtime: value.sendtime.timestamp() as i32,
            wd_recvtime: value.recvtime.map_or(0, |dt| dt.timestamp() as i32),
            wd_hostname,
            wd_loadav: [
                value.load_average_5_min,
                value.load_average_10_min,
                value.load_average_15_min,
            ],
            wd_boottime: value.boot_time.timestamp() as i32,
            wd_we,
        })
    }
}
