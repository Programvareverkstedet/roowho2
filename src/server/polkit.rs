//! polkit authorization checks against `org.freedesktop.PolicyKit1.Authority`.

use std::collections::HashMap;

use anyhow::Context;
use zbus::{Connection, proxy, zvariant::Value};

#[proxy(
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority",
    interface = "org.freedesktop.PolicyKit1.Authority"
)]
trait Authority {
    #[allow(clippy::type_complexity)]
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: &HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

#[proxy(
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    interface = "org.freedesktop.login1.Manager"
)]
trait LoginManager {
    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[proxy(interface = "org.freedesktop.login1.Session")]
trait LoginSession {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
}

#[derive(Clone)]
pub struct PolkitAuthority {
    connection: Connection,
}

impl PolkitAuthority {
    pub async fn connect() -> anyhow::Result<Self> {
        let connection = Connection::system()
            .await
            .context("failed to connect to the D-Bus system bus")?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Resolve `pid`'s logind session id, if it has one.
    async fn session_id_for_pid(&self, pid: u32) -> Option<String> {
        let manager = LoginManagerProxy::new(&self.connection).await.ok()?;
        let path = manager.get_session_by_pid(pid).await.ok()?;
        let session = LoginSessionProxy::builder(&self.connection)
            .path(path)
            .ok()?
            .build()
            .await
            .ok()?;
        session.id().await.ok()
    }

    /// Build a polkit subject for `pid`, using details from `logind` if possible.
    async fn subject(
        &self,
        pid: u32,
    ) -> anyhow::Result<(&'static str, HashMap<&'static str, Value<'_>>)> {
        if let Some(session_id) = self.session_id_for_pid(pid).await {
            let mut details = HashMap::new();
            details.insert("session-id", Value::from(session_id));
            return Ok(("unix-session", details));
        }

        let start_time = process_start_time(pid)?;
        let mut details = HashMap::new();
        details.insert("pid", Value::from(pid));
        details.insert("start-time", Value::from(start_time));
        Ok(("unix-process", details))
    }

    /// Ask polkit whether `pid` is authorized to perform `action_id`
    pub(crate) async fn check(
        &self,
        pid: u32,
        action_id: &str,
        details: HashMap<&str, &str>,
    ) -> anyhow::Result<bool> {
        let proxy = AuthorityProxy::new(&self.connection)
            .await
            .context("failed to build polkit Authority proxy")?;

        let subject = self.subject(pid).await?;

        let (authorized, _interactive, _details) = proxy
            .check_authorization(&subject, action_id, &details, 0, "")
            .await
            .context("CheckAuthorization call failed")?;

        Ok(authorized)
    }
}

/// Read a process's start time from `/proc/<pid>/stat`
fn process_start_time(pid: u32) -> anyhow::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("failed to read /proc/{pid}/stat"))?;

    let after_comm = stat
        .rsplit_once(')')
        .with_context(|| format!("malformed /proc/{pid}/stat"))?
        .1;

    // starttime is field 22; index 19 once `state` (field 3) is index 0.
    after_comm
        .split_whitespace()
        .nth(19)
        .with_context(|| format!("missing starttime field in /proc/{pid}/stat"))?
        .parse::<u64>()
        .context("starttime field is not a valid number")
}
