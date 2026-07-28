use std::collections::BTreeMap;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use roowho2_lib::{
    proto::WhodUserEntry,
    server::varlink_api::{
        DEFAULT_CLIENT_SERVER_SOCKET_PATH, VarlinkRwhodClientError, VarlinkRwhodClientProxy,
    },
};

/// Check who is logged in on local machines.
///
/// The `rwho` command produces output similar to `who`, but for all machines on the local network.
/// If no report has been received from a machine for 11 minutes then rwho assumes the machine is down,
/// and does not report users last known to be logged into that machine.
///
/// If a users hasn't typed to the system for a minute or more, then rwho reports this idle time.
/// If a user hasn't typed to the system for an hour or more,
/// then the user will be omitted from the output of `rwho` unless the `-a` flag is given.
#[derive(Debug, Parser)]
#[command(author = "Programvareverkstedet <projects@pvv.ntnu.no>", version)]
pub struct Args {
    /// Print all machines responding even if no one is currently logged in
    #[arg(long, short, conflicts_with = "idle_timeout")]
    all: bool,

    /// Only show users idle for less than this many minutes.
    /// Cannot be used together with `--all`.
    #[arg(long, value_name = "MINUTES", default_value_t = DEFAULT_IDLE_TIMEOUT_MINUTES)]
    idle_timeout: u32,

    /// Print the output with the old formatting
    #[arg(long, short)]
    old: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,

    /// Generate shell completion scripts for the specified shell
    /// and print them to stdout.
    #[arg(long, value_enum, hide = true)]
    completions: Option<Shell>,
}

/// Users idle for longer than this are omitted from the output by default.
const DEFAULT_IDLE_TIMEOUT_MINUTES: u32 = 60;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        generate(shell, &mut Args::command(), "rwho", &mut std::io::stdout());
        return Ok(());
    }

    let max_idle_seconds = if args.all {
        None
    } else {
        Some(i64::from(args.idle_timeout) * 60)
    };

    let mut conn = zlink::tokio::unix::connect(DEFAULT_CLIENT_SERVER_SOCKET_PATH)
        .await
        .expect("Failed to connect to rwhod server");

    let reply = conn
        .rwho(max_idle_seconds)
        .await
        .context("Failed to send rwho request")?
        .map_err(|e| match e {
            VarlinkRwhodClientError::Disabled => {
                anyhow::anyhow!("The rwhod service is disabled on the server")
            }
            VarlinkRwhodClientError::TimedOut => {
                anyhow::anyhow!("The rwhod service timed out while processing the request")
            }
            VarlinkRwhodClientError::InvalidRequest => {
                anyhow::anyhow!("The rwhod service could not process the request, please check the logs or report the error to your system administrators")
            }
        })?;

    if args.json {
        let sorted: BTreeMap<String, Vec<WhodUserEntry>> = reply
            .into_iter()
            .map(|(hostname, mut users)| {
                users.sort_by(|a, b| a.user_id.cmp(&b.user_id).then_with(|| a.tty.cmp(&b.tty)));
                (hostname, users)
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&sorted).unwrap());
    } else {
        let mut entries: Vec<(String, WhodUserEntry)> = reply
            .into_iter()
            .flat_map(|(hostname, users)| {
                users.into_iter().map(move |user| (hostname.clone(), user))
            })
            .collect();

        entries.sort_by(|(host, user), (host2, user2)| {
            user.user_id
                .cmp(&user2.user_id)
                .then_with(|| host.cmp(host2))
                .then_with(|| user.tty.cmp(&user2.tty))
        });

        if args.old {
            old_format_user_entries(&entries)
                .iter()
                .for_each(|line| println!("{}", line));
        } else {
            // TODO: add a newer and nicer format here
            old_format_user_entries(&entries)
                .iter()
                .for_each(|line| println!("{}", line));
        }
    }

    Ok(())
}

fn old_format_user_entries(entries: &[(String, WhodUserEntry)]) -> Vec<String> {
    let hostname_tty_width = entries
        .iter()
        .map(|(host, user)| host.len() + user.tty.len() + 1)
        .max()
        .unwrap_or(0);

    let idle_time_width = entries
        .iter()
        .map(|(_, user)| user.idle_time.num_hours())
        .max()
        .map(|hours| {
            if hours >= 10 {
                5
            } else if hours > 0 {
                4
            } else {
                3
            }
        })
        .unwrap_or(0);

    entries
        .iter()
        .map(|(hostname, user)| {
            old_format_user_entry(hostname, hostname_tty_width, idle_time_width, user)
        })
        .collect()
}

fn old_format_user_entry(
    hostname: &str,
    hostname_tty_width: usize,
    idle_time_width: usize,
    user: &WhodUserEntry,
) -> String {
    let idle_str = {
        let hours = user.idle_time.num_hours().min(99);
        let minutes = user.idle_time.num_minutes() % 60;
        format!(
            "{}:{:02}",
            if hours == 0 {
                "".to_string()
            } else {
                hours.to_string()
            },
            minutes
        )
    };

    format!(
        "{:<8.8} {:<hostname_tty_width$} {:.12} {:>idle_time_width$}",
        user.user_id,
        format!("{hostname}:{}", user.tty),
        user.login_time.format("%b %d %H:%M"),
        idle_str,
    )
}
