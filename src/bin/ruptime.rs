use anyhow::Context;
use chrono::{Duration, Utc};
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};

use roowho2_lib::{
    proto::WhodStatusUpdate,
    server::varlink_api::{
        DEFAULT_CLIENT_SERVER_SOCKET_PATH, VarlinkRwhodClientError, VarlinkRwhodClientProxy,
    },
    version,
};

/// Show host status of local machines.
///
/// `ruptime` gives a status line like uptime for each machine on the local network;
/// these are formed from packets broadcast by each host on the network once a minute.
///
/// Machines for which no status report has been received for a while (11 minutes by default,
/// see `--uptime-timeout`) are shown as being down.
#[derive(Debug, Parser)]
#[command(
  author = "Programvareverkstedet <projects@pvv.ntnu.no>",
  version,
  long_version = version::LONG_VERSION
)]
pub struct Args {
    /// Users idle an hour or more are not counted unless the `-a` flag is given.
    #[arg(long, short, conflicts_with = "idle_timeout")]
    all: bool,

    /// Only count users idle for less than this many minutes.
    /// Cannot be used together with `--all`.
    #[arg(long, value_name = "MINUTES", default_value_t = DEFAULT_IDLE_TIMEOUT_MINUTES)]
    idle_timeout: u32,

    /// Consider a machine down if no status report has been received from it for this many minutes.
    #[arg(long, value_name = "MINUTES", default_value_t = DEFAULT_UPTIME_TIMEOUT_MINUTES)]
    uptime_timeout: u32,

    /// Sort by load average.
    #[arg(long, short, group = "sort_mode")]
    load: bool,

    /// Reverses the sort order.
    #[arg(long, short)]
    reverse: bool,

    /// Sort by uptime.
    #[arg(long, short, group = "sort_mode")]
    time: bool,

    /// Sort by number of users.
    #[arg(long, short, group = "sort_mode")]
    users: bool,

    /// Print the output with the old formatting
    #[arg(long, short)]
    old: bool,

    /// Output in JSON format
    #[arg(long, short, conflicts_with_all = ["sort_mode", "reverse"])]
    json: bool,

    /// Generate shell completion scripts for the specified shell
    /// and print them to stdout.
    #[arg(long, value_enum, hide = true)]
    completions: Option<Shell>,
}

/// Users idle for longer than this are not counted by default.
const DEFAULT_IDLE_TIMEOUT_MINUTES: u32 = 60;

/// Machines that haven't reported in for longer than this are shown as down by default.
const DEFAULT_UPTIME_TIMEOUT_MINUTES: u32 = 11;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        generate(
            shell,
            &mut Args::command(),
            "ruptime",
            &mut std::io::stdout(),
        );
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

    let mut reply = conn
        .ruptime(max_idle_seconds)
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

    sort_entries(&mut reply, args.load, args.time, args.users, args.reverse);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    // } else if args.old {
    //     for entry in &reply {
    //         let line = old_format_machine_entry(args.all, entry);
    //         println!("{}", line);
    //     }
    } else {
        for entry in &reply {
            let line = old_format_machine_entry(entry, args.uptime_timeout);
            println!("{}", line);
        }
    }

    Ok(())
}

fn sort_entries(
    entries: &mut [WhodStatusUpdate],
    sort_by_load: bool,
    sort_by_time: bool,
    sort_by_users: bool,
    reverse: bool,
) {
    entries.sort_by(|entry1, entry2| {
        let ordering = if sort_by_load {
            let load1 = entry1.load_average.0 + entry1.load_average.1 + entry1.load_average.2;
            let load2 = entry2.load_average.0 + entry2.load_average.1 + entry2.load_average.2;
            load1
                .partial_cmp(&load2)
                .unwrap_or(std::cmp::Ordering::Equal)
        } else if sort_by_time {
            let uptime1 = Utc::now() - entry1.sendtime;
            let uptime2 = Utc::now() - entry2.sendtime;
            uptime1.cmp(&uptime2)
        } else if sort_by_users {
            let users1 = entry1.users.len();
            let users2 = entry2.users.len();
            users1.cmp(&users2)
        } else {
            entry1.hostname.cmp(&entry2.hostname)
        };

        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn old_format_machine_entry(entry: &WhodStatusUpdate, uptime_timeout_minutes: u32) -> String {
    let time_since_last_ping = Utc::now() - entry.sendtime;
    let is_up = time_since_last_ping <= Duration::minutes(i64::from(uptime_timeout_minutes));

    let uptime = Utc::now() - entry.boot_time;
    let days = uptime.num_days();
    let hours = uptime.num_hours() % 24;
    let minutes = uptime.num_minutes() % 60;

    let uptime_str = if uptime.num_seconds() < 0 || days > 999 {
        "    ??:??".to_string()
    } else if days > 0 {
        format!("{:3}+{:02}:{:02}", days, hours, minutes)
    } else {
        format!("    {:2}:{:02}", hours, minutes)
    };

    let user_count = entry.users.len();

    format!(
        "{:<12.12} {} {},  {:4} user{}  load {:>4.2}, {:>4.2}, {:>4.2}",
        entry.hostname,
        if is_up { "up" } else { "down" },
        uptime_str,
        user_count,
        if user_count == 1 { ", " } else { "s," },
        entry.load_average.0 as f32 / 100.0,
        entry.load_average.1 as f32 / 100.0,
        entry.load_average.2 as f32 / 100.0,
    )
}
