use anyhow::Context;
use clap::Parser;
use roowho2_lib::{proto::WhodUserEntry, server::rwhod::RwhodClientProxy};

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
pub struct Args {
    /// Print all machines responding even if no one is currently logged in
    #[arg(long, short)]
    all: bool,

    /// Print the output with the old formatting
    #[arg(long, short)]
    old: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut conn = zlink::unix::connect("/run/roowho2/roowho2.varlink")
        .await
        .expect("Failed to connect to rwhod server");

    let mut reply = conn
        .rwho(args.all)
        .await
        .context("Failed to send rwho request")?
        .map_err(|e| anyhow::anyhow!("Server returned an error for rwho request: {:?}", e))?;

    if !args.all {
        reply.retain(|(_, user)| user.idle_time.num_minutes() <= 11);
    }

    reply.sort_by(|(host, user), (host2, user2)| {
        user.user_id
            .cmp(&user2.user_id)
            .then_with(|| host.cmp(host2))
            .then_with(|| user.tty.cmp(&user2.tty))
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    } else if args.old {
        old_format_user_entries(&reply)
            .iter()
            .for_each(|line| println!("{}", line));
    } else {
        old_format_user_entries(&reply)
            .iter()
            .for_each(|line| println!("{}", line));
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

    let result = entries
        .iter()
        .map(|(hostname, user)| {
            old_format_user_entry(hostname, hostname_tty_width, idle_time_width, user)
        })
        .collect();

    result
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
