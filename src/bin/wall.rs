use std::{
    io::{self, Read as _},
    os::fd::AsFd,
};

use anyhow::Context;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use nix::unistd;
use roowho2_lib::{
    server::varlink_api::{
        DEFAULT_CLIENT_SERVER_SOCKET_PATH, VarlinkWalldClientProxy, VarlinkWalldClientResponse,
    },
    version,
};

/// Write a message to all users
#[derive(Debug, Parser)]
#[command(
  author = "Programvareverkstedet <projects@pvv.ntnu.no>",
  version,
  long_version = version::LONG_VERSION
)]
pub struct Args {
    /// Only send message to group
    #[arg(long, short, value_name = "GROUP")]
    group: Option<String>,

    // TODO: this 'works only for root' is leftover from the original wall implementation, no?
    //       maybe add it to the integration test?
    /// Do not print banner, works only for root
    #[arg(long, short)]
    nobanner: bool,

    /// Write timeout in seconds
    #[arg(long, short, value_name = "TIMEOUT", default_value_t = 30)]
    timeout: u32,

    /// Message to send, if not specified, read from stdin
    #[arg(value_name = "MESSAGE | FILE")]
    file_or_message: Option<String>,

    /// Generate shell completion scripts for the specified shell
    /// and print them to stdout.
    #[arg(long, value_enum, hide = true)]
    completions: Option<Shell>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        generate(shell, &mut Args::command(), "wall", &mut std::io::stdout());
        return Ok(());
    }

    let message = read_message(args.file_or_message.as_deref())?;

    let mut conn = zlink::tokio::unix::connect(DEFAULT_CLIENT_SERVER_SOCKET_PATH)
        .await
        .with_context(|| {
            format!("failed to connect to roowho2 at {DEFAULT_CLIENT_SERVER_SOCKET_PATH}")
        })?;

    let stdin = io::stdin();
    let source_tty = if !unistd::isatty(stdin.as_fd()).unwrap_or(false) {
        None
    } else {
        // TODO: should we send this as a CStr maybe?
        unistd::ttyname(stdin.as_fd())
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    };

    let response = conn
        .wall(source_tty, message, args.group, args.nobanner, args.timeout)
        .await
        .context("varlink call to walld failed")?
        .map_err(|err| anyhow::format_err!("{err}"))
        .and_then(|res| {
            if let VarlinkWalldClientResponse::Wall(r) = res {
                Ok(r)
            } else {
                Err(anyhow::format_err!(
                    "unexpected response from walld: {:?}",
                    res
                ))
            }
        })?;

    for failure in &response.failures {
        eprintln!(
            "wall: could not reach {} on {}: {}",
            failure.user, failure.tty, failure.reason
        );
    }

    if !response.failures.is_empty() && response.delivered.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn read_message(file_or_message: Option<&str>) -> anyhow::Result<String> {
    match file_or_message {
        Some(arg) if std::path::Path::new(arg).is_file() => {
            std::fs::read_to_string(arg).with_context(|| format!("cannot read {arg}"))
        }
        Some(text) => Ok(text.to_string()),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read message from stdin")?;
            Ok(buf)
        }
    }
}
