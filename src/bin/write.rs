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

/// Send a message to another user
#[derive(Debug, Parser)]
#[command(
  author = "Programvareverkstedet <projects@pvv.ntnu.no>",
  version,
  long_version = version::LONG_VERSION
)]
pub struct Args {
    /// User to send the message to
    #[arg(value_name = "USER", required_unless_present = "completions")]
    user: Option<String>,

    /// The tty to send the message to
    ttyname: Option<String>,

    /// Generate shell completion scripts for the specified shell
    /// and print them to stdout.
    #[arg(long, value_enum, hide = true)]
    completions: Option<Shell>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        generate(shell, &mut Args::command(), "write", &mut std::io::stdout());
        return Ok(());
    }

    let mut message = String::new();
    std::io::stdin()
        .read_to_string(&mut message)
        .context("failed to read message from stdin")?;

    let mut conn = zlink::tokio::unix::connect(DEFAULT_CLIENT_SERVER_SOCKET_PATH)
        .await
        .with_context(|| {
            format!("failed to connect to roowho2 at {DEFAULT_CLIENT_SERVER_SOCKET_PATH}")
        })?;

    let user = args
        .user
        .expect("required_unless_present=completions guarantees this is set");

    let stdin = io::stdin();
    let source_tty = if !unistd::isatty(stdin.as_fd()).unwrap_or(false) {
        None
    } else {
        // TODO: should we send this as a CStr maybe?
        unistd::ttyname(stdin.as_fd())
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    };

    VarlinkWalldClientProxy::write(&mut conn, source_tty, user, args.ttyname, message)
        .await
        .context("varlink call to walld failed")?
        .map_err(|err| anyhow::format_err!("{err}"))
        .and_then(|res| {
            if let VarlinkWalldClientResponse::Write(r) = res {
                Ok(r)
            } else {
                Err(anyhow::format_err!(
                    "unexpected response from walld: {:?}",
                    res
                ))
            }
        })?;

    Ok(())
}
