use std::io::Read as _;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};

use roowho2_lib::server::varlink_api::{
    DEFAULT_CLIENT_SERVER_SOCKET_PATH, VarlinkWalldClientProxy, VarlinkWalldClientResponse,
};

/// Send a message to another user
#[derive(Debug, Parser)]
#[command(author = "Programvareverkstedet <projects@pvv.ntnu.no>", version)]
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

    VarlinkWalldClientProxy::write(&mut conn, user, args.ttyname, message)
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
