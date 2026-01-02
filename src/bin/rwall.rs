use clap::Parser;

/// Send a message to users logged on a host.
///
/// The `rwall` command sends a message to the users logged into the specified host.
/// The message to be sent can be typed in and terminated with EOF or it can be in a file
#[derive(Debug, Parser)]
pub struct Args {
    /// The host to send the message to
    host: String,

    /// The file containing the message to be sent
    #[arg(value_name = "PATH")]
    file: Option<String>,
}

fn main() {
    let _args = Args::parse();
    unimplemented!()
}
