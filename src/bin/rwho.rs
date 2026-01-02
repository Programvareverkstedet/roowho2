use clap::Parser;

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

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,
}

fn main() {
    let _args = Args::parse();
    unimplemented!()
}
