use clap::Parser;

/// Check who is logged in to machines on local network.
///
/// The `rusers` command produces output similar to `who`,
/// but for the list of hosts or all machines on the local network.
/// For each host responding to the rusers query,
/// the host‐name with the names of the users currently logged on is printed on each line.
/// The `rusers` command will wait for one minute to catch late responders.
#[derive(Debug, Parser)]
pub struct Args {
    /// Print all machines responding even if no one is currently logged in
    #[arg(long, short)]
    all: bool,

    /// Print a long format listing.
    /// This includes:
    ///   - the user name
    ///   - the host name
    ///   - the tty that the user is logged in to
    ///   - the date and time the user logged in
    ///   - the amount of time since the user typed on the keyboard
    ///   - the remote host they logged in from (if applicable)
    #[arg(long, short)]
    long: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,
}

fn main() {
    let _args = Args::parse();
    unimplemented!()
}
