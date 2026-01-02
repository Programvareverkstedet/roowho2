use clap::Parser;

/// Show host status of local machines.
///
/// `ruptime` gives a status line like uptime for each machine on the local network;
/// these are formed from packets broadcast by each host on the network once a minute.
///
/// Machines for which no status report has been received for 11 minutes are shown as being down.
#[derive(Debug, Parser)]
pub struct Args {
    /// Users idle an hour or more are not counted unless the `-a` flag is given.
    #[arg(long, short)]
    all: bool,

    /// Sort by load average.
    #[arg(long, short)]
    load: bool,

    /// Reverses the sort order.
    #[arg(long, short)]
    reverse: bool,

    /// Sort by uptime.
    #[arg(long, short)]
    time: bool,

    /// Sort by number of users.
    #[arg(long, short)]
    users: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,
}

fn main() {
    let _args = Args::parse();
    unimplemented!()
}
