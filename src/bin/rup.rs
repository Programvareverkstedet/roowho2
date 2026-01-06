use clap::Parser;

/// Remote status display.
///
/// `rup` displays a summary of the current system status of a particular host or all hosts on the local network.
/// The output shows the current time of day, how long the system has been up, and the load averages.
/// The load average numbers give the number of jobs in the run queue averaged over 1, 5 and 15 minutes.
#[derive(Debug, Parser)]
#[command(
    author = "Programvareverkstedet <projects@pvv.ntnu.no>",
    about,
    version,
)]
pub struct Args {
    /// The hosts to query.
    hosts: Vec<String>,

    /// For each host, report what its local time is.
    /// This is useful for checking time syncronization on a network.
    #[arg(long, short)]
    date: bool,

    /// Print time data in seconds (seconds of uptime or seconds since the epoch), for scripts.
    #[arg(long, short)]
    seconds: bool,

    /// Sort the display alphabetically by host name.
    #[arg(long, short)]
    hostname: bool,

    /// Sort the display by load average.
    #[arg(long, short)]
    load: bool,

    /// Sort the display by uptime.
    #[arg(long, short)]
    uptime: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,
}

fn main() {
    let _args = Args::parse();
    unimplemented!()
}
