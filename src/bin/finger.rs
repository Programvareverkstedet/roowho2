use anyhow::Context;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use roowho2_lib::server::varlink_api::VarlinkFingerClientProxy;

/// User information lookup program
///
/// The `finger` utility displays information about the system users.
///
///
/// If no options are specified, finger defaults to the -l style output if operands are provided, otherwise to the -s style.
/// Note that some fields may be missing, in either format, if information is not available for them.
///
/// If no arguments are specified, finger will print an entry for each user currently logged into the system.
///
/// Finger may be used to look up users on a remote machine.
/// The format is to specify a user as “user@host”, or “@host”,
/// where the default output format for the former is the -l style,
/// and the default output format for the latter is the -s style.
/// The -l option is the only option that may be passed to a remote machine.
///
/// If standard output is a socket, finger will emit a carriage return (^M) before every linefeed (^J).
/// This is for processing remote finger requests when invoked by the daemon.
#[derive(Debug, Parser)]
#[command(
    author = "Programvareverkstedet <projects@pvv.ntnu.no>",
    about,
    version
)]
pub struct Args {
    /// Forces finger to use IPv4 addresses only.
    #[arg(long, short = '4', conflicts_with = "ipv6")]
    ipv4: bool,

    /// Forces finger to use IPv6 addresses only.
    #[arg(long, short = '6', conflicts_with = "ipv4")]
    ipv6: bool,

    /// Display the user's login name, real name, terminal name and write status
    /// (as a ``*'' before the terminal name if write permission is denied),
    /// idle time, login time, and either office location and office phone number,
    /// or the remote host. If -o is given, the office location and office phone number
    /// is printed (the default). If -h is given, the remote host is printed instead.
    ///
    /// Idle time is in minutes if it is a single integer, hours and minutes if a ``:''
    /// is present, or days if a ``d'' is present. If it is an "*", the login time indicates
    /// the time of last login. Login time is displayed as the day name if less than 6 days,
    /// else month, day; hours and minutes, unless more than six months ago, in which case the year
    /// is displayed rather than the hours and minutes.
    ///
    /// Unknown devices as well as nonexistent idle and login times are displayed as single asterisks.
    #[arg(long, short, conflicts_with = "long")]
    short: bool,

    /// When used in conjunction with the -s option, the name of the remote host
    /// is displayed instead of the office location and office phone.
    #[arg(long, short = 'H', requires = "short", conflicts_with = "office")]
    host: bool,

    /// When used in conjunction with the -s option, the office location and
    /// office phone information is displayed instead of the name of the remote host.
    #[arg(long, short, requires = "short", conflicts_with = "host")]
    office: bool,

    /// This option restricts the gecos output to only the users' real name.
    /// It also has the side-effect of restricting the output of the remote host
    /// when used in conjunction with the -h option.
    #[arg(long, short, requires = "short")]
    gecos: bool,

    /// Disable all use of the user accounting database.
    #[arg(short = 'k')]
    no_acct: bool,

    /// Produce a multi-line format displaying all of the information
    /// described for the -s option as well as the user's home directory,
    /// home phone number, login shell, mail status, and the contents of
    /// the files .forward, .plan, .project and .pubkey from the user's home directory.
    ///
    /// If idle time is at least a minute and less than a day, it is presented in the form ``hh:mm''.
    /// Idle times greater than a day are presented as ``d day[s]hh:mm''
    ///
    /// Phone numbers specified as eleven digits are printed as ``+N-NNN-NNN-NNNN''.
    /// Numbers specified as ten or seven digits are printed as the appropriate subset of that string.
    /// Numbers specified as five digits are printed as ``xN-NNNN''.
    /// Numbers specified as four digits are printed as ``xNNNN''.
    ///
    /// If write permission is denied to the device, the phrase ``(messages off)''
    /// is appended to the line containing the device name. One entry per user is displayed with the -l option;
    /// if a user is logged on multiple times, terminal information is repeated once per login.
    ///
    /// Mail status is shown as ``No Mail.'' if there is no mail at all,
    /// ``Mail last read DDD MMM ## HH:MM YYYY (TZ)'' if the person has looked at their mailbox since new mail arriving,
    /// or ``New mail received ...'', ``Unread since ...'' if they have new mail.
    #[arg(long, short, conflicts_with = "short")]
    long: bool,

    /// Prevent the -l option of finger from displaying the contents of
    /// the .forward, .plan, .project and .pubkey files.
    #[arg(long, short, requires = "long")]
    prevent_files: bool,

    /// Prevent matching of user names. User is usually a login name;
    /// however, matching will also be done on the users' real names,
    /// unless the -m option is supplied. All name matching performed by finger is case insensitive.
    #[arg(long, short = 'm')]
    no_name_match: bool,

    /// Output in JSON format
    #[arg(long, short)]
    json: bool,

    /// Generate shell completion scripts for the specified shell
    /// and print them to stdout.
    #[arg(long, value_enum, hide = true)]
    completions: Option<Shell>,

    users: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(shell) = args.completions {
        generate(shell, &mut Args::command(), "rwho", &mut std::io::stdout());
        return Ok(());
    }

    let mut conn = zlink::unix::connect("/run/roowho2/roowho2.varlink")
        .await
        .expect("Failed to connect to fingerd server");

    let reply = conn
        .finger(args.users)
        .await
        .context("Failed to send finger request")?
        .map_err(|e| anyhow::anyhow!("Server returned an error for finger request: {:?}", e))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply).unwrap());
    } else {
        for user in reply {
            println!("{:#?}", user.unwrap());
        }
    }

    Ok(())
}
