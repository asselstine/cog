use clap::{Parser, Subcommand};
use cog::Config;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    config: Config,
}

#[derive(Subcommand)]
enum Command {
    /// Create a user while cog is stopped.
    CreateUser {
        /// Email address used to sign in.
        email: String,
        /// Password used to sign in. Warning: command-line passwords may be
        /// visible in shell history and process inspection.
        #[arg(
            required_unless_present = "password_stdin",
            conflicts_with = "password_stdin"
        )]
        password: Option<String>,
        /// Read one password line from standard input instead of accepting it
        /// as a command-line argument.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cog=info".into()),
        )
        .init();
    let mut cli = Cli::parse();
    cli.config.initialize()?;
    cli.config.validate()?;
    match cli.command {
        Some(Command::CreateUser {
            email,
            password,
            password_stdin,
        }) => {
            let password = if password_stdin {
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                password.trim_end_matches(['\r', '\n']).to_owned()
            } else {
                password.expect("clap requires a password or --password-stdin")
            };
            cog::server::create_user(cli.config, &email, &password).await
        }
        None => cog::server::run(cli.config).await,
    }
}
