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
        /// Read one password line from standard input (required).
        #[arg(long, required = true)]
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
            password_stdin,
        }) => {
            anyhow::ensure!(password_stdin, "--password-stdin is required");
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']).to_owned();
            cog::server::create_user(cli.config, &email, &password).await
        }
        None => cog::server::run(cli.config).await,
    }
}
