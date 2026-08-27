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
        #[arg(long)]
        email: String,
        /// Read the password from standard input instead of prompting on a TTY.
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
    let cli = Cli::parse();
    cli.config.validate()?;
    match cli.command {
        Some(Command::CreateUser {
            email,
            password_stdin,
        }) => {
            let password = if password_stdin {
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                password.trim_end_matches(['\r', '\n']).to_owned()
            } else {
                let password = rpassword::prompt_password("Password: ")?;
                let confirmation = rpassword::prompt_password("Confirm password: ")?;
                anyhow::ensure!(password == confirmation, "passwords do not match");
                password
            };
            cog::server::create_user(cli.config, &email, &password).await
        }
        None => cog::server::run(cli.config).await,
    }
}
