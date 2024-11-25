
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    GenerateKey {
        #[arg(short, long)]
        label: Option<String>,

        #[arg(short, long)]
        expiry: Option<String>,
    },
    StartServer,
}
