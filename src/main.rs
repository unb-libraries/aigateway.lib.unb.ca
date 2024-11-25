mod adapters;
mod auth;
mod client;
mod commands;
mod config;
mod logging;
mod proxy;
mod server;

use clap::Parser;
use env_logger;

use crate::commands::commands::Commands;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        // Key Generation.
        Commands::GenerateKey { label, expiry } => {
            commands::keys::generate_key(label, expiry).await;
        }

        // Start the server.
        Commands::StartServer => {
            println!("Starting server...");
            server::start_server().await.expect("Failed to start server");
        }
    }
}
