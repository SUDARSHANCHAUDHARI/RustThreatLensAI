use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "threatlens",
    about = "AI-powered log threat analyzer — detects brute-force, suspicious IPs, secrets, and anomalies",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a log file for threats
    Analyze {
        /// Path to log file
        file: String,
        /// Log type: auth, nginx, docker (default: auto)
        #[arg(long, default_value = "auto")]
        log_type: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}
