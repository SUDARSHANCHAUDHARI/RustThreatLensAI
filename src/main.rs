mod cli;
mod output;

use threatlens::{parser, report};

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            log_type,
            json,
            brute_force_threshold,
        } => {
            let content = std::fs::read_to_string(&file)?;
            let events = parser::parse(&content, &log_type);
            let findings = threatlens::detector::detect_with_brute_force_threshold(
                &events,
                brute_force_threshold.max(1),
            );
            let report = report::build(&file, &log_type, &events, &findings);
            if json {
                output::json::print(&report)?;
            } else {
                output::terminal::print(&report);
            }
        }
    }

    Ok(())
}
