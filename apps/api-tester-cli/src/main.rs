use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "api-tester", version, about = "API security testing platform")]
struct Cli {
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Version) => println!("api-tester {}", env!("CARGO_PKG_VERSION")),
        None => {
            println!("api-tester workspace is ready; runtime commands are added by later phases")
        }
    }
    let _ = cli.config;
}
