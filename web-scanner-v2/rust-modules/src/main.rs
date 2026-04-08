use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

mod fuzzer;
mod payload;
mod crypto;
mod bruteforce;

#[derive(Parser)]
#[command(name = "rustscan")]
#[command(about = "High-performance security scanner written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Advanced fuzzing engine
    Fuzz {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value_t = 1000)]
        requests: usize,
        #[arg(short, long, default_value_t = 10)]
        mutations: usize,
    },
    /// Intelligent payload generation
    Payload {
        #[arg(short, long)]
        attack_type: String,
        #[arg(short, long, default_value_t = 100)]
        count: usize,
    },
    /// Cryptographic attacks
    Crypto {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        mode: String,
    },
    /// High-speed brute forcing
    Bruteforce {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        wordlist: String,
        #[arg(short, long, default_value_t = 100)]
        threads: usize,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct Finding {
    finding_type: String,
    severity: String,
    param: String,
    payload: String,
    detail: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let results: Vec<Finding> = match cli.command {
        Commands::Fuzz { target, requests, mutations } => {
            fuzzer::run_fuzzer(&target, requests, mutations).await
        }
        Commands::Payload { attack_type, count } => {
            payload::generate_payloads(&attack_type, count)
        }
        Commands::Crypto { target, mode } => {
            crypto::analyze(&target, &mode).await
        }
        Commands::Bruteforce { target, wordlist, threads } => {
            bruteforce::run(&target, &wordlist, threads).await
        }
    };

    // Output as JSON
    let json = serde_json::to_string_pretty(&results).unwrap();
    println!("{}", json);
}
