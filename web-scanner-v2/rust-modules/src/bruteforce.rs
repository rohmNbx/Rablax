use crate::Finding;
use rayon::prelude::*;
use reqwest::Client;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

pub async fn run(target: &str, wordlist_path: &str, threads: usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Read wordlist
    let wordlist = match read_wordlist(wordlist_path) {
        Ok(words) => words,
        Err(e) => {
            findings.push(Finding {
                finding_type: "Bruteforce Error".to_string(),
                severity: "INFO".to_string(),
                param: "wordlist".to_string(),
                payload: "-".to_string(),
                detail: format!("Failed to read wordlist: {}", e),
            });
            return findings;
        }
    };

    // Configure thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .unwrap();

    // Parallel bruteforce
    let results: Vec<_> = wordlist
        .par_iter()
        .filter_map(|word| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap();

                let url = format!("{}/{}", target, word);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        
                        // Check for successful responses
                        if status == 200 || status == 301 || status == 302 {
                            Some(Finding {
                                finding_type: "Directory/File Found".to_string(),
                                severity: "INFO".to_string(),
                                param: word.clone(),
                                payload: url.clone(),
                                detail: format!("Status: {}", status),
                            })
                        } else if status == 403 {
                            Some(Finding {
                                finding_type: "Forbidden Resource".to_string(),
                                severity: "MEDIUM".to_string(),
                                param: word.clone(),
                                payload: url.clone(),
                                detail: "Resource exists but access forbidden".to_string(),
                            })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            })
        })
        .collect();

    findings.extend(results);
    findings
}

fn read_wordlist(path: &str) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let words: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    Ok(words)
}

pub fn generate_wordlist(base: &str, mutations: usize) -> Vec<String> {
    let mut wordlist = Vec::new();
    
    // Common suffixes
    let suffixes = vec!["", ".php", ".html", ".asp", ".aspx", ".jsp", ".txt", ".bak", ".old"];
    
    // Common prefixes
    let prefixes = vec!["", "admin", "test", "dev", "backup", "old"];
    
    // Generate combinations
    for prefix in &prefixes {
        for suffix in &suffixes {
            if prefix.is_empty() {
                wordlist.push(format!("{}{}", base, suffix));
            } else {
                wordlist.push(format!("{}-{}{}", prefix, base, suffix));
                wordlist.push(format!("{}_{}{}", prefix, base, suffix));
            }
        }
    }

    // Add mutations
    for i in 0..mutations {
        wordlist.push(format!("{}{}", base, i));
        wordlist.push(format!("{}-{}", base, i));
        wordlist.push(format!("{}_{}", base, i));
    }

    wordlist
}
