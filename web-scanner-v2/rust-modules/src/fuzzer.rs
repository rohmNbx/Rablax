use crate::Finding;
use rayon::prelude::*;
use reqwest::Client;
use std::time::Duration;

pub async fn run_fuzzer(target: &str, num_requests: usize, mutations: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Generate fuzzing payloads
    let payloads = generate_fuzz_payloads(mutations);

    // Parallel fuzzing using rayon
    let results: Vec<_> = payloads
        .par_iter()
        .take(num_requests)
        .filter_map(|payload| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let url = format!("{}?fuzz={}", target, payload);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();

                        // Check for interesting responses
                        if status == 500 || body.contains("error") || body.contains("exception") {
                            Some(Finding {
                                finding_type: "Fuzzing - Error Response".to_string(),
                                severity: "MEDIUM".to_string(),
                                param: "fuzz".to_string(),
                                payload: payload.clone(),
                                detail: format!("Status: {}, Body length: {}", status, body.len()),
                            })
                        } else if body.len() > 10000 {
                            Some(Finding {
                                finding_type: "Fuzzing - Large Response".to_string(),
                                severity: "LOW".to_string(),
                                param: "fuzz".to_string(),
                                payload: payload.clone(),
                                detail: format!("Response size: {} bytes", body.len()),
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

fn generate_fuzz_payloads(count: usize) -> Vec<String> {
    use rand::Rng;
    let mut payloads = Vec::new();
    let mut rng = rand::thread_rng();

    // Base payloads
    let base = vec![
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
        "; ls -la",
        "admin' --",
        "1 UNION SELECT NULL--",
    ];

    payloads.extend(base.iter().map(|s| s.to_string()));

    // Generate mutations
    for _ in 0..count {
        let base_payload = &base[rng.gen_range(0..base.len())];
        
        // Mutation strategies
        let mutation_type = rng.gen_range(0..5);
        let mutated = match mutation_type {
            0 => format!("{}{}", base_payload, random_string(5)),
            1 => format!("{}{}", random_string(5), base_payload),
            2 => url_encode(base_payload),
            3 => double_url_encode(base_payload),
            4 => case_mutation(base_payload),
            _ => base_payload.clone(),
        };

        payloads.push(mutated);
    }

    payloads
}

fn random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

fn double_url_encode(s: &str) -> String {
    url_encode(&url_encode(s))
}

fn case_mutation(s: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    s.chars()
        .map(|c| {
            if rng.gen_bool(0.5) {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}
