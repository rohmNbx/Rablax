use crate::Finding;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};

pub async fn analyze(target: &str, mode: &str) -> Vec<Finding> {
    match mode {
        "hash" => analyze_hashes(target),
        "jwt" => analyze_jwt(target),
        "weak-crypto" => detect_weak_crypto(target).await,
        _ => Vec::new(),
    }
}

fn analyze_hashes(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Detect hash type
    let hash_type = detect_hash_type(input);
    
    if !hash_type.is_empty() {
        findings.push(Finding {
            finding_type: "Hash Detected".to_string(),
            severity: "INFO".to_string(),
            param: "hash".to_string(),
            payload: input.to_string(),
            detail: format!("Detected hash type: {}", hash_type),
        });

        // Try common passwords
        let common_passwords = vec!["password", "123456", "admin", "letmein", "qwerty"];
        
        for password in common_passwords {
            if hash_type == "SHA256" {
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let result = format!("{:x}", hasher.finalize());
                
                if result == input.to_lowercase() {
                    findings.push(Finding {
                        finding_type: "Weak Password Hash".to_string(),
                        severity: "CRITICAL".to_string(),
                        param: "password".to_string(),
                        payload: password.to_string(),
                        detail: format!("Hash cracked: {}", password),
                    });
                    break;
                }
            }
        }
    }

    findings
}

fn detect_hash_type(hash: &str) -> String {
    match hash.len() {
        32 => "MD5".to_string(),
        40 => "SHA1".to_string(),
        64 => "SHA256".to_string(),
        128 => "SHA512".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn analyze_jwt(token: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return findings;
    }

    // Decode header
    if let Ok(header_bytes) = general_purpose::STANDARD.decode(parts[0]) {
        if let Ok(header_str) = String::from_utf8(header_bytes) {
            findings.push(Finding {
                finding_type: "JWT Header".to_string(),
                severity: "INFO".to_string(),
                param: "header".to_string(),
                payload: header_str.clone(),
                detail: "JWT header decoded".to_string(),
            });

            // Check for algorithm none
            if header_str.contains("\"alg\":\"none\"") || header_str.contains("\"alg\":\"None\"") {
                findings.push(Finding {
                    finding_type: "JWT Algorithm None".to_string(),
                    severity: "CRITICAL".to_string(),
                    param: "algorithm".to_string(),
                    payload: "none".to_string(),
                    detail: "JWT uses 'none' algorithm - signature bypass possible".to_string(),
                });
            }
        }
    }

    // Decode payload
    if let Ok(payload_bytes) = general_purpose::STANDARD.decode(parts[1]) {
        if let Ok(payload_str) = String::from_utf8(payload_bytes) {
            findings.push(Finding {
                finding_type: "JWT Payload".to_string(),
                severity: "INFO".to_string(),
                param: "payload".to_string(),
                payload: payload_str.clone(),
                detail: "JWT payload decoded".to_string(),
            });

            // Check for sensitive data
            let sensitive_keys = vec!["password", "secret", "api_key", "private_key"];
            for key in sensitive_keys {
                if payload_str.to_lowercase().contains(key) {
                    findings.push(Finding {
                        finding_type: "JWT Sensitive Data".to_string(),
                        severity: "HIGH".to_string(),
                        param: key.to_string(),
                        payload: "-".to_string(),
                        detail: format!("JWT contains sensitive data: {}", key),
                    });
                }
            }
        }
    }

    findings
}

async fn detect_weak_crypto(target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check SSL/TLS configuration
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client.get(target).send().await {
        Ok(_) => {
            findings.push(Finding {
                finding_type: "Weak TLS Configuration".to_string(),
                severity: "HIGH".to_string(),
                param: "TLS".to_string(),
                payload: "-".to_string(),
                detail: "Server accepts invalid certificates".to_string(),
            });
        }
        Err(_) => {}
    }

    findings
}
