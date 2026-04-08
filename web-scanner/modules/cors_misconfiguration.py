import requests

# Test origins untuk CORS misconfiguration
TEST_ORIGINS = [
    "https://evil.com",
    "http://evil.com",
    "null",
    "https://subdomain.target.com",
]

def test_cors_misconfiguration(url):
    """Test CORS (Cross-Origin Resource Sharing) misconfiguration."""
    results = []
    
    for origin in TEST_ORIGINS:
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        
        try:
            # Test preflight request
            response = requests.options(url, headers=headers, timeout=10, verify=False)
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            # Vulnerability 1: Reflects arbitrary origin
            if acao == origin:
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                results.append({
                    "type": "CORS Arbitrary Origin Reflection",
                    "severity": severity,
                    "param": "Access-Control-Allow-Origin",
                    "payload": origin,
                    "detail": f"Server reflects arbitrary origin{' with credentials' if acac.lower() == 'true' else ''}"
                })
            
            # Vulnerability 2: Wildcard with credentials
            if acao == "*" and acac.lower() == "true":
                results.append({
                    "type": "CORS Wildcard with Credentials",
                    "severity": "CRITICAL",
                    "param": "Access-Control-Allow-Origin",
                    "payload": "*",
                    "detail": "Wildcard origin (*) allowed with credentials - severe misconfiguration"
                })
            
            # Vulnerability 3: Null origin allowed
            if origin == "null" and acao == "null":
                results.append({
                    "type": "CORS Null Origin Allowed",
                    "severity": "HIGH",
                    "param": "Access-Control-Allow-Origin",
                    "payload": "null",
                    "detail": "Null origin allowed - exploitable via sandboxed iframe"
                })
            
            # Vulnerability 4: Subdomain wildcard
            if origin.startswith("https://subdomain.") and acao == origin:
                results.append({
                    "type": "CORS Subdomain Wildcard",
                    "severity": "MEDIUM",
                    "param": "Access-Control-Allow-Origin",
                    "payload": origin,
                    "detail": "Any subdomain accepted - risk if subdomain takeover possible"
                })
            
        except requests.RequestException:
            pass
    
    # Test actual request (not just preflight)
    try:
        response = requests.get(
            url,
            headers={"Origin": "https://evil.com"},
            timeout=10,
            verify=False
        )
        
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        
        # Check if sensitive data exposed
        if acao and acao != "":
            content_type = response.headers.get("Content-Type", "")
            if "json" in content_type or "xml" in content_type:
                results.append({
                    "type": "CORS Sensitive Data Exposure",
                    "severity": "HIGH",
                    "param": "CORS Policy",
                    "payload": "-",
                    "detail": f"CORS enabled on endpoint returning {content_type}"
                })
    except:
        pass
    
    return results

def test_cors_headers(url):
    """Check CORS headers configuration."""
    results = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        
        # Check for overly permissive CORS
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        
        if acao == "*":
            results.append({
                "type": "CORS Wildcard Origin",
                "severity": "MEDIUM",
                "param": "Access-Control-Allow-Origin",
                "payload": "*",
                "detail": "Wildcard origin allowed - may expose sensitive data"
            })
        
        # Check for missing CORS headers when needed
        if not acao and "api" in url.lower():
            results.append({
                "type": "CORS Headers Missing",
                "severity": "INFO",
                "param": "Access-Control-Allow-Origin",
                "payload": "-",
                "detail": "API endpoint without CORS headers - may cause client issues"
            })
        
    except requests.RequestException:
        pass
    
    return results
