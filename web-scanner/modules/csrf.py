import requests
from bs4 import BeautifulSoup

CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "csrf", "_csrf", "csrf-token",
    "authenticity_token", "_token", "token", "xsrf_token", "xsrf-token"
]

def test_csrf(url):
    """Check apakah form memiliki CSRF token."""
    results = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        
        for idx, form in enumerate(forms):
            action = form.get('action', 'N/A')
            method = form.get('method', 'GET').upper()
            
            # Hanya cek form POST/PUT/DELETE
            if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
                continue
            
            # Cari CSRF token di form
            has_csrf = False
            inputs = form.find_all('input')
            
            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(token_name in name for token_name in CSRF_TOKEN_NAMES):
                    has_csrf = True
                    break
            
            if not has_csrf:
                results.append({
                    "type": "Missing CSRF Token",
                    "severity": "HIGH",
                    "param": f"Form #{idx+1}",
                    "payload": "-",
                    "detail": f"Method: {method}, Action: {action}"
                })
    
    except requests.RequestException:
        pass
    
    return results
