import requests
from bs4 import BeautifulSoup

def test_clickjacking(url):
    """Test Clickjacking vulnerability."""
    results = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check X-Frame-Options
        xfo = headers.get('x-frame-options', '').upper()
        
        # Check Content-Security-Policy frame-ancestors
        csp = headers.get('content-security-policy', '').lower()
        has_frame_ancestors = 'frame-ancestors' in csp
        
        # Vulnerability: Missing both protections
        if not xfo and not has_frame_ancestors:
            # Check if page has sensitive forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            has_password = any(
                inp.get('type') == 'password' 
                for form in forms 
                for inp in form.find_all('input')
            )
            
            severity = "HIGH" if (forms or has_password) else "MEDIUM"
            
            results.append({
                "type": "Clickjacking - Missing Frame Protection",
                "severity": severity,
                "param": "X-Frame-Options / CSP",
                "payload": "-",
                "detail": f"No frame protection headers{' - sensitive forms detected' if has_password else ''}"
            })
        
        # Weak configuration: ALLOW-FROM
        elif xfo.startswith('ALLOW-FROM'):
            results.append({
                "type": "Clickjacking - Weak X-Frame-Options",
                "severity": "MEDIUM",
                "param": "X-Frame-Options",
                "payload": xfo,
                "detail": "ALLOW-FROM is deprecated and not supported by modern browsers"
            })
        
        # Check for frame-busting code
        if response.text:
            frame_busting_patterns = [
                'top.location', 'top.location.href', 'self.parent.frames',
                'parent.frames.length', 'if (top != self)', 'if (window.top !== window.self)'
            ]
            
            has_frame_busting = any(pattern in response.text for pattern in frame_busting_patterns)
            
            if has_frame_busting and not xfo and not has_frame_ancestors:
                results.append({
                    "type": "Clickjacking - JavaScript Frame Busting Only",
                    "severity": "MEDIUM",
                    "param": "Frame Busting",
                    "payload": "-",
                    "detail": "Relies on JavaScript frame busting - can be bypassed with sandbox attribute"
                })
    
    except requests.RequestException:
        pass
    
    return results

def generate_clickjacking_poc(url):
    """Generate PoC HTML untuk clickjacking test."""
    poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {{
            width: 100%;
            height: 600px;
            position: absolute;
            top: 0;
            left: 0;
            opacity: 0.5; /* Set to 0 for real attack */
            z-index: 2;
        }}
        .decoy {{
            position: absolute;
            top: 200px;
            left: 200px;
            z-index: 1;
        }}
    </style>
</head>
<body>
    <h1>Clickjacking Proof of Concept</h1>
    <div class="decoy">
        <button>Click here for FREE prize!</button>
    </div>
    <iframe src="{url}"></iframe>
</body>
</html>"""
    
    return poc_html
