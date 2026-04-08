import requests
import jwt
import json
from datetime import datetime, timedelta

def analyze_jwt(token):
    """Analyze JWT token untuk kerentanan."""
    vulnerabilities = []
    
    try:
        # Decode tanpa verifikasi untuk analisis
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Check 1: Algorithm None attack
        if header.get('alg', '').lower() in ['none', 'None', 'NONE']:
            vulnerabilities.append({
                "type": "JWT Algorithm None",
                "severity": "CRITICAL",
                "param": "JWT Token",
                "payload": "alg: none",
                "detail": "Token menggunakan algorithm 'none' - signature bypass possible"
            })
        
        # Check 2: Weak algorithm (HS256 with potential key bruteforce)
        if header.get('alg') == 'HS256':
            vulnerabilities.append({
                "type": "JWT Weak Algorithm",
                "severity": "MEDIUM",
                "param": "JWT Token",
                "payload": "alg: HS256",
                "detail": "HS256 vulnerable to key bruteforce - consider RS256"
            })
        
        # Check 3: Expired token
        if 'exp' in payload:
            exp_time = datetime.fromtimestamp(payload['exp'])
            if exp_time < datetime.now():
                vulnerabilities.append({
                    "type": "JWT Expired Token Accepted",
                    "severity": "HIGH",
                    "param": "JWT Token",
                    "payload": f"exp: {exp_time}",
                    "detail": "Server accepts expired tokens"
                })
        else:
            vulnerabilities.append({
                "type": "JWT Missing Expiration",
                "severity": "MEDIUM",
                "param": "JWT Token",
                "payload": "No 'exp' claim",
                "detail": "Token tidak memiliki expiration time"
            })
        
        # Check 4: Sensitive data in payload
        sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn', 'credit_card']
        for key in payload.keys():
            if any(sens in key.lower() for sens in sensitive_keys):
                vulnerabilities.append({
                    "type": "JWT Sensitive Data Exposure",
                    "severity": "HIGH",
                    "param": "JWT Token",
                    "payload": f"Key: {key}",
                    "detail": f"Token contains sensitive data in claim: {key}"
                })
        
        # Check 5: Missing standard claims
        standard_claims = ['iss', 'sub', 'aud']
        missing = [c for c in standard_claims if c not in payload]
        if missing:
            vulnerabilities.append({
                "type": "JWT Missing Standard Claims",
                "severity": "LOW",
                "param": "JWT Token",
                "payload": f"Missing: {', '.join(missing)}",
                "detail": "Token missing recommended claims for validation"
            })
        
    except jwt.DecodeError:
        vulnerabilities.append({
            "type": "JWT Decode Error",
            "severity": "INFO",
            "param": "JWT Token",
            "payload": "-",
            "detail": "Invalid JWT format"
        })
    except Exception as e:
        pass
    
    return vulnerabilities

def test_jwt_vulnerabilities(url):
    """Test JWT vulnerabilities pada endpoint."""
    results = []
    
    try:
        # Get response untuk cari JWT token
        response = requests.get(url, timeout=10, verify=False)
        
        # Check Authorization header
        auth_header = response.request.headers.get('Authorization', '')
        if 'Bearer ' in auth_header:
            token = auth_header.replace('Bearer ', '')
            results.extend(analyze_jwt(token))
        
        # Check cookies
        for cookie in response.cookies:
            if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                results.extend(analyze_jwt(cookie.value))
        
        # Check response body untuk JWT
        try:
            body = response.json()
            for key, value in body.items():
                if isinstance(value, str) and value.count('.') == 2:  # JWT format
                    results.extend(analyze_jwt(value))
        except:
            pass
        
        # Test algorithm confusion attack
        if results:  # Jika ada JWT ditemukan
            results.append({
                "type": "JWT Algorithm Confusion Test",
                "severity": "INFO",
                "param": "JWT Token",
                "payload": "alg: RS256 -> HS256",
                "detail": "Manual test: Try changing RS256 to HS256 with public key as secret"
            })
    
    except requests.RequestException:
        pass
    
    return results
