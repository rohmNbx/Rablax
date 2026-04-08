import ssl
import socket
from datetime import datetime

def check_ssl(hostname, port=443):
    """Check SSL/TLS certificate dan configuration."""
    results = []
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Check expiry
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                
                if days_left < 30:
                    results.append({
                        "type": "SSL Certificate Expiring Soon",
                        "severity": "HIGH" if days_left < 7 else "MEDIUM",
                        "param": "Certificate",
                        "payload": "-",
                        "detail": f"Expires in {days_left} days ({not_after.strftime('%Y-%m-%d')})"
                    })
                
                # Check TLS version
                if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    results.append({
                        "type": "Weak TLS Version",
                        "severity": "HIGH",
                        "param": "TLS Version",
                        "payload": "-",
                        "detail": f"Using {version} (should use TLS 1.2+)"
                    })
                
                # Check cipher strength
                cipher_name = cipher[0] if cipher else "Unknown"
                if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']):
                    results.append({
                        "type": "Weak Cipher Suite",
                        "severity": "HIGH",
                        "param": "Cipher",
                        "payload": "-",
                        "detail": f"Using weak cipher: {cipher_name}"
                    })
                
                # Check hostname mismatch
                san = cert.get('subjectAltName', [])
                cn = dict(x[0] for x in cert.get('subject', []))['commonName']
                valid_names = [cn] + [name[1] for name in san if name[0] == 'DNS']
                
                if hostname not in valid_names and not any(hostname.endswith(name.replace('*', '')) for name in valid_names):
                    results.append({
                        "type": "SSL Hostname Mismatch",
                        "severity": "HIGH",
                        "param": "Hostname",
                        "payload": "-",
                        "detail": f"Certificate issued for: {', '.join(valid_names[:3])}"
                    })
                
    except ssl.SSLError as e:
        results.append({
            "type": "SSL Error",
            "severity": "HIGH",
            "param": "SSL/TLS",
            "payload": "-",
            "detail": str(e)
        })
    except Exception as e:
        results.append({
            "type": "SSL Check Failed",
            "severity": "INFO",
            "param": "SSL/TLS",
            "payload": "-",
            "detail": str(e)
        })
    
    return results
