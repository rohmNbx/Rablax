import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "app",
    "blog", "shop", "store", "portal", "vpn", "remote", "secure", "login",
    "dashboard", "panel", "cpanel", "webmail", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "mx", "cdn", "static", "assets", "media",
    "beta", "alpha", "demo", "sandbox", "uat", "prod", "production",
]

def check_subdomain(subdomain, domain):
    """Check apakah subdomain exist."""
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        ips = [str(rdata) for rdata in answers]
        return {"subdomain": full_domain, "ips": ips}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None

def enumerate_subdomains(domain, wordlist=None, max_workers=10):
    """Enumerate subdomains menggunakan DNS bruteforce."""
    results = []
    
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in wordlist}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append({
                    "type": "Subdomain Found",
                    "severity": "INFO",
                    "param": result["subdomain"],
                    "payload": "-",
                    "detail": f"IPs: {', '.join(result['ips'])}"
                })
    
    return results
