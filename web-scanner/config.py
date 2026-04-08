# Configuration file untuk scanner

# Request settings
REQUEST_TIMEOUT = 10  # seconds
MAX_RETRIES = 3
VERIFY_SSL = False

# Threading
DEFAULT_THREADS = 10
MAX_THREADS = 100

# Time-based injection
BLIND_SQLI_DELAY = 5  # seconds

# Port scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
PORT_SCAN_TIMEOUT = 1  # seconds

# Subdomain enumeration
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "app",
    "blog", "shop", "store", "portal", "vpn", "remote", "secure", "login",
    "dashboard", "panel", "cpanel", "webmail", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "mx", "cdn", "static", "assets", "media",
    "beta", "alpha", "demo", "sandbox", "uat", "prod", "production",
]

# User Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Rate limiting
RATE_LIMIT_DELAY = 0.1  # seconds between requests
