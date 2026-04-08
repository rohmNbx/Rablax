import requests

# Security headers yang wajib ada
REQUIRED_HEADERS = {
    "X-Frame-Options": "Mencegah Clickjacking",
    "X-Content-Type-Options": "Mencegah MIME sniffing",
    "Content-Security-Policy": "Mencegah XSS dan injeksi konten",
    "Strict-Transport-Security": "Memaksa HTTPS (HSTS)",
    "X-XSS-Protection": "Perlindungan XSS browser lama",
    "Referrer-Policy": "Mengontrol informasi referrer",
    "Permissions-Policy": "Mengontrol fitur browser",
}

def test_security_headers(url):
    """Cek security headers pada response."""
    results = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, description in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                results.append({
                    "type": "Missing Security Header",
                    "severity": "MEDIUM",
                    "param": header,
                    "payload": "-",
                    "detail": description
                })

        # Cek apakah server mengekspos versi
        server = response.headers.get("Server", "")
        if any(char.isdigit() for char in server):
            results.append({
                "type": "Server Version Disclosure",
                "severity": "LOW",
                "param": "Server",
                "payload": "-",
                "detail": f"Server header mengekspos versi: {server}"
            })

    except requests.RequestException as e:
        results.append({
            "type": "Connection Error",
            "severity": "INFO",
            "param": "-",
            "payload": "-",
            "detail": str(e)
        })

    return results
