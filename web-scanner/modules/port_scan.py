import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def scan_port(host, port, timeout=1):
    """Scan single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_ports(host, ports=None, max_workers=50):
    """Scan multiple ports dengan threading."""
    results = []
    
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        
        for future in as_completed(futures):
            port = future.result()
            if port:
                service = COMMON_PORTS.get(port, "Unknown")
                severity = "HIGH" if port in [21, 23, 3389, 5900] else "MEDIUM"
                
                results.append({
                    "type": "Open Port",
                    "severity": severity,
                    "param": f"Port {port}",
                    "payload": "-",
                    "detail": f"Service: {service}"
                })
    
    return results
