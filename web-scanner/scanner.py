#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Alat untuk mendeteksi kerentanan pada website dengan fitur advanced.
PERINGATAN: Gunakan hanya pada website yang Anda miliki atau sudah mendapat izin!
"""

import sys
import argparse
import json
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import urllib3
from colorama import init, Fore, Style
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Matikan warning SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

from modules.sql_injection import test_sql_injection
from modules.blind_sqli import test_blind_sqli
from modules.xss import test_xss
from modules.stored_xss import test_stored_xss
from modules.headers import test_security_headers
from modules.open_redirect import test_open_redirect
from modules.csrf import test_csrf
from modules.lfi import test_lfi
from modules.command_injection import test_command_injection
from modules.ssrf import test_ssrf
from modules.subdomain_enum import enumerate_subdomains
from modules.port_scan import scan_ports
from modules.ssl_check import check_ssl
from modules.xxe import test_xxe
from modules.jwt_analysis import test_jwt_vulnerabilities
from modules.graphql_injection import test_graphql_security
from modules.nosql_injection import test_nosql_injection, test_nosql_timing
from modules.ssti import test_ssti
from modules.cors_misconfiguration import test_cors_misconfiguration
from modules.clickjacking import test_clickjacking
from modules.race_condition import test_race_condition
from modules.mass_assignment import test_mass_assignment, test_parameter_pollution
from modules.websocket_security import test_websocket_security


SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}

BANNER = f"""
{Fore.GREEN}╔══════════════════════════════════════════════╗
║     Advanced Web Vulnerability Scanner      ║
║          Gunakan hanya dengan izin!         ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

ALL_MODULES = {
    "sqli": "SQL Injection (Error-based)",
    "blind-sqli": "Blind SQL Injection (Time-based)",
    "nosql": "NoSQL Injection",
    "xss": "XSS (Reflected)",
    "stored-xss": "XSS (Stored)",
    "lfi": "Local File Inclusion",
    "cmd": "Command Injection",
    "ssrf": "Server-Side Request Forgery",
    "csrf": "CSRF Token Check",
    "headers": "Security Headers",
    "redirect": "Open Redirect",
    "subdomain": "Subdomain Enumeration",
    "portscan": "Port Scanning",
    "ssl": "SSL/TLS Analysis",
    "xxe": "XML External Entity (XXE)",
    "jwt": "JWT Token Analysis",
    "graphql": "GraphQL Security",
    "ssti": "Server-Side Template Injection",
    "cors": "CORS Misconfiguration",
    "clickjacking": "Clickjacking",
    "race": "Race Condition",
    "mass-assign": "Mass Assignment",
    "websocket": "WebSocket Security",
}

def print_result(result):
    color = SEVERITY_COLOR.get(result["severity"], Fore.WHITE)
    print(f"  {color}[{result['severity']}]{Style.RESET_ALL} {result['type']}")
    print(f"         Param   : {result['param']}")
    print(f"         Payload : {result['payload']}")
    print(f"         Detail  : {result['detail']}")
    print()

def parse_url(url):
    """Pisahkan URL dan query params."""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    return base_url, params

def run_scan(url, modules, threads=10, output_file=None):
    print(BANNER)
    print(f"{Fore.BLUE}[*] Target  : {url}")
    print(f"[*] Modul   : {', '.join(modules)}")
    print(f"[*] Threads : {threads}")
    print(f"[*] Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

    base_url, params = parse_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc
    all_results = []

    # Daftar scan tasks
    scan_tasks = []

    # --- Security Headers ---
    if "headers" in modules:
        scan_tasks.append(("Security Headers", lambda: test_security_headers(base_url)))

    # --- SSL/TLS ---
    if "ssl" in modules and parsed.scheme == "https":
        scan_tasks.append(("SSL/TLS Analysis", lambda: check_ssl(hostname)))

    # --- CSRF ---
    if "csrf" in modules:
        scan_tasks.append(("CSRF Token Check", lambda: test_csrf(base_url)))

    # --- SQL Injection ---
    if "sqli" in modules and params:
        scan_tasks.append(("SQL Injection", lambda: test_sql_injection(base_url, params)))

    # --- Blind SQL Injection ---
    if "blind-sqli" in modules and params:
        scan_tasks.append(("Blind SQL Injection", lambda: test_blind_sqli(base_url, params)))

    # --- XSS ---
    if "xss" in modules and params:
        scan_tasks.append(("XSS (Reflected)", lambda: test_xss(base_url, params)))

    # --- Stored XSS ---
    if "stored-xss" in modules and params:
        scan_tasks.append(("XSS (Stored)", lambda: test_stored_xss(base_url, params)))

    # --- LFI ---
    if "lfi" in modules and params:
        scan_tasks.append(("Local File Inclusion", lambda: test_lfi(base_url, params)))

    # --- Command Injection ---
    if "cmd" in modules and params:
        scan_tasks.append(("Command Injection", lambda: test_command_injection(base_url, params)))

    # --- SSRF ---
    if "ssrf" in modules:
        scan_tasks.append(("SSRF", lambda: test_ssrf(base_url, params)))

    # --- Open Redirect ---
    if "redirect" in modules:
        scan_tasks.append(("Open Redirect", lambda: test_open_redirect(base_url, params)))

    # --- Subdomain Enumeration ---
    if "subdomain" in modules:
        scan_tasks.append(("Subdomain Enumeration", lambda: enumerate_subdomains(hostname)))

    # --- Port Scan ---
    if "portscan" in modules:
        scan_tasks.append(("Port Scanning", lambda: scan_ports(hostname)))

    # --- XXE ---
    if "xxe" in modules and params:
        scan_tasks.append(("XXE Injection", lambda: test_xxe(base_url, params)))

    # --- JWT Analysis ---
    if "jwt" in modules:
        scan_tasks.append(("JWT Analysis", lambda: test_jwt_vulnerabilities(base_url)))

    # --- GraphQL ---
    if "graphql" in modules:
        scan_tasks.append(("GraphQL Security", lambda: test_graphql_security(base_url)))

    # --- NoSQL Injection ---
    if "nosql" in modules and params:
        scan_tasks.append(("NoSQL Injection", lambda: test_nosql_injection(base_url, params)))
        scan_tasks.append(("NoSQL Timing", lambda: test_nosql_timing(base_url, params)))

    # --- SSTI ---
    if "ssti" in modules and params:
        scan_tasks.append(("SSTI", lambda: test_ssti(base_url, params)))

    # --- CORS ---
    if "cors" in modules:
        scan_tasks.append(("CORS Misconfiguration", lambda: test_cors_misconfiguration(base_url)))

    # --- Clickjacking ---
    if "clickjacking" in modules:
        scan_tasks.append(("Clickjacking", lambda: test_clickjacking(base_url)))

    # --- Race Condition ---
    if "race" in modules and params:
        scan_tasks.append(("Race Condition", lambda: test_race_condition(base_url, params)))

    # --- Mass Assignment ---
    if "mass-assign" in modules and params:
        scan_tasks.append(("Mass Assignment", lambda: test_mass_assignment(base_url, params)))
        scan_tasks.append(("Parameter Pollution", lambda: test_parameter_pollution(base_url, params)))

    # --- WebSocket ---
    if "websocket" in modules:
        scan_tasks.append(("WebSocket Security", lambda: test_websocket_security(base_url)))

    # Run scans dengan progress bar
    with tqdm(total=len(scan_tasks), desc="Scanning", unit="module") as pbar:
        for name, task in scan_tasks:
            print(f"\n{Fore.BLUE}[*] Running: {name}...{Style.RESET_ALL}")
            try:
                results = task()
                all_results.extend(results)
                
                if results:
                    for r in results:
                        print_result(r)
                else:
                    print(f"  {Fore.GREEN}[OK] No issues found{Style.RESET_ALL}")
            except Exception as e:
                print(f"  {Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
            
            pbar.update(1)

    # --- Ringkasan ---
    print(f"\n{Fore.BLUE}{'='*50}")
    print(f"[*] Scan selesai. Total temuan: {len(all_results)}")
    
    critical = sum(1 for r in all_results if r["severity"] == "CRITICAL")
    high     = sum(1 for r in all_results if r["severity"] == "HIGH")
    medium   = sum(1 for r in all_results if r["severity"] == "MEDIUM")
    low      = sum(1 for r in all_results if r["severity"] == "LOW")
    info     = sum(1 for r in all_results if r["severity"] == "INFO")
    
    print(f"    {Fore.RED + Style.BRIGHT}CRITICAL: {critical}  "
          f"{Fore.RED}HIGH: {high}  "
          f"{Fore.YELLOW}MEDIUM: {medium}  "
          f"{Fore.CYAN}LOW: {low}  "
          f"{Fore.WHITE}INFO: {info}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'='*50}{Style.RESET_ALL}\n")

    # Export hasil
    if output_file:
        export_results(all_results, url, output_file)
        print(f"{Fore.GREEN}[+] Hasil disimpan ke: {output_file}{Style.RESET_ALL}")

    return all_results


def export_results(results, target_url, output_file):
    """Export hasil scan ke JSON atau HTML."""
    data = {
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(results),
        "findings": results
    }
    
    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    elif output_file.endswith('.html'):
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid; }}
        .CRITICAL {{ border-color: #8B0000; }}
        .HIGH {{ border-color: #e74c3c; }}
        .MEDIUM {{ border-color: #f39c12; }}
        .LOW {{ border-color: #3498db; }}
        .INFO {{ border-color: #95a5a6; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }}
        .CRITICAL-badge {{ background: #8B0000; }}
        .HIGH-badge {{ background: #e74c3c; }}
        .MEDIUM-badge {{ background: #f39c12; }}
        .LOW-badge {{ background: #3498db; }}
        .INFO-badge {{ background: #95a5a6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Vulnerability Scan Report</h1>
        <p>Target: {target}</p>
        <p>Scan Time: {scan_time}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: {total}</p>
        <p>
            <span class="severity CRITICAL-badge">CRITICAL: {critical}</span>
            <span class="severity HIGH-badge">HIGH: {high}</span>
            <span class="severity MEDIUM-badge">MEDIUM: {medium}</span>
            <span class="severity LOW-badge">LOW: {low}</span>
            <span class="severity INFO-badge">INFO: {info}</span>
        </p>
    </div>
    
    <h2>Findings</h2>
    {findings_html}
</body>
</html>
"""
        
        findings_html = ""
        for r in results:
            findings_html += f"""
    <div class="finding {r['severity']}">
        <span class="severity {r['severity']}-badge">{r['severity']}</span>
        <h3>{r['type']}</h3>
        <p><strong>Parameter:</strong> {r['param']}</p>
        <p><strong>Payload:</strong> <code>{r['payload']}</code></p>
        <p><strong>Detail:</strong> {r['detail']}</p>
    </div>
"""
        
        critical = sum(1 for r in results if r["severity"] == "CRITICAL")
        high = sum(1 for r in results if r["severity"] == "HIGH")
        medium = sum(1 for r in results if r["severity"] == "MEDIUM")
        low = sum(1 for r in results if r["severity"] == "LOW")
        info = sum(1 for r in results if r["severity"] == "INFO")
        
        html = html_template.format(
            target=target_url,
            scan_time=data["scan_time"],
            total=len(results),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            info=info,
            findings_html=findings_html
        )
        
        with open(output_file, 'w') as f:
            f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web Vulnerability Scanner - Gunakan hanya dengan izin!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Available Modules:
{chr(10).join(f"  {k:15} - {v}" for k, v in ALL_MODULES.items())}

Examples:
  python scanner.py https://example.com --modules all
  python scanner.py https://example.com?id=1 --modules sqli xss lfi
  python scanner.py https://example.com --modules subdomain portscan
  python scanner.py https://example.com --output report.html
        """
    )
    
    parser.add_argument("url", help="URL target (contoh: https://example.com?id=1)")
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=list(ALL_MODULES.keys()) + ["all", "web", "recon", "api", "injection"],
        default=["all"],
        help="Modul yang dijalankan (default: all)"
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Jumlah threads untuk scanning (default: 10)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Export hasil ke file (.json atau .html)"
    )

    args = parser.parse_args()

    modules = args.modules
    
    # Preset modules
    if "all" in modules:
        modules = list(ALL_MODULES.keys())
    elif "web" in modules:
        modules = ["sqli", "blind-sqli", "nosql", "xss", "stored-xss", "lfi", "cmd", "ssrf", 
                   "csrf", "headers", "redirect", "xxe", "ssti", "cors", "clickjacking", 
                   "mass-assign", "race"]
    elif "recon" in modules:
        modules = ["subdomain", "portscan", "ssl", "headers"]
    elif "api" in modules:
        modules = ["jwt", "graphql", "cors", "mass-assign", "race", "nosql", "websocket"]
    elif "injection" in modules:
        modules = ["sqli", "blind-sqli", "nosql", "xss", "stored-xss", "lfi", "cmd", "xxe", "ssti"]

    run_scan(args.url, modules, args.threads, args.output)


if __name__ == "__main__":
    main()
