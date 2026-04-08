#!/usr/bin/env python3
"""
Ultimate Web Security Scanner v2.0
Multi-Language High-Performance Architecture
"""

import sys
import argparse
import json
import subprocess
from urllib.parse import urlparse
from colorama import init, Fore, Style
import yaml

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║   Ultimate Web Security Scanner v2.0                 ║
║   Multi-Language High-Performance Architecture       ║
║   Python • Golang • Rust • Ruby                      ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

class MultiLanguageScanner:
    def __init__(self, config_path="config.yaml"):
        self.config = self.load_config(config_path)
        self.results = []
    
    def load_config(self, path):
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except:
            return {
                'engines': {
                    'golang': {'enabled': True, 'max_goroutines': 1000},
                    'rust': {'enabled': True, 'fuzzer_threads': 100},
                    'ruby': {'enabled': False},
                    'python': {'enabled': True}
                },
                'performance': {
                    'mode': 'hybrid',
                    'max_threads': 100
                }
            }
    
    def run_golang_module(self, module, target, threads=100):
        """Execute Golang module"""
        if not self.config['engines']['golang']['enabled']:
            return []
        
        print(f"{Fore.BLUE}[*] Running Golang module: {module}{Style.RESET_ALL}")
        
        try:
            cmd = [
                './bin/goscan',
                '-module', module,
                '-target', target,
                '-threads', str(threads),
                '-output', 'json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                print(f"{Fore.RED}[!] Golang module error: {result.stderr}{Style.RESET_ALL}")
                return []
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] Golang module timeout{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[!] Golang error: {e}{Style.RESET_ALL}")
            return []
    
    def run_rust_module(self, command, args):
        """Execute Rust module"""
        if not self.config['engines']['rust']['enabled']:
            return []
        
        print(f"{Fore.BLUE}[*] Running Rust module: {command}{Style.RESET_ALL}")
        
        try:
            cmd = ['./bin/rustscan', command] + args
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                print(f"{Fore.RED}[!] Rust module error: {result.stderr}{Style.RESET_ALL}")
                return []
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] Rust module timeout{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[!] Rust error: {e}{Style.RESET_ALL}")
            return []
    
    def run_ruby_module(self, module, target):
        """Execute Ruby module (Metasploit integration)"""
        if not self.config['engines']['ruby']['enabled']:
            return []
        
        print(f"{Fore.BLUE}[*] Running Ruby module: {module}{Style.RESET_ALL}")
        
        try:
            cmd = ['ruby', f'ruby-modules/lib/{module}.rb', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return []
        except Exception as e:
            print(f"{Fore.RED}[!] Ruby error: {e}{Style.RESET_ALL}")
            return []
    
    def run_python_modules(self, target, modules):
        """Execute Python modules"""
        from modules import run_python_scan
        
        print(f"{Fore.BLUE}[*] Running Python modules{Style.RESET_ALL}")
        return run_python_scan(target, modules)
    
    def scan(self, target, mode='hybrid', modules=None):
        """Main scanning orchestrator"""
        print(BANNER)
        print(f"{Fore.GREEN}[+] Target: {target}")
        print(f"[+] Mode: {mode}")
        print(f"[+] Engines: {', '.join([k for k, v in self.config['engines'].items() if v['enabled']])}{Style.RESET_ALL}\n")
        
        parsed = urlparse(target)
        hostname = parsed.netloc or target
        
        all_results = []
        
        # Golang modules (High Performance)
        if mode in ['hybrid', 'golang']:
            # Port scanning
            results = self.run_golang_module('portscan', hostname, threads=1000)
            all_results.extend(results)
            
            # Subdomain enumeration
            results = self.run_golang_module('subdomain', hostname, threads=500)
            all_results.extend(results)
            
            # Race condition testing
            if '?' in target:
                results = self.run_golang_module('race', target, threads=100)
                all_results.extend(results)
        
        # Rust modules (Fuzzing & Crypto)
        if mode in ['hybrid', 'rust']:
            # Advanced fuzzing
            results = self.run_rust_module('fuzz', [
                '-t', target,
                '-r', '1000',
                '-m', '100'
            ])
            all_results.extend(results)
            
            # Payload generation
            for attack_type in ['sqli', 'xss', 'xxe']:
                results = self.run_rust_module('payload', [
                    '-a', attack_type,
                    '-c', '50'
                ])
                # Use generated payloads for testing
        
        # Python modules (Core functionality)
        if mode in ['hybrid', 'python']:
            results = self.run_python_modules(target, modules or [])
            all_results.extend(results)
        
        # Ruby modules (Exploitation)
        if mode in ['hybrid', 'ruby'] and self.config['engines']['ruby']['enabled']:
            results = self.run_ruby_module('exploit_scanner', target)
            all_results.extend(results)
        
        self.results = all_results
        return all_results
    
    def print_results(self):
        """Print scan results"""
        severity_color = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN,
            'INFO': Fore.WHITE
        }
        
        print(f"\n{Fore.BLUE}{'='*60}")
        print(f"[*] Scan Results: {len(self.results)} findings")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        for r in self.results:
            color = severity_color.get(r.get('severity', 'INFO'), Fore.WHITE)
            print(f"{color}[{r.get('severity', 'INFO')}] {r.get('type', 'Unknown')}{Style.RESET_ALL}")
            print(f"  Param  : {r.get('param', '-')}")
            print(f"  Payload: {r.get('payload', '-')[:100]}")
            print(f"  Detail : {r.get('detail', '-')}")
            print()
        
        # Summary
        critical = sum(1 for r in self.results if r.get('severity') == 'CRITICAL')
        high = sum(1 for r in self.results if r.get('severity') == 'HIGH')
        medium = sum(1 for r in self.results if r.get('severity') == 'MEDIUM')
        low = sum(1 for r in self.results if r.get('severity') == 'LOW')
        
        print(f"{Fore.BLUE}{'='*60}")
        print(f"Summary: {Fore.RED + Style.BRIGHT}CRITICAL: {critical}  "
              f"{Fore.RED}HIGH: {high}  "
              f"{Fore.YELLOW}MEDIUM: {medium}  "
              f"{Fore.CYAN}LOW: {low}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
    
    def export_results(self, output_file):
        """Export results to file"""
        if output_file.endswith('.json'):
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
        elif output_file.endswith('.html'):
            # Generate HTML report
            self.generate_html_report(output_file)
        
        print(f"{Fore.GREEN}[+] Results exported to: {output_file}{Style.RESET_ALL}")
    
    def generate_html_report(self, output_file):
        """Generate HTML report"""
        # Implementation similar to previous version
        pass


def main():
    parser = argparse.ArgumentParser(
        description='Ultimate Web Security Scanner v2.0 - Multi-Language Architecture'
    )
    
    parser.add_argument('target', help='Target URL or hostname')
    parser.add_argument(
        '--mode', '-m',
        choices=['hybrid', 'golang', 'rust', 'ruby', 'python'],
        default='hybrid',
        help='Scanning mode (default: hybrid)'
    )
    parser.add_argument(
        '--engine',
        choices=['golang', 'rust', 'ruby', 'python'],
        help='Use specific engine only'
    )
    parser.add_argument(
        '--threads', '-t',
        type=int,
        default=100,
        help='Number of threads (default: 100)'
    )
    parser.add_argument(
        '--fuzzer',
        choices=['rust', 'python'],
        default='rust',
        help='Fuzzer engine (default: rust)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file (.json or .html)'
    )
    parser.add_argument(
        '--exploit',
        action='store_true',
        help='Enable exploitation mode (requires Ruby/Metasploit)'
    )
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Configuration file (default: config.yaml)'
    )
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = MultiLanguageScanner(args.config)
    
    # Override mode if engine specified
    if args.engine:
        mode = args.engine
    else:
        mode = args.mode
    
    # Run scan
    scanner.scan(args.target, mode=mode)
    
    # Print results
    scanner.print_results()
    
    # Export if requested
    if args.output:
        scanner.export_results(args.output)


if __name__ == '__main__':
    main()
