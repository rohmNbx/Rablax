"""
Python modules for Ultimate Web Security Scanner v2.0
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'web-scanner', 'modules'))

# Import existing Python modules from v1
try:
    from sql_injection import test_sql_injection
    from blind_sqli import test_blind_sqli
    from xss import test_xss
    from xxe import test_xxe
    from jwt_analysis import test_jwt_vulnerabilities
    from ssti import test_ssti
    from cors_misconfiguration import test_cors_misconfiguration
    from graphql_injection import test_graphql_security
    from nosql_injection import test_nosql_injection
except ImportError as e:
    print(f"Warning: Could not import some Python modules: {e}")


def run_python_scan(target, modules=None):
    """
    Run Python-based security modules
    """
    from urllib.parse import urlparse, parse_qs
    
    results = []
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    
    # Default modules if none specified
    if not modules:
        modules = ['xxe', 'jwt', 'ssti', 'cors', 'graphql', 'nosql']
    
    # Run each module
    if 'xxe' in modules and params:
        try:
            results.extend(test_xxe(base_url, params))
        except:
            pass
    
    if 'jwt' in modules:
        try:
            results.extend(test_jwt_vulnerabilities(base_url))
        except:
            pass
    
    if 'ssti' in modules and params:
        try:
            results.extend(test_ssti(base_url, params))
        except:
            pass
    
    if 'cors' in modules:
        try:
            results.extend(test_cors_misconfiguration(base_url))
        except:
            pass
    
    if 'graphql' in modules:
        try:
            results.extend(test_graphql_security(base_url))
        except:
            pass
    
    if 'nosql' in modules and params:
        try:
            results.extend(test_nosql_injection(base_url, params))
        except:
            pass
    
    return results
