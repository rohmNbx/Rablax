import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def test_race_condition(url, params, num_requests=20):
    """Test race condition vulnerabilities."""
    results = []
    
    # Endpoints yang sering vulnerable terhadap race condition
    race_endpoints = ['coupon', 'voucher', 'redeem', 'transfer', 'withdraw', 'purchase', 'checkout']
    
    is_vulnerable_endpoint = any(endpoint in url.lower() for endpoint in race_endpoints)
    
    if not is_vulnerable_endpoint and not params:
        return results
    
    # Test 1: Concurrent requests dengan same data
    responses = []
    response_codes = []
    response_times = []
    
    def make_request():
        try:
            start = time.time()
            resp = requests.post(url, data=params, timeout=10, verify=False)
            elapsed = time.time() - start
            return resp.status_code, len(resp.text), elapsed, resp.text
        except:
            return None, None, None, None
    
    # Send concurrent requests
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(make_request) for _ in range(num_requests)]
        
        for future in as_completed(futures):
            code, length, elapsed, text = future.result()
            if code:
                response_codes.append(code)
                response_times.append(elapsed)
                responses.append((code, length, text))
    
    # Analysis
    if len(response_codes) > 0:
        success_count = sum(1 for code in response_codes if code in [200, 201, 202])
        
        # Check if multiple requests succeeded (possible race condition)
        if success_count > 1:
            # Check for duplicate processing indicators
            unique_responses = len(set(r[2][:100] for r in responses if r[2]))
            
            if unique_responses < success_count:
                results.append({
                    "type": "Race Condition Vulnerability",
                    "severity": "CRITICAL",
                    "param": "Concurrent Requests",
                    "payload": f"{num_requests} concurrent requests",
                    "detail": f"{success_count} requests succeeded - possible duplicate processing"
                })
            else:
                results.append({
                    "type": "Possible Race Condition",
                    "severity": "HIGH",
                    "param": "Concurrent Requests",
                    "payload": f"{num_requests} concurrent requests",
                    "detail": f"{success_count} requests succeeded - verify for duplicate processing"
                })
        
        # Check for timing anomalies
        if len(response_times) > 5:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            
            if max_time > avg_time * 3:
                results.append({
                    "type": "Race Condition Timing Anomaly",
                    "severity": "MEDIUM",
                    "param": "Response Time",
                    "payload": "-",
                    "detail": f"Timing variance detected (avg: {avg_time:.2f}s, max: {max_time:.2f}s)"
                })
    
    return results

def test_toctou(url, params):
    """Test Time-of-Check Time-of-Use (TOCTOU) vulnerabilities."""
    results = []
    
    # Test dengan rapid sequential requests
    try:
        # First request - check
        resp1 = requests.get(url, params=params, timeout=10, verify=False)
        
        # Immediate second request - use
        resp2 = requests.post(url, data=params, timeout=10, verify=False)
        
        # Third request - verify
        resp3 = requests.get(url, params=params, timeout=10, verify=False)
        
        # Check if state changed unexpectedly
        if resp1.status_code == 200 and resp2.status_code in [200, 201]:
            if resp1.text != resp3.text:
                results.append({
                    "type": "Possible TOCTOU Vulnerability",
                    "severity": "HIGH",
                    "param": "State Management",
                    "payload": "Sequential check-use-check",
                    "detail": "State changed between check and use - possible TOCTOU"
                })
    except:
        pass
    
    return results
