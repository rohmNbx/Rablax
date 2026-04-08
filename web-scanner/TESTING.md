# Testing Guide

## Test Environments

Untuk testing scanner ini, gunakan environment yang aman dan legal:

### 1. DVWA (Damn Vulnerable Web Application)
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
URL: http://localhost
- Default credentials: admin/password
- Set security level ke "low" untuk testing

### 2. bWAPP (Buggy Web Application)
```bash
docker run -d -p 80:80 raesene/bwapp
```
URL: http://localhost/install.php

### 3. WebGoat (OWASP)
```bash
docker run -p 8080:8080 -p 9090:9090 webgoat/goatandwolf
```
URL: http://localhost:8080/WebGoat

### 4. Mutillidae II
```bash
docker run -d -p 80:80 citizenstig/nowasp
```
URL: http://localhost

## Test Cases

### SQL Injection
```bash
# Test pada DVWA
python scanner.py "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --modules sqli blind-sqli

# Expected: Menemukan SQL injection vulnerability
```

### XSS
```bash
# Test reflected XSS
python scanner.py "http://localhost/vulnerabilities/xss_r/?name=test" --modules xss

# Test stored XSS
python scanner.py "http://localhost/vulnerabilities/xss_s/" --modules stored-xss
```

### LFI
```bash
# Test file inclusion
python scanner.py "http://localhost/vulnerabilities/fi/?page=include.php" --modules lfi
```

### Command Injection
```bash
# Test command injection
python scanner.py "http://localhost/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit" --modules cmd
```

### CSRF
```bash
# Test CSRF token
python scanner.py "http://localhost/vulnerabilities/csrf/" --modules csrf
```

### Full Scan
```bash
# Scan semua vulnerability
python scanner.py "http://localhost/vulnerabilities/sqli/?id=1" --modules all --output dvwa-report.html
```

## Verification

Setelah scan, verifikasi hasil dengan:

1. Manual testing menggunakan browser
2. Cross-check dengan tools lain (Burp Suite, OWASP ZAP)
3. Review false positives
4. Dokumentasi findings

## Safe Testing Checklist

- ✅ Gunakan isolated environment (Docker/VM)
- ✅ Tidak test pada production systems
- ✅ Backup data sebelum testing
- ✅ Monitor resource usage
- ✅ Review logs setelah testing
- ✅ Clean up test data

## Performance Testing

```bash
# Test dengan berbagai thread counts
time python scanner.py "http://localhost" --threads 5
time python scanner.py "http://localhost" --threads 10
time python scanner.py "http://localhost" --threads 20

# Compare execution time
```

## Troubleshooting

### Connection Timeout
- Increase timeout di config.py
- Reduce thread count
- Check network connectivity

### False Positives
- Review detection signatures
- Adjust payload patterns
- Manual verification

### Memory Issues
- Reduce thread count
- Scan specific modules only
- Process in batches
