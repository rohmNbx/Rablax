# Quick Start Guide

## 🚀 Setup (5 menit)

### 1. Install Dependencies
```bash
cd web-scanner
pip install -r requirements.txt
```

### 2. Verify Installation
```bash
python scanner.py --help
```

## 🎯 Basic Usage

### Scan Website dengan Parameter
```bash
python scanner.py "https://example.com?id=1"
```

### Scan Specific Modules
```bash
# SQL Injection only
python scanner.py "https://example.com?id=1" --modules sqli

# Multiple modules
python scanner.py "https://example.com?id=1" --modules sqli xss lfi
```

### Generate Report
```bash
# HTML report (recommended)
python scanner.py "https://example.com" --output report.html

# JSON report
python scanner.py "https://example.com" --output results.json
```

## 📊 Common Scenarios

### Scenario 1: Test Login Form
```bash
python scanner.py "https://example.com/login" --modules csrf xss sqli
```

### Scenario 2: Test Search Function
```bash
python scanner.py "https://example.com/search?q=test" --modules xss sqli
```

### Scenario 3: Test File Upload
```bash
python scanner.py "https://example.com/upload?file=test.txt" --modules lfi cmd
```

### Scenario 4: Reconnaissance
```bash
python scanner.py "https://example.com" --modules recon --output recon.html
```

### Scenario 5: Full Security Audit
```bash
python scanner.py "https://example.com?id=1" --modules all --threads 20 --output audit.html
```

## 🎨 Understanding Output

### Severity Levels
- **CRITICAL** 🔴 - Immediate action required (RCE, SQLi, etc.)
- **HIGH** 🟠 - Serious vulnerability (XSS, CSRF, etc.)
- **MEDIUM** 🟡 - Security weakness (Missing headers, etc.)
- **LOW** 🔵 - Minor issue (Version disclosure, etc.)
- **INFO** ⚪ - Informational (Subdomains found, etc.)

### Sample Output
```
[CRITICAL] Blind SQL Injection (Time-based)
         Param   : id
         Payload : ' AND SLEEP(5)--
         Detail  : Response delay: 5.23s (expected: 5s) - MYSQL
```

## ⚡ Performance Tips

### Faster Scans
```bash
# Increase threads (untuk server yang stabil)
python scanner.py "https://example.com" --threads 50

# Scan specific modules saja
python scanner.py "https://example.com" --modules headers ssl
```

### Slower/Safer Scans
```bash
# Reduce threads (untuk server yang sensitif)
python scanner.py "https://example.com" --threads 5
```

## 🛡️ Before You Start

### Legal Requirements
1. ✅ Dapatkan izin tertulis dari pemilik website
2. ✅ Tentukan scope testing yang jelas
3. ✅ Pastikan tidak melanggar hukum setempat

### Best Practices
1. 🔍 Mulai dengan reconnaissance (`--modules recon`)
2. 🎯 Test specific modules berdasarkan findings
3. 📊 Generate report untuk dokumentasi
4. ✅ Verify findings secara manual
5. 🔒 Jangan test pada production tanpa approval

## 🆘 Troubleshooting

### "Connection timeout"
```bash
# Edit config.py, increase REQUEST_TIMEOUT
REQUEST_TIMEOUT = 30
```

### "Too many requests"
```bash
# Reduce threads
python scanner.py "https://example.com" --threads 5
```

### "Module not found"
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## 📚 Next Steps

1. Baca [README.md](README.md) untuk dokumentasi lengkap
2. Lihat [TESTING.md](TESTING.md) untuk setup test environment
3. Check [examples.sh](examples.sh) untuk contoh lebih banyak
4. Review [CHANGELOG.md](CHANGELOG.md) untuk update terbaru

## 💡 Pro Tips

1. **Combine dengan tools lain**: Gunakan bersama Burp Suite atau OWASP ZAP
2. **Automate**: Integrate ke CI/CD pipeline
3. **Custom payloads**: Edit files di `modules/` untuk custom testing
4. **Rate limiting**: Adjust `RATE_LIMIT_DELAY` di config.py
5. **Wordlists**: Customize `SUBDOMAIN_WORDLIST` untuk better recon

Happy Hacking! 🔒
