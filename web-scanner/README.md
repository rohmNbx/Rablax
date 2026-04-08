# Advanced Web Vulnerability Scanner

> **⚠️ PERINGATAN:** Gunakan alat ini HANYA pada website yang Anda miliki atau sudah mendapat izin tertulis. Penggunaan tanpa izin adalah ilegal dan dapat dikenakan sanksi hukum.

## 🚀 Fitur

### Web Application Testing
- ✅ SQL Injection (Error-based)
- ✅ Blind SQL Injection (Time-based)
- ✅ NoSQL Injection (MongoDB, CouchDB, etc.)
- ✅ XSS - Cross-Site Scripting (Reflected)
- ✅ XSS - Cross-Site Scripting (Stored)
- ✅ Local File Inclusion (LFI)
- ✅ Command Injection (OS Command)
- ✅ Server-Side Request Forgery (SSRF)
- ✅ CSRF Token Validation
- ✅ Open Redirect
- ✅ Missing Security Headers

### Advanced Injection Attacks
- ✅ XXE (XML External Entity)
- ✅ SSTI (Server-Side Template Injection)
- ✅ Mass Assignment / Parameter Pollution
- ✅ Race Condition / TOCTOU

### API Security
- ✅ JWT Token Analysis (Algorithm confusion, weak secrets)
- ✅ GraphQL Introspection & Injection
- ✅ CORS Misconfiguration
- ✅ WebSocket Security Testing

### Security Misconfigurations
- ✅ Clickjacking (X-Frame-Options)
- ✅ CORS Policy Issues
- ✅ SSL/TLS Certificate Analysis
- ✅ Security Headers Missing

### Reconnaissance
- ✅ Subdomain Enumeration (DNS bruteforce)
- ✅ Port Scanning (Common ports)
- ✅ SSL/TLS Certificate Analysis
- ✅ Server Version Detection

### Advanced Features
- 🔥 Multi-threading untuk speed
- 📊 Export hasil ke JSON/HTML
- 🎨 Colored output dengan severity levels
- 📈 Progress bar untuk tracking
- ⚡ Concurrent scanning
- 🎯 Module presets (all/web/recon/api/injection)

## 📦 Instalasi

```bash
cd web-scanner
pip install -r requirements.txt
```

## 🎯 Cara Pakai

### Basic Scan
```bash
# Scan semua modul
python scanner.py "https://example.com?id=1"

# Scan dengan modul tertentu
python scanner.py "https://example.com?id=1" --modules sqli xss lfi
```

### Advanced Scan
```bash
# Web application testing saja
python scanner.py "https://example.com" --modules web

# API security testing
python scanner.py "https://api.example.com" --modules api

# Injection attacks only
python scanner.py "https://example.com?id=1" --modules injection

# Reconnaissance saja
python scanner.py "https://example.com" --modules recon

# Custom threads
python scanner.py "https://example.com" --threads 20

# Export hasil
python scanner.py "https://example.com" --output report.html
python scanner.py "https://example.com" --output results.json
```

## 📋 Modul yang Tersedia

| Modul         | Keterangan                              | Severity      |
|---------------|-----------------------------------------|---------------|
| `sqli`        | SQL Injection (Error-based)             | HIGH          |
| `blind-sqli`  | Blind SQL Injection (Time-based)        | CRITICAL      |
| `nosql`       | NoSQL Injection (MongoDB, etc.)         | CRITICAL      |
| `xss`         | Cross-Site Scripting (Reflected)        | HIGH          |
| `stored-xss`  | Cross-Site Scripting (Stored)           | CRITICAL      |
| `lfi`         | Local File Inclusion                    | CRITICAL      |
| `cmd`         | Command Injection                       | CRITICAL      |
| `ssrf`        | Server-Side Request Forgery             | CRITICAL      |
| `csrf`        | CSRF Token Check                        | HIGH          |
| `headers`     | Missing Security Headers                | MEDIUM        |
| `redirect`    | Open Redirect                           | MEDIUM        |
| `xxe`         | XML External Entity                     | CRITICAL      |
| `jwt`         | JWT Token Analysis                      | HIGH          |
| `graphql`     | GraphQL Security                        | HIGH          |
| `ssti`        | Server-Side Template Injection          | CRITICAL      |
| `cors`        | CORS Misconfiguration                   | HIGH          |
| `clickjacking`| Clickjacking                            | MEDIUM        |
| `race`        | Race Condition                          | CRITICAL      |
| `mass-assign` | Mass Assignment                         | HIGH          |
| `websocket`   | WebSocket Security                      | HIGH          |
| `subdomain`   | Subdomain Enumeration                   | INFO          |
| `portscan`    | Port Scanning                           | MEDIUM/HIGH   |
| `ssl`         | SSL/TLS Analysis                        | HIGH          |

### Preset Modules
- `all` - Semua modul (default)
- `web` - Web application testing
- `api` - API security testing (JWT, GraphQL, CORS, WebSocket, etc.)
- `injection` - Injection attacks only (SQL, NoSQL, XSS, XXE, SSTI, etc.)
- `recon` - Reconnaissance only

## 📊 Output Format

### Console Output
```
[CRITICAL] Blind SQL Injection (Time-based)
         Param   : id
         Payload : ' AND SLEEP(5)--
         Detail  : Response delay: 5.23s (expected: 5s) - MYSQL

[HIGH] Missing CSRF Token
         Param   : Form #1
         Payload : -
         Detail  : Method: POST, Action: /login
```

### HTML Report
Export ke HTML untuk report yang lebih readable:
```bash
python scanner.py "https://example.com" --output report.html
```

### JSON Export
Export ke JSON untuk processing lebih lanjut:
```bash
python scanner.py "https://example.com" --output results.json
```

## 🔧 Konfigurasi

Edit file modul di `modules/` untuk customize:
- Tambah payload baru
- Adjust timeout
- Modify detection signatures
- Custom wordlist untuk subdomain enum

## ⚡ Performance Tips

1. Gunakan threads lebih banyak untuk target yang stabil:
```bash
python scanner.py "https://example.com" --threads 50
```

2. Pilih modul spesifik untuk scan lebih cepat:
```bash
python scanner.py "https://example.com" --modules sqli xss
```

3. Untuk reconnaissance, gunakan preset `recon`:
```bash
python scanner.py "https://example.com" --modules recon
```

## 🛡️ Severity Levels

- **CRITICAL** - Exploitable vulnerability yang bisa langsung digunakan
- **HIGH** - Vulnerability serius yang perlu segera diperbaiki
- **MEDIUM** - Vulnerability yang bisa meningkatkan attack surface
- **LOW** - Minor security issue
- **INFO** - Informational findings

## 📝 Legal Disclaimer

Tool ini dibuat untuk tujuan edukasi dan security testing yang sah. Pengguna bertanggung jawab penuh atas penggunaan tool ini. Pastikan Anda memiliki:

1. ✅ Izin tertulis dari pemilik website
2. ✅ Scope testing yang jelas
3. ✅ Tidak melanggar hukum setempat

Penggunaan tanpa izin dapat melanggar:
- UU ITE (Indonesia)
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Dan hukum cyber crime lainnya

## 🤝 Contributing

Contributions welcome! Silakan buat PR untuk:
- Tambah modul baru
- Improve detection
- Fix bugs
- Update documentation
