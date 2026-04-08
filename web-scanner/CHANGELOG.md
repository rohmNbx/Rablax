# Changelog

## [3.0.0] - Ultimate Advanced Version 🔥

### Added - Powerful New Modules
- ✨ **XXE (XML External Entity)** - File reading, SSRF via XML
- ✨ **JWT Token Analysis** - Algorithm confusion, weak secrets, expired tokens
- ✨ **GraphQL Security** - Introspection, injection, batch attacks
- ✨ **NoSQL Injection** - MongoDB, CouchDB operator injection
- ✨ **SSTI (Server-Side Template Injection)** - Jinja2, Twig, Freemarker, etc.
- ✨ **CORS Misconfiguration** - Origin reflection, wildcard issues
- ✨ **Clickjacking** - X-Frame-Options, CSP frame-ancestors
- ✨ **Race Condition** - Concurrent request testing, TOCTOU
- ✨ **Mass Assignment** - Parameter pollution, privilege escalation
- ✨ **WebSocket Security** - Unauthenticated connections, message injection

### Added - New Presets
- 🎯 `api` preset - API security testing (JWT, GraphQL, CORS, WebSocket)
- 🎯 `injection` preset - All injection attacks (SQL, NoSQL, XSS, XXE, SSTI)
- 📚 Advanced modules documentation (ADVANCED_MODULES.md)

### Improved
- 🔧 Better detection algorithms
- 🔧 More comprehensive payloads
- 🔧 Enhanced error handling
- 🔧 Optimized concurrent scanning

### Total Modules
- 23 security testing modules
- 5 preset combinations
- Support untuk 10+ template engines
- Support untuk 5+ database types

## [2.0.0] - Advanced Version

### Added
- ✨ Blind SQL Injection (Time-based detection)
- ✨ Stored XSS detection with unique identifiers
- ✨ Local File Inclusion (LFI) / Directory Traversal
- ✨ Command Injection (Time-based & Output-based)
- ✨ Server-Side Request Forgery (SSRF)
- ✨ CSRF Token validation
- ✨ Subdomain enumeration via DNS bruteforce
- ✨ Port scanning with service detection
- ✨ SSL/TLS certificate analysis
- ✨ Multi-threading support untuk performance
- ✨ Export hasil ke JSON dan HTML
- ✨ Progress bar dengan tqdm
- ✨ Rate limiting dan retry logic
- ✨ Configurable settings
- ✨ Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- ✨ Module presets: all, web, recon
- ✨ Colored output dengan severity indicators

### Improved
- 🔧 Better error handling
- 🔧 Enhanced detection signatures
- 🔧 Optimized payload lists
- 🔧 Concurrent scanning untuk speed
- 🔧 More detailed reporting
- 🔧 Better documentation

### Security
- 🔒 SSL verification options
- 🔒 Request timeout controls
- 🔒 Rate limiting untuk avoid DoS
- 🔒 Safe request wrapper

## [1.0.0] - Initial Release

### Added
- Basic SQL Injection detection (Error-based)
- XSS (Reflected) detection
- Security Headers check
- Open Redirect detection
- Simple CLI interface
- Basic reporting
