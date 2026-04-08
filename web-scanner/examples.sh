#!/bin/bash
# Contoh penggunaan Advanced Web Vulnerability Scanner

echo "=== Advanced Web Vulnerability Scanner - Examples ==="
echo ""

# 1. Basic scan
echo "1. Basic scan (all modules):"
echo "   python scanner.py \"https://example.com?id=1\""
echo ""

# 2. Web application testing
echo "2. Web application testing only:"
echo "   python scanner.py \"https://example.com?id=1\" --modules web"
echo ""

# 3. Reconnaissance
echo "3. Reconnaissance only:"
echo "   python scanner.py \"https://example.com\" --modules recon"
echo ""

# 4. Specific modules
echo "4. Test specific vulnerabilities:"
echo "   python scanner.py \"https://example.com?id=1\" --modules sqli blind-sqli xss"
echo ""

# 5. Fast scan with more threads
echo "5. Fast scan with 50 threads:"
echo "   python scanner.py \"https://example.com\" --threads 50"
echo ""

# 6. Export to HTML
echo "6. Export results to HTML report:"
echo "   python scanner.py \"https://example.com\" --output report.html"
echo ""

# 7. Export to JSON
echo "7. Export results to JSON:"
echo "   python scanner.py \"https://example.com\" --output results.json"
echo ""

# 8. SQL Injection focused
echo "8. SQL Injection testing only:"
echo "   python scanner.py \"https://example.com?id=1\" --modules sqli blind-sqli"
echo ""

# 9. XSS focused
echo "9. XSS testing only:"
echo "   python scanner.py \"https://example.com?search=test\" --modules xss stored-xss"
echo ""

# 10. Full recon
echo "10. Full reconnaissance:"
echo "    python scanner.py \"https://example.com\" --modules subdomain portscan ssl headers"
echo ""

# 11. Critical vulnerabilities only
echo "11. Test critical vulnerabilities:"
echo "    python scanner.py \"https://example.com?id=1\" --modules blind-sqli lfi cmd ssrf stored-xss"
echo ""

# 12. Security headers check
echo "12. Quick security headers check:"
echo "    python scanner.py \"https://example.com\" --modules headers ssl"
echo ""
