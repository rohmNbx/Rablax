import websocket
import json
import ssl

def test_websocket_security(url):
    """Test WebSocket security vulnerabilities."""
    results = []
    
    # Convert HTTP(S) URL to WS(S)
    ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://')
    
    # Common WebSocket paths
    ws_paths = ['/ws', '/websocket', '/socket', '/api/ws', '/chat', '/notifications']
    
    for path in ws_paths:
        test_url = ws_url.rstrip('/') + path
        
        try:
            # Test 1: Connection without authentication
            ws = websocket.create_connection(
                test_url,
                timeout=5,
                sslopt={"cert_reqs": ssl.CERT_NONE}
            )
            
            results.append({
                "type": "WebSocket - Unauthenticated Connection",
                "severity": "HIGH",
                "param": path,
                "payload": "-",
                "detail": "WebSocket accepts connection without authentication"
            })
            
            # Test 2: Send malicious payloads
            test_payloads = [
                '{"type":"admin","action":"getUsers"}',
                '{"role":"admin"}',
                '{"cmd":"ls"}',
                '<script>alert(1)</script>',
            ]
            
            for payload in test_payloads:
                try:
                    ws.send(payload)
                    response = ws.recv()
                    
                    if response and len(response) > 0:
                        # Check for sensitive data
                        if any(word in response.lower() for word in ['password', 'token', 'secret', 'key']):
                            results.append({
                                "type": "WebSocket - Sensitive Data Exposure",
                                "severity": "CRITICAL",
                                "param": path,
                                "payload": payload,
                                "detail": "Sensitive data exposed via WebSocket"
                            })
                            break
                        
                        # Check for command execution
                        if any(word in response for word in ['root:', 'uid=', 'gid=']):
                            results.append({
                                "type": "WebSocket - Command Injection",
                                "severity": "CRITICAL",
                                "param": path,
                                "payload": payload,
                                "detail": "Command execution via WebSocket"
                            })
                            break
                except:
                    pass
            
            ws.close()
            break  # Found working WebSocket, no need to test other paths
            
        except websocket.WebSocketException:
            pass
        except Exception:
            pass
    
    # Test 3: CORS on WebSocket
    try:
        ws = websocket.create_connection(
            test_url,
            timeout=5,
            origin="https://evil.com",
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )
        
        results.append({
            "type": "WebSocket - CORS Misconfiguration",
            "severity": "HIGH",
            "param": "Origin Header",
            "payload": "https://evil.com",
            "detail": "WebSocket accepts arbitrary origin"
        })
        
        ws.close()
    except:
        pass
    
    return results

def test_websocket_injection(url):
    """Test WebSocket message injection."""
    results = []
    
    ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://')
    
    injection_payloads = [
        # XSS
        '{"message":"<script>alert(1)</script>"}',
        # SQL Injection
        '{"id":"1\' OR \'1\'=\'1"}',
        # NoSQL Injection
        '{"user":{"$ne":null}}',
        # Command Injection
        '{"cmd":"test; id"}',
    ]
    
    try:
        ws = websocket.create_connection(
            ws_url,
            timeout=5,
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )
        
        for payload in injection_payloads:
            try:
                ws.send(payload)
                response = ws.recv()
                
                # Check for injection success
                if '<script>' in response:
                    results.append({
                        "type": "WebSocket XSS",
                        "severity": "HIGH",
                        "param": "WebSocket Message",
                        "payload": payload,
                        "detail": "XSS payload reflected without sanitization"
                    })
                
                if any(err in response.lower() for err in ['sql', 'syntax', 'mysql', 'postgresql']):
                    results.append({
                        "type": "WebSocket SQL Injection",
                        "severity": "CRITICAL",
                        "param": "WebSocket Message",
                        "payload": payload,
                        "detail": "SQL error in WebSocket response"
                    })
            except:
                pass
        
        ws.close()
    except:
        pass
    
    return results
