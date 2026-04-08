import requests

# Payload open redirect
PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]

# Parameter yang sering digunakan untuk redirect
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "goto", "dest", "destination", "redir", "redirect_uri"]

def test_open_redirect(url, params):
    """Test parameter URL untuk Open Redirect."""
    results = []

    # Gabungkan params dari URL dengan params redirect umum
    all_params = list(params.keys()) + [p for p in REDIRECT_PARAMS if p not in params]

    for param in all_params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload

            try:
                response = requests.get(
                    url,
                    params=test_params,
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )

                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    results.append({
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "param": param,
                        "payload": payload,
                        "detail": f"Redirect ke: {location}"
                    })
                    break
            except requests.RequestException:
                pass

    return results
