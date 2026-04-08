"""Utility functions untuk scanner."""

import time
import requests
from functools import wraps
from config import REQUEST_TIMEOUT, MAX_RETRIES, RATE_LIMIT_DELAY, USER_AGENT

def rate_limit(func):
    """Decorator untuk rate limiting."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        time.sleep(RATE_LIMIT_DELAY)
        return func(*args, **kwargs)
    return wrapper

def retry_on_failure(max_retries=MAX_RETRIES):
    """Decorator untuk retry request yang gagal."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(1 * (attempt + 1))  # Exponential backoff
            return None
        return wrapper
    return decorator

@rate_limit
@retry_on_failure()
def safe_request(method, url, **kwargs):
    """Wrapper untuk requests dengan rate limiting dan retry."""
    headers = kwargs.get('headers', {})
    headers['User-Agent'] = USER_AGENT
    kwargs['headers'] = headers
    kwargs.setdefault('timeout', REQUEST_TIMEOUT)
    kwargs.setdefault('verify', False)
    
    if method.upper() == 'GET':
        return requests.get(url, **kwargs)
    elif method.upper() == 'POST':
        return requests.post(url, **kwargs)
    else:
        raise ValueError(f"Unsupported method: {method}")

def is_valid_url(url):
    """Validasi URL."""
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_domain(url):
    """Extract domain dari URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc

def sanitize_filename(filename):
    """Sanitize filename untuk export."""
    import re
    return re.sub(r'[^\w\-_\. ]', '_', filename)
