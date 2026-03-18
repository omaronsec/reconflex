#!/usr/bin/env python3
"""
Reconflex Utilities
Shared retry logic, domain validation, and helper functions
"""

import re
import time
import requests
from functools import wraps


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

# Valid domain regex pattern
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def is_valid_domain(domain):
    """
    Validate that a string is a properly formatted domain name.

    Args:
        domain: String to validate

    Returns:
        bool: True if valid domain format
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    # Check length
    if len(domain) > 253 or len(domain) < 4:
        return False

    # Check pattern
    return bool(DOMAIN_PATTERN.match(domain))


def validate_domains(domains):
    """
    Validate a list of domains and return valid ones with warnings for invalid.

    Args:
        domains: List of domain strings

    Returns:
        List of valid domain strings
    """
    valid = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        if is_valid_domain(domain):
            valid.append(domain)
        else:
            print(f"[!] Skipping invalid domain: {domain}")
    return valid


# ============================================================================
# RETRY WITH EXPONENTIAL BACKOFF
# ============================================================================

def retry_request(func=None, max_retries=3, initial_delay=5, backoff_factor=2,
                  retry_on_status=(429, 500, 502, 503, 504)):
    """
    Decorator for retrying HTTP requests with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        backoff_factor: Multiply delay by this factor after each retry
        retry_on_status: HTTP status codes that trigger a retry

    Usage:
        @retry_request
        def my_api_call(domain):
            response = requests.get(url, timeout=30)
            return response

        @retry_request(max_retries=5, initial_delay=10)
        def my_slow_api_call(domain):
            response = requests.get(url, timeout=60)
            return response
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except requests.exceptions.HTTPError as e:
                    last_exception = e
                    status = e.response.status_code if e.response is not None else None

                    if status in retry_on_status and attempt < max_retries:
                        # Check for Retry-After header
                        retry_after = e.response.headers.get('Retry-After') if e.response is not None else None
                        wait_time = int(retry_after) if retry_after else delay

                        print(f"    [!] HTTP {status} - retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        delay *= backoff_factor
                    else:
                        raise

                except requests.exceptions.Timeout as e:
                    last_exception = e
                    if attempt < max_retries:
                        print(f"    [!] Timeout - retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        raise

                except requests.exceptions.ConnectionError as e:
                    last_exception = e
                    if attempt < max_retries:
                        print(f"    [!] Connection error - retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        raise

            # Should not reach here, but just in case
            if last_exception:
                raise last_exception

        return wrapper

    # Handle both @retry_request and @retry_request(args) syntax
    if func is not None:
        return decorator(func)
    return decorator


# ============================================================================
# HTTP REQUEST HELPER
# ============================================================================

def make_request(url, headers=None, params=None, timeout=30, max_retries=3,
                 source_name="API"):
    """
    Make an HTTP GET request with automatic retry and error handling.

    Args:
        url: Request URL
        headers: Request headers dict
        params: Query parameters dict
        timeout: Request timeout in seconds
        max_retries: Number of retries on failure
        source_name: Name of the source for error messages

    Returns:
        requests.Response object or None on failure
    """
    delay = 5

    for attempt in range(max_retries + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', delay))
                # If Retry-After is absurdly long (>30s), just bail immediately
                if retry_after > 30:
                    return None
                if attempt < max_retries:
                    print(f"    [!] {source_name} rate limited - waiting {retry_after}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(retry_after)
                    delay *= 2
                    continue
                else:
                    return None

            # Handle server errors
            if response.status_code in (500, 502, 503, 504):
                if attempt < max_retries:
                    print(f"    [!] {source_name} server error (HTTP {response.status_code}) - retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    delay *= 2
                    continue
                else:
                    print(f"    [!] {source_name} server error (HTTP {response.status_code}) - max retries reached")
                    return None

            return response

        except requests.exceptions.Timeout:
            if attempt < max_retries:
                print(f"    [!] {source_name} timeout - retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"    [!] {source_name} timeout - max retries reached")
                return None

        except requests.exceptions.ConnectionError:
            if attempt < max_retries:
                print(f"    [!] {source_name} connection error - retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"    [!] {source_name} connection error - max retries reached")
                return None

        except requests.exceptions.RequestException as e:
            print(f"    [!] {source_name} request error: {str(e)}")
            return None

    return None


# ============================================================================
# HTTPX BINARY DETECTION
# ============================================================================

def find_go_httpx():
    """
    Find the Go version of httpx (projectdiscovery/httpx).
    The Python httpx package can shadow the Go binary in PATH.

    Returns:
        str: Path to Go httpx binary, or None if not found
    """
    import subprocess
    import os

    # Check common Go binary locations first
    go_paths = [
        os.path.expanduser('~/go/bin/httpx'),
        '/usr/local/go/bin/httpx',
        '/root/go/bin/httpx',
    ]

    for path in go_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            # Verify it's the Go version by checking if it supports -list flag
            try:
                result = subprocess.run(
                    [path, '-version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if 'projectdiscovery' in result.stdout.lower() or 'projectdiscovery' in result.stderr.lower():
                    return path
            except Exception:
                continue

    # Fallback: check PATH but verify it's the Go version
    try:
        result = subprocess.run(['which', 'httpx'], capture_output=True, text=True)
        if result.returncode == 0:
            httpx_path = result.stdout.strip()
            # Check if it's Go binary (not Python)
            check = subprocess.run(
                [httpx_path, '-version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'projectdiscovery' in check.stdout.lower() or 'projectdiscovery' in check.stderr.lower():
                return httpx_path
    except Exception:
        pass

    return None
