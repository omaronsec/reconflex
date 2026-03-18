import requests
import json
import time

from logger import logger


def _matches_domain(hostname, domain):
    """Proper suffix-based domain matching."""
    return hostname == domain or hostname.endswith('.' + domain)


def _parse_crtsh_response(data, domain):
    """Parse crt.sh JSON response into a set of subdomains."""
    subdomains = set()
    for entry in data:
        if 'name_value' in entry:
            for raw_value in entry['name_value'].split("\n"):
                cleaned = raw_value.strip()
                if cleaned.startswith('*.'):
                    cleaned = cleaned[2:]
                if cleaned and _matches_domain(cleaned, domain):
                    subdomains.add(cleaned)
    return subdomains


def _try_certspotter(domain):
    """
    Fallback CT log source: Certspotter (no API key, 100 req/hr free tier).
    Returns a sorted list of subdomains or None on failure.
    """
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        'domain': domain,
        'include_subdomains': 'true',
        'expand': 'dns_names',
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                for name in entry.get('dns_names', []):
                    cleaned = name.strip().lstrip('*.')
                    if cleaned and _matches_domain(cleaned, domain):
                        subdomains.add(cleaned)
            return sorted(list(subdomains))
        if response.status_code == 429:
            logger.debug("Certspotter rate limited for %s", domain)
        return None
    except Exception as e:
        logger.debug("Certspotter error for %s: %s", domain, e)
        return None


def get_crtsh_subdomains(domain):
    """
    Fetch subdomains from crt.sh certificate transparency logs.
    Falls back to Certspotter immediately on 503 (rate limit / overload).

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    max_retries = 2
    retry_delay = 5

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.warning("crt.sh JSON decode error: %s", e)
                return []

            return sorted(list(_parse_crtsh_response(data, domain)))

        except requests.exceptions.Timeout:
            logger.debug("crt.sh timeout (attempt %d/%d) for %s", attempt + 1, max_retries, domain)
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                break

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0

            if status == 503:
                # crt.sh overloaded — switch to certspotter immediately
                logger.debug("crt.sh 503 for %s — falling back to Certspotter", domain)
                result = _try_certspotter(domain)
                return result if result is not None else []

            if status in (429, 500, 502, 504) and attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                break

        except requests.exceptions.RequestException as e:
            logger.debug("crt.sh request error for %s: %s", domain, e)
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                break

        except Exception as e:
            logger.debug("crt.sh unexpected error for %s: %s", domain, e)
            break

    # crt.sh exhausted — try certspotter as final fallback
    result = _try_certspotter(domain)
    return result if result is not None else []
