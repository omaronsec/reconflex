import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_virustotal_subdomains(domain):
    """
    Fetch subdomains from VirusTotal API.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('VIRUSTOTAL_API_KEY')
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"

    params = {
        'apikey': api_key,
        'domain': domain
    }

    try:
        response = make_request(url, params=params, timeout=30, max_retries=3,
                                source_name="VirusTotal")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()

            if data.get('response_code') != 1:
                return []

            subdomains = data.get('subdomains', [])

            cleaned_subdomains = []
            for subdomain in subdomains:
                cleaned = subdomain.strip().replace(" ", "").replace(",", "").replace("&", "").replace('"', '')
                if cleaned:
                    cleaned_subdomains.append(cleaned)

            return cleaned_subdomains

        elif response.status_code == 204:
            # No content — rate limit or no data for this domain; not an error
            return []

        elif response.status_code == 401:
            print(f"    [!] VirusTotal API key invalid")
            return []

        else:
            print(f"    [!] VirusTotal API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] VirusTotal unexpected error: {str(e)}")
        return []
