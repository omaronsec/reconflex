#!/usr/bin/env python3
"""
Reconflex Pre-flight Checker
Validates API keys (via real requests) and tools before the scan starts.
"""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from utils import make_request


# ============================================================================
# API KEY VALIDATORS
# ============================================================================

def _check_virustotal():
    api_key = config.API_KEYS.get('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return False, "not set"
    resp = make_request(
        "https://www.virustotal.com/vtapi/v2/domain/report",
        params={'apikey': api_key, 'domain': 'google.com'},
        timeout=10, max_retries=1, source_name="VirusTotal"
    )
    if resp is None:
        return False, "no response"
    if resp.status_code in (200, 204):
        return True, "OK"
    if resp.status_code == 401:
        return False, "invalid API key"
    return False, f"HTTP {resp.status_code}"


def _check_securitytrails():
    api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY', '')
    if not api_key:
        return False, "not set"
    resp = make_request(
        "https://api.securitytrails.com/v1/ping",
        headers={'APIKEY': api_key},
        timeout=10, max_retries=1, source_name="SecurityTrails"
    )
    if resp is None:
        return False, "no response"
    if resp.status_code == 200:
        return True, "OK"
    if resp.status_code == 401:
        return False, "invalid API key"
    return False, f"HTTP {resp.status_code}"


def _check_otx():
    api_key = config.API_KEYS.get('OTX_API_KEY', '')
    if not api_key:
        return False, "not set"
    resp = make_request(
        "https://otx.alienvault.com/api/v1/user/me",
        headers={'X-OTX-API-KEY': api_key},
        timeout=10, max_retries=1, source_name="OTX"
    )
    if resp is None:
        return False, "no response"
    if resp.status_code == 200:
        return True, "OK"
    if resp.status_code == 401:
        return False, "invalid API key"
    return False, f"HTTP {resp.status_code}"




def _check_chaos():
    api_key = config.API_KEYS.get('CHAOS_API_KEY', '')
    if not api_key:
        return False, "not set"
    # Chaos doesn't expose a public ping endpoint — just confirm key is set
    return True, "set (unverified)"


def _check_shodan():
    try:
        result = subprocess.run(
            ['shodan', 'info'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            plan_line = next((l for l in lines if 'Plan' in l), None)
            detail = plan_line.split(':', 1)[-1].strip() if plan_line else "OK"
            return True, detail
        return False, "not configured (run: shodan init YOUR_KEY)"
    except FileNotFoundError:
        return False, "CLI not installed"
    except Exception as e:
        return False, str(e)


# ============================================================================
# TOOL VALIDATORS
# ============================================================================

def _check_tool(name):
    try:
        r = subprocess.run(['which', name], capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False


# ============================================================================
# PREFLIGHT RUNNER
# ============================================================================

API_CHECKS = {
    'VirusTotal':     _check_virustotal,
    'SecurityTrails': _check_securitytrails,
    'AlienVault OTX': _check_otx,
    'Chaos':          _check_chaos,
    'Shodan':         _check_shodan,
}

CORE_TOOLS = ['subfinder', 'httpx']
EXPANSION_TOOLS = ['alterx', 'shuffledns', 'anew']


def run_preflight(check_expansion=False, silent=False):
    """
    Run pre-flight checks before a scan.

    - Validates all API keys via real HTTP requests (parallel).
    - Checks required tools are installed.
    - Warns on API issues and asks the user whether to continue.
    - Hard-exits if critical tools are missing.

    Args:
        check_expansion: Also validate alterx/shuffledns/anew if True (-expand flag)
        silent:          Skip checks entirely in --silent/pipe mode

    Returns:
        bool: True = OK to proceed, False = user chose to abort
    """
    if silent:
        return True

    print("[*] Running pre-flight checks...\n")

    api_issues = []
    tool_issues = []

    # ── API Keys (all in parallel) ──────────────────────────────────────────
    api_results = {}
    with ThreadPoolExecutor(max_workers=len(API_CHECKS)) as ex:
        futures = {ex.submit(fn): name for name, fn in API_CHECKS.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                ok, msg = future.result()
            except Exception as e:
                ok, msg = False, str(e)
            api_results[name] = (ok, msg)

    print("  [API Keys]")
    for name in API_CHECKS:
        ok, msg = api_results[name]
        icon = "✓" if ok else "✗"
        print(f"    [{icon}] {name}: {msg}")
        if not ok:
            api_issues.append(name)

    # ── Tools ───────────────────────────────────────────────────────────────
    print("\n  [Tools]")
    for tool in CORE_TOOLS:
        ok = _check_tool(tool)
        icon = "✓" if ok else "✗"
        print(f"    [{icon}] {tool}")
        if not ok:
            tool_issues.append(tool)
            print(f"        Install: {config.REQUIRED_TOOLS.get(tool, 'N/A')}")

    if check_expansion:
        for tool in EXPANSION_TOOLS:
            ok = _check_tool(tool)
            icon = "✓" if ok else "✗"
            print(f"    [{icon}] {tool} (expansion)")
            if not ok:
                print(f"        Install: {config.REQUIRED_TOOLS.get(tool, 'N/A')}")

    print()

    # ── Hard block on missing core tools ────────────────────────────────────
    if tool_issues:
        print(f"[✗] Critical tools missing: {', '.join(tool_issues)}")
        print("[!] Install them and re-run. Exiting.\n")
        sys.exit(1)

    # ── Soft warn on API issues — ask user ──────────────────────────────────
    if api_issues:
        print(f"[!] {len(api_issues)} source(s) unavailable: {', '.join(api_issues)}")
        print("[!] These sources will return 0 results during the scan.")
        try:
            answer = input("\n    Continue anyway? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = 'n'
        if answer == 'n':
            print("[-] Aborted.\n")
            return False
        print()

    print("[✓] Pre-flight passed — starting scan\n")
    return True
