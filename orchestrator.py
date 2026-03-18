#!/usr/bin/env python3
"""
Reconflex Orchestrator
Core scan coordination - subdomain enumeration, IP enumeration, acquisition
"""

import os
import time
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
import expand
from utils import find_go_httpx, is_valid_domain, validate_domains
from output_manager import (
    ensure_dir, get_quick_results_dir, get_scan_dir,
    get_acquisition_dir, get_ips_dir, save_results, read_domains_from_file
)

# Import subdomain modules
from subdomain_modules.shodan_subs import download_and_parse_shodan_data
from subdomain_modules.virustotal_subs import get_virustotal_subdomains
from subdomain_modules.securitytrails_subs import get_securitytrails_subdomains
from subdomain_modules.crtsh_subs import get_crtsh_subdomains
from subdomain_modules.chaos_subs import get_chaos_subdomains
from subdomain_modules.otx_subs import get_otx_subdomains
from subdomain_modules.subfinder_subs import get_subfinder_subdomains

# Import acquisition modules
from acquisition.securitytrails_acq import get_securitytrails_associated
from acquisition.otx_acq import get_otx_associated

# Import IP modules
from ip_modules.securitytrails_ips import get_securitytrails_cidrs, expand_cidrs_to_ips
from ip_modules.shodan_ips import get_shodan_ips


# ============================================================================
# SOURCE MAPPING
# ============================================================================

# Map source names to their functions (urlscan removed)
SOURCE_MAP = {
    'virustotal': ('VirusTotal', lambda d: get_virustotal_subdomains(d)),
    'securitytrails': ('SecurityTrails', lambda d: get_securitytrails_subdomains(d)),
    'crtsh': ('crt.sh', lambda d: get_crtsh_subdomains(d)),
    'shodan': ('Shodan', lambda d: download_and_parse_shodan_data(d)),
    'chaos': ('Chaos', lambda d: get_chaos_subdomains(d)),
    'otx': ('AlienVault OTX', lambda d: get_otx_subdomains(d)),
    'subfinder': ('Subfinder', lambda d: get_subfinder_subdomains(d)),
}


# ============================================================================
# HTTPX LIVE CHECK
# ============================================================================

def check_live_subdomains(input_file, output_file, silent=False):
    """
    Check which subdomains are live using Go httpx.

    Args:
        input_file: File containing subdomains to check
        output_file: File to write live results to
        silent: If True, suppress progress output

    Returns:
        int: Number of live subdomains found
    """
    httpx_path = find_go_httpx()

    if not httpx_path:
        if not silent:
            print("\n[!] Go httpx (projectdiscovery) not found!")
            print("    The Python 'httpx' package is NOT the same tool.")
            print("    Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            print("    Or run: ./setup.sh\n")
        return 0

    try:
        command = [
            httpx_path,
            '-l', input_file,
            '-silent',
            '-no-color',
            '-timeout', '10',
            '-threads', '50',
            '-o', output_file
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            if not silent:
                print(f"[-] httpx error: {result.stderr}")
            return 0

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                live_count = sum(1 for line in f if line.strip())
            return live_count
        else:
            return 0

    except Exception as e:
        if not silent:
            print(f"[-] Error running httpx: {str(e)}")
        return 0


# ============================================================================
# EXPANSION TOOLS VALIDATION
# ============================================================================

def validate_expansion_tools(silent=False):
    """
    Validate expansion tools (alterx, shuffledns, anew) only when -expand is used.
    Returns True if all tools available, False otherwise.
    """
    if not silent:
        print("\n[*] Validating expansion tools (alterx, shuffledns, anew)...")

    required_tools = ['alterx', 'shuffledns', 'anew']
    missing_tools = []

    for tool in required_tools:
        if not config.check_tool_installed(tool):
            missing_tools.append(tool)
            if not silent:
                print(f"    [✗] {tool}: NOT FOUND")
        else:
            if not silent:
                print(f"    [✓] {tool}: Installed")

    # Check required files
    if not os.path.exists(config.RESOLVERS_FILE):
        if not silent:
            print(f"    [✗] Resolvers file not found: {config.RESOLVERS_FILE}")
            print(f"        Download with: python3 config.py")
        return False
    else:
        if not silent:
            print(f"    [✓] Resolvers file: {config.RESOLVERS_FILE}")

    if not os.path.exists(config.WORDLIST_FILE):
        if not silent:
            print(f"    [✗] Wordlist not found: {config.WORDLIST_FILE}")
            print(f"        Download with: python3 config.py")
        return False
    else:
        if not silent:
            print(f"    [✓] Wordlist file: {config.WORDLIST_FILE}")

    if missing_tools:
        if not silent:
            print(f"\n[!] Missing tools: {', '.join(missing_tools)}")
            print(f"[!] Install with: ./setup.sh")
            for tool in missing_tools:
                print(f"    {config.REQUIRED_TOOLS.get(tool, 'N/A')}")
            print()
        return False

    if not silent:
        print("[✓] All expansion tools ready!\n")
    return True


# ============================================================================
# CORE: PARALLEL SUBDOMAIN FETCHING
# ============================================================================

def fetch_subdomains_parallel(domain, selected_sources=None, silent=False):
    """
    Fetch subdomains from all (or selected) sources in parallel.
    Runs fully silent — callers handle output.

    Args:
        domain: Target domain
        selected_sources: List of source keys to use (None = all)
        silent: Unused here (kept for API compatibility)

    Returns:
        Tuple of (all_subdomains set, source_results dict)
    """
    # Build task list based on selected sources
    if selected_sources:
        tasks = {}
        for key in selected_sources:
            if key in SOURCE_MAP:
                display_name, func = SOURCE_MAP[key]
                tasks[display_name] = lambda d=domain, f=func: f(d)
    else:
        tasks = {
            display_name: (lambda d=domain, f=func: f(d))
            for key, (display_name, func) in SOURCE_MAP.items()
        }

    results = {}
    all_subdomains = set()

    with ThreadPoolExecutor(max_workers=min(7, len(tasks))) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result() or []
                results[source] = result
                all_subdomains.update(result)
            except Exception:
                results[source] = []

    return all_subdomains, results


# ============================================================================
# SUBDOMAIN ENUMERATION (for batch/list mode)
# ============================================================================

def subdomain_enumeration(domain, domain_output_dir, check_live=False, selected_sources=None, silent=False):
    """
    Run subdomain enumeration for a single domain (used in batch mode).
    Prints one start line before fetching; result line is printed by the caller.

    Returns:
        Tuple of (all_subdomains set, live_subdomains set)
    """
    ensure_dir(domain_output_dir)

    domain_subs_file = os.path.join(domain_output_dir, 'subdomains.txt')
    domain_live_file = os.path.join(domain_output_dir, 'live_subdomains.txt')

    if not silent:
        print(f"[INF] Enumerating subdomains for {domain} ...")

    all_subdomains, source_results = fetch_subdomains_parallel(domain, selected_sources)

    save_results(domain_subs_file, all_subdomains)

    live_subdomains = set()
    if check_live:
        check_live_subdomains(domain_subs_file, domain_live_file, silent=True)
        if os.path.exists(domain_live_file):
            with open(domain_live_file, 'r') as f:
                live_subdomains = set(line.strip() for line in f if line.strip())

    return all_subdomains, live_subdomains


# ============================================================================
# HELPERS
# ============================================================================

def _fmt_duration(seconds):
    """Format seconds into a human-readable duration string."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _print_report(domains_count, subs_count, live_count, elapsed, output_dir, check_live):
    """Print the final scan summary report."""
    print(f"\n{'='*54}")
    print(f"  SCAN REPORT")
    print(f"{'='*54}")
    print(f"  Domains scanned :  {domains_count:,}")
    print(f"  Subdomains found:  {subs_count:,}")
    if check_live:
        print(f"  Live subdomains :  {live_count:,}")
    print(f"  Duration        :  {_fmt_duration(elapsed)}")
    print(f"  Output          :  {output_dir}")
    print(f"{'='*54}\n")


# ============================================================================
# PROCESS MODES
# ============================================================================

def process_single_domain(domain, check_live=False, run_expansion=False,
                          selected_sources=None, silent=False):
    """Process a single domain (-u flag)."""
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return

    output_dir = get_quick_results_dir()
    all_subs_file = os.path.join(output_dir, f'{domain}_subdomains.txt')
    live_subs_file = os.path.join(output_dir, f'live_{domain}_subdomains.txt')

    if not silent:
        print(f"[INF] Enumerating subdomains for {domain} ...")

    start_time = time.time()
    all_subdomains, _ = fetch_subdomains_parallel(domain, selected_sources)
    elapsed = time.time() - start_time

    save_results(all_subs_file, all_subdomains)

    if silent:
        for sub in sorted(all_subdomains):
            print(sub)
        return

    # Run expansion if requested
    if run_expansion:
        if not validate_expansion_tools(silent):
            print("[!] Expansion tools not available. Skipping expansion.")
            print("[!] Run './setup.sh' to install required tools\n")
        else:
            all_in_one_file = os.path.join(output_dir, f'all_in_one_{domain}.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, [domain])

            if check_live:
                live_expansion_file = os.path.join(output_dir, f'live_all_in_one_{domain}.txt')
                live_count = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                print(f"[INF] {domain} → {len(all_subdomains)} subdomains found "
                      f"| {live_count} live (expanded) | {elapsed:.1f}s")
                print(f"[INF] Saved: {all_in_one_file}")
                return

    live_count = 0
    if check_live:
        live_count = check_live_subdomains(all_subs_file, live_subs_file, silent=True)

    live_str = f" | {live_count} live" if check_live else ""
    print(f"[INF] {domain} → {len(all_subdomains)} subdomains found{live_str} | {elapsed:.1f}s")
    print(f"[INF] Saved: {all_subs_file}")


def process_domain_list(list_file, check_live=False, parallel_domains=3,
                        run_expansion=False, selected_sources=None, silent=False):
    """Process a list of domains (-l flag)."""
    domains = read_domains_from_file(list_file)
    if not domains:
        return

    domains = validate_domains(domains)
    if not domains:
        print("[-] No valid domains in list!")
        return

    scan_dir = get_scan_dir(domains[0])

    if not silent:
        print(f"[INF] Scan directory : {scan_dir}")
        print(f"[INF] Domains loaded : {len(domains)} | parallel workers: {parallel_domains}\n")

    all_subdomains_aggregate = set()
    all_live_aggregate = set()
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, domain in enumerate(domains, 1):
            domain_dir = os.path.join(scan_dir, domain)
            future = executor.submit(
                subdomain_enumeration, domain, domain_dir, check_live, selected_sources, silent
            )
            futures.append((future, domain, idx))

        for future, domain, idx in futures:
            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
                if not silent:
                    live_str = f" | {len(domain_live)} live" if check_live else ""
                    print(f"[{idx}/{len(domains)}] {domain} → {len(domain_subs)} subdomains{live_str}")
            except Exception as e:
                if not silent:
                    print(f"[{idx}/{len(domains)}] {domain} → ERROR: {str(e)}")
                continue

    elapsed = time.time() - start_time

    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    save_results(all_subs_file, all_subdomains_aggregate)

    if silent:
        for sub in sorted(all_subdomains_aggregate):
            print(sub)
        return

    # Run expansion if requested
    if run_expansion:
        if not validate_expansion_tools(silent):
            print("[!] Expansion tools not available. Skipping expansion.")
            print("[!] Run './setup.sh' to install required tools\n")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, domains)

            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                expanded_live = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                print(f"[INF] Expanded live subdomains: {expanded_live} → {live_expansion_file}")

    if check_live and all_live_aggregate:
        all_live_file = os.path.join(scan_dir, 'live_all_subdomains.txt')
        save_results(all_live_file, all_live_aggregate)

    _print_report(len(domains), len(all_subdomains_aggregate),
                  len(all_live_aggregate), elapsed, scan_dir, check_live)


# ============================================================================
# IP ENUMERATION
# ============================================================================

def ip_enumeration(domain, ip_output_dir, silent=False):
    """Run IP enumeration for a single domain."""
    ensure_dir(ip_output_dir)

    now = datetime.now()
    date_suffix = now.strftime('%d_%m')
    ips_file = os.path.join(ip_output_dir, f'ips_for_{domain}_{date_suffix}.txt')

    if not silent:
        print(f"\n{'='*60}")
        print(f"[*] IP Enumeration for: {domain}")
        print(f"{'='*60}\n")

    all_ips = set()

    tasks = {
        'SecurityTrails CIDRs': lambda: get_securitytrails_cidrs(domain),
        'Shodan SSL': lambda: get_shodan_ips(domain)
    }

    if not silent:
        print(f"[+] Fetching IPs from sources in parallel...\n")

    st_cidrs = []
    shodan_ips = set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}

        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                if source == 'SecurityTrails CIDRs':
                    st_cidrs = result or []
                    if not silent:
                        print(f"[✓] SecurityTrails: {len(st_cidrs)} CIDRs")
                else:
                    shodan_ips = result or set()
                    if not silent:
                        print(f"[✓] Shodan: {len(shodan_ips)} IPs")
            except Exception as e:
                if not silent:
                    print(f"[✗] {source}: Error - {str(e)}")

    if st_cidrs:
        if not silent:
            print(f"\n[+] Expanding CIDRs to individual IPs...")
        expanded_ips = expand_cidrs_to_ips(st_cidrs, max_ips_per_cidr=10000)
        all_ips.update(expanded_ips)

    all_ips.update(shodan_ips)

    if all_ips:
        save_results(ips_file, all_ips)
        if not silent:
            print(f"\n[✓] Total IPs saved to: {ips_file}")
    else:
        if not silent:
            print(f"\n[!] No IPs found")

    if not silent:
        print(f"\n{'='*60}")
        print(f"[✓] Total unique IPs: {len(all_ips)}")
        print(f"[✓] Ready for scanning with masscan/nmap")
        print(f"{'='*60}\n")

    return all_ips


def process_ip_single(domain, silent=False):
    """Process IP enumeration for a single domain."""
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return
    ip_output_dir = get_ips_dir()
    ip_enumeration(domain, ip_output_dir, silent)


def process_ip_list(list_file, silent=False):
    """Process IP enumeration for a list of domains."""
    domains = read_domains_from_file(list_file)
    if not domains:
        return

    domains = validate_domains(domains)
    if not domains:
        print("[-] No valid domains in list!")
        return

    ip_output_dir = get_ips_dir()

    if not silent:
        print(f"\n{'#'*60}")
        print(f"[*] Starting IP enumeration for {len(domains)} domains...")
        print(f"{'#'*60}\n")

    for idx, domain in enumerate(domains, 1):
        if not silent:
            print(f"[*] IP Enumeration {idx}/{len(domains)}: {domain}")
        try:
            ip_enumeration(domain, ip_output_dir, silent)
        except Exception as e:
            if not silent:
                print(f"[-] Error during IP enumeration for {domain}: {str(e)}\n")
            continue


def process_ip_enum_single(domain, check_live=False, selected_sources=None, silent=False):
    """Combined subdomain + IP enumeration for a single domain."""
    process_single_domain(domain, check_live, selected_sources=selected_sources, silent=silent)

    if not silent:
        print(f"\n{'#'*60}")
        print(f"[*] Starting IP enumeration phase...")
        print(f"{'#'*60}\n")
    process_ip_single(domain, silent)


def process_ip_enum_list(list_file, check_live=False, selected_sources=None, silent=False):
    """Combined subdomain + IP enumeration for a list of domains."""
    process_domain_list(list_file, check_live, selected_sources=selected_sources, silent=silent)

    if not silent:
        print(f"\n{'#'*60}")
        print(f"[*] Starting IP enumeration phase...")
        print(f"{'#'*60}\n")
    process_ip_list(list_file, silent)


# ============================================================================
# ACQUISITION
# ============================================================================

def process_acquisition(domain, email_filters=None, silent=False):
    """Find associated domains (-acq flag)."""
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return

    output_dir = get_acquisition_dir()
    acq_file = os.path.join(output_dir, f'{domain}_acquisition.txt')

    if not silent:
        print(f"[INF] Finding associated domains for {domain} ...")
        if email_filters:
            print(f"[INF] Email filters: {', '.join(email_filters)}")

    all_associated = set()
    tasks = {
        'SecurityTrails': lambda: get_securitytrails_associated(domain),
        'AlienVault OTX': lambda: get_otx_associated(domain, email_filters)
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}
        for future in as_completed(future_to_source):
            try:
                result = future.result() or []
                all_associated.update(result)
            except Exception:
                pass

    save_results(acq_file, all_associated)

    if not silent:
        print(f"[INF] {domain} → {len(all_associated)} associated domains found")
        print(f"[INF] Saved: {acq_file}")

    if silent:
        for d in sorted(all_associated):
            print(d)


def process_acquisition_with_enum(domain, email_filters=None, check_live=False,
                                  parallel_domains=3, run_expansion=False,
                                  selected_sources=None, silent=False):
    """Find associated domains AND enumerate subdomains (-acq-enum flag)."""
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return

    scan_dir = get_scan_dir(domain, 'acquisition')

    if not silent:
        print(f"[INF] Scan directory : {scan_dir}")
        print(f"[INF] Phase 1: Finding associated domains for {domain} ...")
        if email_filters:
            print(f"[INF] Email filters  : {', '.join(email_filters)}")

    all_associated = set()
    tasks = {
        'SecurityTrails': lambda: get_securitytrails_associated(domain),
        'AlienVault OTX': lambda: get_otx_associated(domain, email_filters)
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}
        for future in as_completed(future_to_source):
            try:
                result = future.result() or []
                all_associated.update(result)
            except Exception:
                pass

    assoc_file = os.path.join(scan_dir, 'associated_domains.txt')
    save_results(assoc_file, all_associated)

    if not silent:
        print(f"[INF] Associated domains found: {len(all_associated)} → {assoc_file}")

    if not all_associated:
        if not silent:
            print("[-] No associated domains found. Exiting.")
        return

    if not silent:
        print(f"\n[INF] Phase 2: Enumerating subdomains for {len(all_associated)} domains "
              f"| {parallel_domains} workers\n")

    all_subdomains_aggregate = set()
    all_live_aggregate = set()
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, assoc_domain in enumerate(sorted(all_associated), 1):
            domain_dir = os.path.join(scan_dir, assoc_domain)
            future = executor.submit(
                subdomain_enumeration, assoc_domain, domain_dir, check_live, selected_sources, silent
            )
            futures.append((future, assoc_domain, idx))

        for future, assoc_domain, idx in futures:
            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
                if not silent:
                    live_str = f" | {len(domain_live)} live" if check_live else ""
                    print(f"[{idx}/{len(all_associated)}] {assoc_domain} → {len(domain_subs)} subdomains{live_str}")
            except Exception as e:
                if not silent:
                    print(f"[{idx}/{len(all_associated)}] {assoc_domain} → ERROR: {str(e)}")
                continue

    elapsed = time.time() - start_time

    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    save_results(all_subs_file, all_subdomains_aggregate)

    if run_expansion:
        if not validate_expansion_tools(silent):
            if not silent:
                print("[!] Expansion tools not available. Skipping expansion.")
                print("[!] Run './setup.sh' to install required tools\n")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, list(all_associated))

            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                expanded_live = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                if not silent:
                    print(f"[INF] Expanded live subdomains: {expanded_live} → {live_expansion_file}")

    if check_live and all_live_aggregate:
        all_live_file = os.path.join(scan_dir, 'live_all_subdomains.txt')
        save_results(all_live_file, all_live_aggregate)

    if not silent:
        _print_report(len(all_associated), len(all_subdomains_aggregate),
                      len(all_live_aggregate), elapsed, scan_dir, check_live)
