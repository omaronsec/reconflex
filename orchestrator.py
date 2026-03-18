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

SOURCE_MAP = {
    'virustotal':     ('VirusTotal',     lambda d: get_virustotal_subdomains(d)),
    'securitytrails': ('SecurityTrails', lambda d: get_securitytrails_subdomains(d)),
    'crtsh':          ('crt.sh',         lambda d: get_crtsh_subdomains(d)),
    'shodan':         ('Shodan',         lambda d: download_and_parse_shodan_data(d)),
    'chaos':          ('Chaos',          lambda d: get_chaos_subdomains(d)),
    'otx':            ('AlienVault OTX', lambda d: get_otx_subdomains(d)),
    'subfinder':      ('Subfinder',      lambda d: get_subfinder_subdomains(d)),
}


# ============================================================================
# HTTPX LIVE CHECK
# ============================================================================

def check_live_subdomains(input_file, output_file, silent=True):
    """
    Check which subdomains are live using Go httpx.

    Returns:
        int: Number of live subdomains found
    """
    httpx_path = find_go_httpx()

    if not httpx_path:
        if not silent:
            print("[!] Go httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
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

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                return sum(1 for line in f if line.strip())
        return 0

    except Exception:
        return 0


# ============================================================================
# EXPANSION TOOLS VALIDATION
# ============================================================================

def validate_expansion_tools(silent=False):
    """Validate alterx, shuffledns, anew are installed. Returns True if ready."""
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

    if not os.path.exists(config.RESOLVERS_FILE):
        if not silent:
            print(f"    [✗] Resolvers file not found: {config.RESOLVERS_FILE}")
        return False
    elif not silent:
        print(f"    [✓] Resolvers file: {config.RESOLVERS_FILE}")

    if not os.path.exists(config.WORDLIST_FILE):
        if not silent:
            print(f"    [✗] Wordlist not found: {config.WORDLIST_FILE}")
        return False
    elif not silent:
        print(f"    [✓] Wordlist file: {config.WORDLIST_FILE}")

    if missing_tools:
        if not silent:
            print(f"\n[!] Missing tools: {', '.join(missing_tools)} — run ./setup.sh\n")
        return False

    if not silent:
        print("[✓] All expansion tools ready!\n")
    return True


# ============================================================================
# CORE: PARALLEL SUBDOMAIN FETCHING
# ============================================================================

def fetch_subdomains_parallel(domain, selected_sources=None):
    """
    Fetch subdomains from all (or selected) sources in parallel.
    Fully silent — callers handle all output.

    Returns:
        Tuple of (all_subdomains set, source_results dict)
    """
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

    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as executor:
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


def _write_grouped_file(scan_dir, domain_results):
    """
    Write subdomains_by_domain.txt — subdomains grouped by root domain.
    Only includes domains that had results.
    """
    grouped_file = os.path.join(scan_dir, 'subdomains_by_domain.txt')
    with open(grouped_file, 'w') as f:
        for domain in sorted(domain_results):
            subs, _ = domain_results[domain]
            if subs:
                f.write(f"# {domain} [{len(subs)} subdomains]\n")
                for sub in sorted(subs):
                    f.write(f"{sub}\n")
                f.write('\n')


def _write_domains_with_results(scan_dir, domain_results):
    """
    Write domains_with_results.txt — only root domains that had at least 1 subdomain.
    Returns list of domains with results.
    """
    domains_with_subs = [d for d in sorted(domain_results) if domain_results[d][0]]
    results_file = os.path.join(scan_dir, 'domains_with_results.txt')
    with open(results_file, 'w') as f:
        for domain in domains_with_subs:
            f.write(f"{domain}\n")
    return domains_with_subs


def _write_summary(scan_dir, domains_count, domains_with_subs, subs_count,
                   live_count, elapsed, check_live, scan_name=None, selected_sources=None):
    """Write summary.txt to the scan directory."""
    summary_file = os.path.join(scan_dir, 'summary.txt')
    with open(summary_file, 'w') as f:
        f.write("Reconflex Scan Summary\n")
        f.write("=" * 40 + "\n")
        f.write(f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if scan_name:
            f.write(f"Scan name  : {scan_name}\n")
        f.write("\n")
        f.write(f"Domains scanned   : {domains_count:,}\n")
        f.write(f"With subdomains   : {domains_with_subs:,}\n")
        f.write(f"Total subdomains  : {subs_count:,}\n")
        if check_live:
            f.write(f"Live subdomains   : {live_count:,}\n")
        f.write(f"Duration          : {_fmt_duration(elapsed)}\n")
        sources_str = ', '.join(selected_sources) if selected_sources else 'all'
        f.write(f"Sources used      : {sources_str}\n")
        f.write(f"Output directory  : {scan_dir}\n")


def _print_report(domains_count, subs_count, live_count, elapsed, output_dir, check_live,
                  domains_with_subs=0, scan_name=None, selected_sources=None):
    """Print the final scan summary to terminal and write summary.txt."""
    print(f"\n{'='*54}")
    print(f"  SCAN REPORT")
    print(f"{'='*54}")
    if scan_name:
        print(f"  Scan            :  {scan_name}")
    print(f"  Domains scanned :  {domains_count:,}")
    print(f"  With subdomains :  {domains_with_subs:,}")
    print(f"  Total subdomains:  {subs_count:,}")
    if check_live:
        print(f"  Live subdomains :  {live_count:,}")
    print(f"  Duration        :  {_fmt_duration(elapsed)}")
    print(f"  Output          :  {output_dir}")
    print(f"{'='*54}\n")

    _write_summary(output_dir, domains_count, domains_with_subs, subs_count,
                   live_count, elapsed, check_live, scan_name, selected_sources)


# ============================================================================
# SUBDOMAIN ENUMERATION (batch worker)
# ============================================================================

def subdomain_enumeration(domain, per_domain_dir, check_live=False,
                          selected_sources=None, silent=False):
    """
    Fetch subdomains for a single domain (used in batch mode).

    - Prints one [INF] start line.
    - Writes files ONLY if results > 0 (no empty files/folders).
    - Per-domain files go flat into per_domain_dir as domain.txt / live_domain.txt

    Returns:
        Tuple of (all_subdomains set, live_subdomains set)
    """
    if not silent:
        print(f"[INF] Enumerating subdomains for {domain} ...")

    all_subdomains, _ = fetch_subdomains_parallel(domain, selected_sources)

    live_subdomains = set()

    if not all_subdomains:
        return all_subdomains, live_subdomains

    # Only create the per_domain dir and write files when we have results
    ensure_dir(per_domain_dir)
    domain_subs_file = os.path.join(per_domain_dir, f'{domain}.txt')
    save_results(domain_subs_file, all_subdomains)

    if check_live:
        domain_live_file = os.path.join(per_domain_dir, f'live_{domain}.txt')
        check_live_subdomains(domain_subs_file, domain_live_file, silent=True)
        if os.path.exists(domain_live_file):
            with open(domain_live_file, 'r') as f:
                live_subdomains = set(line.strip() for line in f if line.strip())
            # Remove empty live file
            if not live_subdomains and os.path.exists(domain_live_file):
                os.remove(domain_live_file)

    return all_subdomains, live_subdomains


# ============================================================================
# PROCESS MODES
# ============================================================================

def process_single_domain(domain, check_live=False, run_expansion=False,
                          selected_sources=None, silent=False):
    """Process a single domain (-u flag). Results go to output/quick_results/."""
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

    # Expansion
    if run_expansion:
        if not validate_expansion_tools(silent):
            print("[!] Expansion tools not available. Run './setup.sh'")
        else:
            all_in_one_file = os.path.join(output_dir, f'all_in_one_{domain}.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, [domain])
            if check_live:
                live_expansion_file = os.path.join(output_dir, f'live_all_in_one_{domain}.txt')
                live_count = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                print(f"[INF] {domain} → {len(all_subdomains)} subdomains | {live_count} live (expanded) | {elapsed:.1f}s")
                print(f"[INF] Saved: {all_in_one_file}")
                return

    live_count = 0
    if check_live:
        live_count = check_live_subdomains(all_subs_file, live_subs_file, silent=True)

    live_str = f" | {live_count} live" if check_live else ""
    print(f"[INF] {domain} → {len(all_subdomains)} subdomains found{live_str} | {elapsed:.1f}s")
    print(f"[INF] Saved: {all_subs_file}")


def process_domain_list(list_file, check_live=False, parallel_domains=3,
                        run_expansion=False, selected_sources=None,
                        silent=False, scan_name=None):
    """
    Process a list of domains (-l flag).

    Output structure:
      output/scans/DATE_NAME/
        summary.txt
        all_subdomains.txt
        live_subdomains.txt         (if -live)
        subdomains_by_domain.txt    (grouped view)
        domains_with_results.txt    (only domains that had hits)
        per_domain/
          domain.com.txt            (only created if count > 0)
          live_domain.com.txt       (only created if live count > 0)

    Returns:
        str: scan_dir path (used by ip_enum callers)
    """
    domains = read_domains_from_file(list_file)
    if not domains:
        return None

    domains = validate_domains(domains)
    if not domains:
        print("[-] No valid domains in list!")
        return None

    scan_dir = get_scan_dir(scan_name or domains[0])
    per_domain_dir = os.path.join(scan_dir, 'per_domain')

    if not silent:
        print(f"[INF] Scan directory : {scan_dir}")
        print(f"[INF] Domains loaded : {len(domains)} | workers: {parallel_domains}\n")

    all_subdomains_aggregate = set()
    all_live_aggregate = set()
    domain_results = {}  # domain -> (subs_set, live_set)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, domain in enumerate(domains, 1):
            future = executor.submit(
                subdomain_enumeration, domain, per_domain_dir,
                check_live, selected_sources, silent
            )
            futures.append((future, domain, idx))

        for future, domain, idx in futures:
            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
                domain_results[domain] = (domain_subs, domain_live)
                if not silent:
                    live_str = f" | {len(domain_live)} live" if check_live else ""
                    print(f"[{idx}/{len(domains)}] {domain} → {len(domain_subs)} subdomains{live_str}")
            except Exception as e:
                domain_results[domain] = (set(), set())
                if not silent:
                    print(f"[{idx}/{len(domains)}] {domain} → ERROR: {str(e)}")

    elapsed = time.time() - start_time

    # ── Aggregated flat files ────────────────────────────────────────────────
    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    save_results(all_subs_file, all_subdomains_aggregate)

    if check_live and all_live_aggregate:
        live_file = os.path.join(scan_dir, 'live_subdomains.txt')
        save_results(live_file, all_live_aggregate)

    if silent:
        for sub in sorted(all_subdomains_aggregate):
            print(sub)
        return scan_dir

    # ── Structured output files ──────────────────────────────────────────────
    _write_grouped_file(scan_dir, domain_results)
    domains_with_subs = _write_domains_with_results(scan_dir, domain_results)

    # ── Expansion ───────────────────────────────────────────────────────────
    if run_expansion:
        if not validate_expansion_tools(silent):
            print("[!] Expansion tools not available. Run './setup.sh'")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, domains)
            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                expanded_live = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                print(f"[INF] Expanded live subdomains: {expanded_live} → {live_expansion_file}")

    # ── Final report ─────────────────────────────────────────────────────────
    _print_report(
        len(domains), len(all_subdomains_aggregate), len(all_live_aggregate),
        elapsed, scan_dir, check_live,
        domains_with_subs=len(domains_with_subs),
        scan_name=scan_name,
        selected_sources=selected_sources
    )

    return scan_dir


# ============================================================================
# IP ENUMERATION
# ============================================================================

def ip_enumeration(domain, ip_output_dir, silent=False):
    """Run IP enumeration for a single domain. Returns set of IPs found."""
    ensure_dir(ip_output_dir)

    ips_file = os.path.join(ip_output_dir, f'{domain}.txt')

    if not silent:
        print(f"[INF] IP enumeration for {domain} ...")

    all_ips = set()
    st_cidrs = []
    shodan_ips = set()

    tasks = {
        'SecurityTrails CIDRs': lambda: get_securitytrails_cidrs(domain),
        'Shodan SSL':           lambda: get_shodan_ips(domain)
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(task): source for source, task in tasks.items()}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                if source == 'SecurityTrails CIDRs':
                    st_cidrs = result or []
                else:
                    shodan_ips = result or set()
            except Exception:
                pass

    if st_cidrs:
        expanded_ips = expand_cidrs_to_ips(st_cidrs, max_ips_per_cidr=10000)
        all_ips.update(expanded_ips)

    all_ips.update(shodan_ips)

    if all_ips:
        save_results(ips_file, all_ips)
        if not silent:
            print(f"[INF] {domain} → {len(all_ips)} IPs → {ips_file}")
    else:
        if not silent:
            print(f"[INF] {domain} → 0 IPs found")

    return all_ips


def process_ip_single(domain, silent=False):
    """IP enumeration for a single domain (-ips-d). Results → output/ips/"""
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return
    ip_enumeration(domain, get_ips_dir(), silent)


def process_ip_list(list_file, silent=False, ip_output_dir=None):
    """IP enumeration for a list of domains (-ips-l). Results → output/ips/ or given dir."""
    domains = read_domains_from_file(list_file)
    if not domains:
        return

    domains = validate_domains(domains)
    if not domains:
        print("[-] No valid domains in list!")
        return

    out_dir = ip_output_dir or get_ips_dir()
    ensure_dir(out_dir)

    if not silent:
        print(f"\n[INF] Starting IP enumeration for {len(domains)} domains ...")

    all_ips_aggregate = set()
    for idx, domain in enumerate(domains, 1):
        if not silent:
            print(f"[{idx}/{len(domains)}] {domain}")
        try:
            ips = ip_enumeration(domain, out_dir, silent)
            all_ips_aggregate.update(ips)
        except Exception as e:
            if not silent:
                print(f"    → ERROR: {str(e)}")

    # Write merged all_ips.txt if we have results
    if all_ips_aggregate and ip_output_dir:
        all_ips_file = os.path.join(out_dir, 'all_ips.txt')
        save_results(all_ips_file, all_ips_aggregate)
        if not silent:
            print(f"\n[INF] All IPs combined: {len(all_ips_aggregate):,} → {all_ips_file}")


def process_ip_enum_single(domain, check_live=False, selected_sources=None, silent=False):
    """Combined subdomain + IP enumeration for a single domain (-ips-enum-d)."""
    process_single_domain(domain, check_live, selected_sources=selected_sources, silent=silent)
    if not silent:
        print(f"\n[INF] Starting IP enumeration phase ...")
    process_ip_single(domain, silent)


def process_ip_enum_list(list_file, check_live=False, selected_sources=None,
                         silent=False, scan_name=None):
    """
    Combined subdomain + IP enumeration for a list of domains (-ips-enum-l).
    IPs go inside the same scan directory as subdomains (output/scans/DATE_NAME/ips/).
    """
    # Subdomain phase — returns scan_dir
    scan_dir = process_domain_list(
        list_file, check_live,
        selected_sources=selected_sources,
        silent=silent,
        scan_name=scan_name
    )

    if not scan_dir:
        return

    # IP phase — goes into scan_dir/ips/
    ip_dir = os.path.join(scan_dir, 'ips')
    if not silent:
        print(f"\n[INF] Starting IP enumeration phase → {ip_dir}")
    process_ip_list(list_file, silent=silent, ip_output_dir=ip_dir)


# ============================================================================
# ACQUISITION
# ============================================================================

def process_acquisition(domain, email_filters=None, silent=False):
    """Find associated domains (-acq flag). Results → output/acquisition/"""
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
                                  selected_sources=None, silent=False, scan_name=None):
    """
    Find associated domains AND enumerate their subdomains (-acq-enum flag).

    Output structure mirrors process_domain_list:
      output/scans/DATE_NAME_acquisition/
        associated_domains.txt
        summary.txt
        all_subdomains.txt
        live_subdomains.txt         (if -live)
        subdomains_by_domain.txt
        domains_with_results.txt
        per_domain/
          domain.com.txt
    """
    if not is_valid_domain(domain):
        print(f"[-] Invalid domain format: {domain}")
        return

    scan_dir = get_scan_dir(scan_name or domain, 'acquisition')

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
        print(f"[INF] Found {len(all_associated)} associated domains → {assoc_file}")

    if not all_associated:
        if not silent:
            print("[-] No associated domains found. Exiting.")
        return

    if not silent:
        print(f"\n[INF] Phase 2: Enumerating subdomains for {len(all_associated)} domains "
              f"| {parallel_domains} workers\n")

    per_domain_dir = os.path.join(scan_dir, 'per_domain')
    all_subdomains_aggregate = set()
    all_live_aggregate = set()
    domain_results = {}
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=parallel_domains) as executor:
        futures = []
        for idx, assoc_domain in enumerate(sorted(all_associated), 1):
            future = executor.submit(
                subdomain_enumeration, assoc_domain, per_domain_dir,
                check_live, selected_sources, silent
            )
            futures.append((future, assoc_domain, idx))

        for future, assoc_domain, idx in futures:
            try:
                domain_subs, domain_live = future.result()
                all_subdomains_aggregate.update(domain_subs)
                all_live_aggregate.update(domain_live)
                domain_results[assoc_domain] = (domain_subs, domain_live)
                if not silent:
                    live_str = f" | {len(domain_live)} live" if check_live else ""
                    print(f"[{idx}/{len(all_associated)}] {assoc_domain} → {len(domain_subs)} subdomains{live_str}")
            except Exception as e:
                domain_results[assoc_domain] = (set(), set())
                if not silent:
                    print(f"[{idx}/{len(all_associated)}] {assoc_domain} → ERROR: {str(e)}")

    elapsed = time.time() - start_time

    # Aggregated files
    all_subs_file = os.path.join(scan_dir, 'all_subdomains.txt')
    save_results(all_subs_file, all_subdomains_aggregate)

    if check_live and all_live_aggregate:
        live_file = os.path.join(scan_dir, 'live_subdomains.txt')
        save_results(live_file, all_live_aggregate)

    if silent:
        for sub in sorted(all_subdomains_aggregate):
            print(sub)
        return

    # Structured output
    _write_grouped_file(scan_dir, domain_results)
    domains_with_subs = _write_domains_with_results(scan_dir, domain_results)

    # Expansion
    if run_expansion:
        if not validate_expansion_tools(silent):
            print("[!] Expansion tools not available. Run './setup.sh'")
        else:
            all_in_one_file = os.path.join(scan_dir, 'all_in_one.txt')
            expand.expand_subdomains(all_subs_file, all_in_one_file, list(all_associated))
            if check_live:
                live_expansion_file = os.path.join(scan_dir, 'live_all_in_one.txt')
                expanded_live = check_live_subdomains(all_in_one_file, live_expansion_file, silent=True)
                print(f"[INF] Expanded live subdomains: {expanded_live} → {live_expansion_file}")

    _print_report(
        len(all_associated), len(all_subdomains_aggregate), len(all_live_aggregate),
        elapsed, scan_dir, check_live,
        domains_with_subs=len(domains_with_subs),
        scan_name=scan_name or domain,
        selected_sources=selected_sources
    )
