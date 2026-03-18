#!/usr/bin/env python3
"""
Reconflex CLI - Command Line Interface
Handles argument parsing and banner display
"""

import argparse
import sys


BANNER = """
    ╔═══════════════════════════════════════════════════════╗
    ║         Reconflex v4.2                                ║
    ║         Bug Bounty Recon Framework (PARALLEL)         ║
    ║                                                       ║
    ║  Sources: VirusTotal, SecurityTrails, crt.sh,         ║
    ║           Shodan, Chaos, AlienVault OTX,              ║
    ║           Subfinder (ProjectDiscovery)                ║
    ║                                                       ║
    ║  Acquisition: SecurityTrails + AlienVault OTX         ║
    ║  IP Enumeration: SecurityTrails + Shodan (SSL)        ║
    ║  Expansion: alterx + shuffledns                       ║
    ║                                                       ║
    ║  Features: pre-flight checks, --silent, --sources,    ║
    ║            retry/backoff, domain validation           ║
    ║                                                       ║
    ║  ⚡ PERFORMANCE: All API calls run in parallel!       ║
    ╚═══════════════════════════════════════════════════════╝
    """

# All available subdomain sources (urlscan removed)
ALL_SOURCES = ['virustotal', 'securitytrails', 'crtsh', 'shodan', 'chaos', 'otx', 'subfinder']


def print_banner():
    """Print the Reconflex banner."""
    print(BANNER)


def parse_args():
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Reconflex - Subdomain Enumeration, Domain Acquisition & IP Enumeration (Parallel Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 reconflex.py -u example.com
  python3 reconflex.py -l domains.txt
  python3 reconflex.py -u example.com -live
  python3 reconflex.py -l domains.txt -expand                # Subdomain expansion
  python3 reconflex.py -l domains.txt -expand -live           # Expansion + live check
  python3 reconflex.py -l domains.txt -pd 5                   # Process 5 domains in parallel
  python3 reconflex.py -u example.com --silent                # Silent mode (results only)
  python3 reconflex.py -u example.com --sources vt,st,crtsh   # Select specific sources
  python3 reconflex.py -ips-d example.com
  python3 reconflex.py -ips-l targets.txt
  python3 reconflex.py -ips-enum-d example.com
  python3 reconflex.py -ips-enum-l targets.txt
  python3 reconflex.py -ips-enum-d example.com -live
  python3 reconflex.py -acq example.com
  python3 reconflex.py -acq example.com -email abbvie,caterpillar
  python3 reconflex.py -acq-enum example.com -live -pd 5 -expand

Available sources for --sources flag:
  virustotal (vt), securitytrails (st), crtsh, shodan,
  chaos, otx, subfinder (sf)

Output Structure:
  output/
  |-- quick_results/              (Single domain scans: -u)
  |   |-- example.com_subdomains.txt
  |   |-- all_in_one_example.com.txt          (if -expand used)
  |   |-- live_all_in_one_example.com.txt     (if -expand -live used)
  |   +-- live_example.com_subdomains.txt
  |
  |-- scans/                      (Batch/complex scans: -l, -acq-enum)
  |   |-- 2026-01-05_example.com/
  |   |   |-- all_subdomains.txt
  |   |   |-- all_in_one.txt                  (if -expand used)
  |   |   +-- live_all_in_one.txt             (if -expand -live used)
  |   +-- 2026-01-05_target.com_acquisition/
  |
  |-- acquisition/                (Acquisition results: -acq)
  |   +-- example.com_acquisition.txt
  |
  +-- ips/                        (IP enumeration results)
      +-- ips_for_example.com_05_01.txt
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-u', '--url', type=str, help="Single target domain")
    group.add_argument('-l', '--list', type=str, help="File containing list of domains")
    group.add_argument('-ips-d', '--ip-domain', type=str, metavar='DOMAIN', help="IP enumeration for single domain")
    group.add_argument('-ips-l', '--ip-list', type=str, metavar='FILE', help="IP enumeration for list of domains")
    group.add_argument('-ips-enum-d', '--ip-enum-domain', type=str, metavar='DOMAIN', help="Subdomain + IP enumeration for single domain")
    group.add_argument('-ips-enum-l', '--ip-enum-list', type=str, metavar='FILE', help="Subdomain + IP enumeration for list of domains")
    group.add_argument('-acq', '--acquisition', type=str, metavar='DOMAIN', help="Find associated domains")
    group.add_argument('-acq-enum', '--acquisition-enum', type=str, metavar='DOMAIN', help="Find associated domains AND enumerate subdomains")

    parser.add_argument('-live', '--live', action='store_true', help="Check for live subdomains using httpx")
    parser.add_argument('-expand', '--expand', action='store_true', help="Run subdomain expansion (alterx + shuffledns)")
    parser.add_argument('-email', '--email-filters', type=str, metavar='DOMAINS', help="Comma-separated email domain names for acquisition")
    parser.add_argument('-pd', '--parallel-domains', type=int, default=3, metavar='N', help="Number of domains to process in parallel (default: 3)")
    parser.add_argument('--silent', action='store_true', help="Silent mode - only output results, no banner/progress")
    parser.add_argument('--sources', type=str, metavar='SOURCES', help="Comma-separated list of sources to use (e.g., vt,st,crtsh,shodan)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output with debug information")

    args = parser.parse_args()

    return args


def parse_sources(sources_str):
    """
    Parse the --sources argument into a list of source names.

    Supports shorthand aliases:
        vt -> virustotal
        st -> securitytrails
        sf -> subfinder

    Args:
        sources_str: Comma-separated source names

    Returns:
        List of normalized source names, or None if no filter (use all)
    """
    if not sources_str:
        return None  # Use all sources

    # Shorthand aliases
    aliases = {
        'vt': 'virustotal',
        'st': 'securitytrails',
        'sf': 'subfinder',
    }

    sources = []
    for s in sources_str.split(','):
        s = s.strip().lower()
        if not s:
            continue
        # Resolve alias
        s = aliases.get(s, s)
        if s in ALL_SOURCES:
            sources.append(s)
        else:
            print(f"[!] Unknown source: {s} (available: {', '.join(ALL_SOURCES)})")

    if not sources:
        print("[!] No valid sources specified, using all sources")
        return None

    return sources
