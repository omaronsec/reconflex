#!/usr/bin/env python3
"""
Reconflex v4.2 - Bug Bounty Recon Framework
Parallel subdomain enumeration, domain acquisition & IP enumeration

Author: Omar Abdelhameed (@omaronsec)
GitHub: https://github.com/omar-secdown/reconflex
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import config
from cli import print_banner, parse_args, parse_sources
from preflight import run_preflight
from orchestrator import (
    process_single_domain,
    process_domain_list,
    process_ip_single,
    process_ip_list,
    process_ip_enum_single,
    process_ip_enum_list,
    process_acquisition,
    process_acquisition_with_enum,
)


def main():
    args = parse_args()

    if not args.silent:
        print_banner()

    # Pre-flight: validate API keys (real requests) + tools before any work
    if not run_preflight(check_expansion=args.expand, silent=args.silent):
        sys.exit(0)

    # Parse source filters
    selected_sources = parse_sources(args.sources) if args.sources else None

    # Parse email filters
    email_filters = None
    if args.email_filters:
        email_filters = [f.strip() for f in args.email_filters.split(',') if f.strip()]
        if not email_filters:
            print("[-] Error: No valid email filters provided!")
            return

    # Route to the correct handler
    if args.url:
        process_single_domain(
            args.url, args.live, args.expand,
            selected_sources=selected_sources, silent=args.silent
        )
    elif args.list:
        process_domain_list(
            args.list, args.live, args.parallel_domains, args.expand,
            selected_sources=selected_sources, silent=args.silent
        )
    elif args.ip_domain:
        process_ip_single(args.ip_domain, silent=args.silent)
    elif args.ip_list:
        process_ip_list(args.ip_list, silent=args.silent)
    elif args.ip_enum_domain:
        process_ip_enum_single(
            args.ip_enum_domain, args.live,
            selected_sources=selected_sources, silent=args.silent
        )
    elif args.ip_enum_list:
        process_ip_enum_list(
            args.ip_enum_list, args.live,
            selected_sources=selected_sources, silent=args.silent
        )
    elif args.acquisition:
        process_acquisition(args.acquisition, email_filters, silent=args.silent)
    elif args.acquisition_enum:
        process_acquisition_with_enum(
            args.acquisition_enum, email_filters, args.live,
            args.parallel_domains, args.expand,
            selected_sources=selected_sources, silent=args.silent
        )

    if not args.silent:
        print("\n[✓] All operations completed!")


if __name__ == "__main__":
    main()
