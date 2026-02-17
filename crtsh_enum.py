#!/usr/bin/env python3

import argparse
import json
import os
import ssl
import sys
import time
import socket
import urllib.request
import urllib.error
from multiprocessing import Pool, cpu_count
from collections import defaultdict

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def supports_color():
    if os.getenv("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


def colorize(text, color):
    if not supports_color():
        return text
    return f"{color}{text}{RESET}"


def query_crtsh(domain, wildcard=True, expired=False):
    base_url = "https://crt.sh/?q={query}&output=json"
    query = f"%.{domain}" if wildcard else domain

    url = base_url.format(query=query)
    headers = {"User-Agent": "Mozilla/5.0 (crt.sh enumerator)"}

    req = urllib.request.Request(url, headers=headers)

    retries = 3
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as resp:
                data = json.loads(resp.read().decode())
                return data
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 2 ** (attempt + 1)
                print(f"[!] Rate limited, waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"[!] HTTP error {e.code}: {e.reason}", file=sys.stderr)
                return []
        except urllib.error.URLError as e:
            print(f"[!] Connection error: {e.reason}", file=sys.stderr)
            time.sleep(2)
        except json.JSONDecodeError:
            print("[!] Invalid JSON response from crt.sh", file=sys.stderr)
            return []
        except Exception as e:
            print(f"[!] Unexpected error: {e}", file=sys.stderr)
            time.sleep(2)

    return []


def extract_subdomains(crtsh_data, domain):
    subdomains = set()

    for entry in crtsh_data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            name = name.lstrip("*.")
            if name and name.endswith(domain) and name != domain:
                if all(c.isalnum() or c in ".-_" for c in name):
                    subdomains.add(name)

    return subdomains


def resolve_subdomain(subdomain):
    try:
        answers = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = sorted(set(addr[4][0] for addr in answers))
        return (subdomain, ips)
    except (socket.gaierror, socket.timeout, OSError):
        return (subdomain, None)


def resolve_subdomains(subdomains, workers):
    results = {"alive": {}, "dead": []}

    with Pool(processes=workers) as pool:
        for subdomain, ips in pool.imap_unordered(resolve_subdomain, subdomains):
            if ips:
                results["alive"][subdomain] = ips
            else:
                results["dead"].append(subdomain)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains via crt.sh Certificate Transparency logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com -r -w 50
  %(prog)s -d example.com -o subs.txt --alive-only
  %(prog)s -d example.com -r --json -o results.json
  cat domains.txt | %(prog)s --stdin -r -w 100"""
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-d", "--domain", help="Target domain to enumerate")
    input_group.add_argument("--stdin", action="store_true",
                             help="Read domains from stdin (one per line)")

    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-r", "--resolve", action="store_true",
                        help="Resolve subdomains to IP addresses")
    parser.add_argument("-w", "--workers", type=int, default=cpu_count() * 4,
                        help=f"Number of parallel workers (default: {cpu_count() * 4})")
    parser.add_argument("--alive-only", action="store_true",
                        help="Only show subdomains that resolve (requires -r)")
    parser.add_argument("--no-wildcard", action="store_true",
                        help="Don't use wildcard query (exact match only)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Suppress banner and status messages")

    args = parser.parse_args()

    if args.alive_only and not args.resolve:
        parser.error("--alive-only requires -r/--resolve")

    if not args.silent:
        print(f"""
 ██████╗██████╗ ████████╗   ███████╗██╗  ██╗
██╔════╝██╔══██╗╚══██╔══╝   ██╔════╝██║  ██║
██║     ██████╔╝   ██║      ███████╗███████║
██║     ██╔══██╗   ██║      ╚════██║██╔══██║
╚██████╗██║  ██║   ██║   ██╗███████║██║  ██║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝
  crt.sh Subdomain Enumerator
  by c0d3Ninja
  https://gotr00t0day.github.io
""", file=sys.stderr)

    domains = []
    if args.stdin:
        domains = [line.strip() for line in sys.stdin if line.strip()]
    else:
        domains = [args.domain]

    all_subdomains = set()
    all_results = {}

    for domain in domains:
        if not args.silent:
            print(f"[*] Querying crt.sh for: {domain}", file=sys.stderr)

        data = query_crtsh(domain, wildcard=not args.no_wildcard)

        if not data:
            if not args.silent:
                print(f"[!] No results for {domain}", file=sys.stderr)
            continue

        subs = extract_subdomains(data, domain)

        if not args.silent:
            print(f"[+] Found {len(subs)} unique subdomains for {domain}", file=sys.stderr)

        all_subdomains.update(subs)

        if args.resolve:
            if not args.silent:
                print(f"[*] Resolving with {args.workers} workers...", file=sys.stderr)

            results = resolve_subdomains(subs, args.workers)
            all_results[domain] = results

            if not args.silent:
                alive = len(results["alive"])
                dead = len(results["dead"])
                print(f"[+] Alive: {alive} | Dead: {dead}", file=sys.stderr)

    raw_output = ""
    if args.json:
        if args.resolve:
            output_data = {}
            for domain, results in all_results.items():
                output_data[domain] = {
                    "alive": results["alive"],
                    "dead": results["dead"] if not args.alive_only else [],
                    "total": len(results["alive"]) + len(results["dead"]),
                    "alive_count": len(results["alive"]),
                }
            output = json.dumps(output_data, indent=2, sort_keys=True)
        else:
            output = json.dumps(sorted(all_subdomains), indent=2)
    else:
        lines = []
        raw_lines = []
        if args.resolve:
            for domain, results in all_results.items():
                for sub in sorted(results["alive"].keys()):
                    ips = ", ".join(results["alive"][sub])
                    lines.append(f"{colorize(sub, GREEN)} -> {colorize(ips, YELLOW)}")
                    raw_lines.append(f"{sub} -> {ips}")
                if not args.alive_only:
                    for sub in sorted(results["dead"]):
                        lines.append(f"{colorize(sub, GREEN)} -> {colorize('NXDOMAIN', RED)}")
                        raw_lines.append(f"{sub} -> NXDOMAIN")
        else:
            for sub in sorted(all_subdomains):
                lines.append(colorize(sub, GREEN))
                raw_lines.append(sub)

        output = "\n".join(lines)
        raw_output = "\n".join(raw_lines)

    if args.output:
        file_output = raw_output if not args.json else output
        with open(args.output, "w") as f:
            f.write(file_output + "\n")
        if not args.silent:
            print(f"\n[+] Results saved to {args.output}", file=sys.stderr)
        if not args.json:
            print(output)
    else:
        print(output)

    if not args.silent:
        print(f"\n[+] Total unique subdomains: {len(all_subdomains)}", file=sys.stderr)


if __name__ == "__main__":
    main()
