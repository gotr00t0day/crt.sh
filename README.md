# crtsh_enum.py

Fast subdomain enumeration via [crt.sh](https://crt.sh) Certificate Transparency logs with parallel DNS resolution.

## Features

- Queries crt.sh CT logs for all certificate entries matching a domain
- Extracts and deduplicates subdomains from certificate `name_value` fields
- Parallel DNS resolution using Python `multiprocessing`
- Color-coded terminal output (green subdomains, yellow IPs, red NXDOMAIN)
- JSON or plaintext output
- Stdin support for batch domain processing
- Zero external dependencies (Python stdlib only)
- Auto-retry with exponential backoff on rate limiting
- Clean output when piping (auto-disables colors)

## Requirements

- Python 3.6+
- No external packages required

## Usage

```
usage: crtsh_enum.py [-h] (-d DOMAIN | --stdin) [-o OUTPUT] [-r] [-w WORKERS]
                     [--alive-only] [--no-wildcard] [--json] [-s]

Enumerate subdomains via crt.sh Certificate Transparency logs

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain to enumerate
  --stdin               Read domains from stdin (one per line)
  -o OUTPUT, --output OUTPUT
                        Output file path
  -r, --resolve         Resolve subdomains to IP addresses
  -w WORKERS, --workers WORKERS
                        Number of parallel workers (default: auto)
  --alive-only          Only show subdomains that resolve (requires -r)
  --no-wildcard         Don't use wildcard query (exact match only)
  --json                Output as JSON
  -s, --silent          Suppress banner and status messages
```

## Examples

### Basic enumeration

```bash
python3 crtsh_enum.py -d example.com
```

### With DNS resolution

```bash
python3 crtsh_enum.py -d example.com -r -w 50
```

Output:
```
mail.example.com -> 93.184.216.34
www.example.com -> 93.184.216.34
dev.example.com -> NXDOMAIN
```

### Only alive subdomains, saved to file

```bash
python3 crtsh_enum.py -d example.com -r --alive-only -o alive.txt
```

### JSON output

```bash
python3 crtsh_enum.py -d example.com -r --json -o results.json
```

```json
{
  "example.com": {
    "alive": {
      "mail.example.com": ["93.184.216.34"],
      "www.example.com": ["93.184.216.34"]
    },
    "alive_count": 2,
    "dead": ["dev.example.com"],
    "total": 3
  }
}
```

### Batch processing from stdin

```bash
cat domains.txt | python3 crtsh_enum.py --stdin -r -w 100
```

### Silent mode (clean output for piping)

```bash
python3 crtsh_enum.py -d example.com -s | httpx
python3 crtsh_enum.py -d example.com -s | nuclei -t cves/
python3 crtsh_enum.py -d example.com -s | sort -u > subs.txt
```

## How It Works

1. Sends a wildcard query (`%.domain.com`) to the crt.sh JSON API
2. Parses certificate `name_value` fields to extract unique subdomains
3. Strips wildcard prefixes (`*.`) and deduplicates
4. Optionally resolves each subdomain via `socket.getaddrinfo()` using a multiprocessing pool
5. Outputs results with color coding to terminal, clean text to files
