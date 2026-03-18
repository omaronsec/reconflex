# Reconflex v4.2

**Bug Bounty Recon Framework (Parallel Edition)**

Reconflex aggregates subdomains from 8 sources simultaneously, giving you broader coverage than any single tool alone.

**Sources:** VirusTotal, SecurityTrails, crt.sh, Shodan, Chaos, URLScan, AlienVault OTX, Subfinder

---

## Features

- **Parallel Execution** - All 8 API sources queried at the same time
- **Pre-flight Checks** - Validates API keys via real requests and tools before scan starts
- **Subdomain Enumeration** - Single domain or batch mode from a list
- **Domain Acquisition** - Discover associated/related domains via SecurityTrails + OTX
- **IP Enumeration** - CIDR and IP discovery via SecurityTrails + Shodan SSL
- **Subdomain Expansion** - Generate and bruteforce permutations with alterx + shuffledns
- **Live Check** - Verify which subdomains are actually alive with httpx
- **Silent Mode** - Pipe-friendly output for chaining with other tools
- **Source Selection** - Choose specific sources with `--sources vt,st,crtsh`
- **Custom Scan Naming** - Name your scan directory with `--name`
- **Domain Validation** - Validates input before firing API calls
- **Retry/Backoff** - Unified exponential backoff across all API modules
- **crt.sh Fallback** - Automatically falls back to Certspotter if crt.sh is down

---

## Installation

### Step 1: Clone the repo

```bash
git clone https://github.com/omaronsec/reconflex.git
cd reconflex
```

### Step 2: Install Python dependencies

```bash
pip install -r requirements.txt
```

> If you get `externally-managed-environment` error (Debian/Ubuntu/Kali):
> ```bash
> pip install --break-system-packages -r requirements.txt
> ```

### Step 3: Install Go tools

Make sure [Go](https://go.dev/doc/install) is installed, then run:

```bash
chmod +x setup.sh
./setup.sh
```

This installs: `subfinder`, `httpx`, `alterx`, `shuffledns`, `anew`, `massdns`, and the Shodan CLI.

Update tools later with:
```bash
./setup.sh --update
```

### Step 4: Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```
OTX_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CHAOS_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

**Where to get the keys:**

| Service | Sign Up |
|---------|---------|
| AlienVault OTX | https://otx.alienvault.com |
| SecurityTrails | https://securitytrails.com |
| VirusTotal | https://virustotal.com |
| Chaos (ProjectDiscovery) | https://chaos.projectdiscovery.io |
| URLScan.io | https://urlscan.io |

### Step 5: Configure Shodan (optional)

```bash
shodan init YOUR_SHODAN_API_KEY
```

### Step 6: Validate setup

```bash
python3 config.py
```

This checks all API keys, tools, and required files are properly configured.

---

## Usage

### Basic subdomain enumeration

```bash
python3 reconflex.py -u example.com
```

### Batch mode (multiple domains)

```bash
python3 reconflex.py -l domains.txt
```

### Named scan

```bash
python3 reconflex.py -l domains.txt --name abbvie-q1
```

### Check for live subdomains

```bash
python3 reconflex.py -u example.com -live
```

### Subdomain expansion (alterx + shuffledns)

```bash
python3 reconflex.py -u example.com -expand
```

### Full scan with expansion + live check

```bash
python3 reconflex.py -l domains.txt -expand -live
```

### IP enumeration

```bash
python3 reconflex.py -ips-d example.com
python3 reconflex.py -ips-l targets.txt
```

### Subdomain + IP enumeration combined

```bash
python3 reconflex.py -ips-enum-d example.com
python3 reconflex.py -ips-enum-d example.com -live
```

### Domain acquisition (find related domains)

```bash
python3 reconflex.py -acq example.com
python3 reconflex.py -acq example.com -email abbvie,caterpillar
```

### Acquisition + enumeration

```bash
python3 reconflex.py -acq-enum example.com -live -pd 5 -expand
```

### Silent mode (pipe to other tools)

```bash
python3 reconflex.py -u example.com --silent | httpx | nuclei
```

### Select specific sources

```bash
python3 reconflex.py -u example.com --sources vt,st,crtsh,shodan
```

### Parallel domain processing

```bash
python3 reconflex.py -l domains.txt -pd 5
```

---

## Output Structure

```
output/
|-- quick_results/              (Single domain: -u)
|   +-- example.com_subdomains.txt
|   +-- live_example.com_subdomains.txt
|   +-- all_in_one_example.com.txt           (if -expand)
|   +-- live_all_in_one_example.com.txt      (if -expand -live)
|
|-- scans/                      (Batch scans: -l, -acq-enum, -ips-enum-l)
|   +-- 2026-01-05_abbvie-q1/               (--name abbvie-q1)
|   |   +-- per_domain/
|   |   |   +-- sub.example.com.txt         (flat file per domain, skipped if 0 results)
|   |   +-- all_subdomains.txt              (all unique subdomains combined)
|   |   +-- live_subdomains.txt             (if -live)
|   |   +-- subdomains_by_domain.txt        (grouped view per domain)
|   |   +-- domains_with_results.txt        (only domains that had results)
|   |   +-- summary.txt                     (scan summary report)
|   |   +-- ips/                            (if -ips-enum-l)
|   |       +-- all_ips.txt
|   |       +-- ips_for_example.com.txt
|
|-- acquisition/                (Acquisition: -acq)
|   +-- example.com_acquisition.txt
|
+-- ips/                        (IP enumeration: -ips-d, -ips-l)
    +-- ips_for_example.com_05_01.txt
```

---

## All Options

| Flag | Description |
|------|-------------|
| `-u DOMAIN` | Single target domain |
| `-l FILE` | File with list of domains |
| `-live` | Check for live subdomains (httpx) |
| `-expand` | Run subdomain expansion (alterx + shuffledns) |
| `-pd N` | Parallel domain count (default: 3) |
| `--name NAME` | Custom name for the scan directory |
| `--silent` | Silent mode - results only, no banner/progress |
| `--sources SOURCES` | Select sources (e.g., `vt,st,crtsh,shodan,chaos,urlscan,otx,sf`) |
| `-ips-d DOMAIN` | IP enumeration for single domain |
| `-ips-l FILE` | IP enumeration for domain list |
| `-ips-enum-d DOMAIN` | Subdomain + IP enumeration |
| `-ips-enum-l FILE` | Subdomain + IP enumeration for list |
| `-acq DOMAIN` | Find associated domains |
| `-acq-enum DOMAIN` | Acquisition + subdomain enumeration |
| `-email DOMAINS` | Email domain filters for acquisition |

---

## Running Tests

```bash
python3 -m unittest tests.test_utils -v
```
