## Overview

**ReconPipe** is an automated reconnaissance pipeline that orchestrates multiple security tools to perform comprehensive network and OSINT assessments. It combines fast port scanning, detailed service detection, web service visualization, vulnerability assessment, and professional reporting into a single streamlined workflow.


## Installation

### Prerequisites

- **Operating System:** Linux (tested on Kali Linux, Ubuntu)
- **Python:** 3.13 or higher
- **Privileges:** Root/sudo access required for Masscan and Nmap

### Step 1: Clone the Repository

```bash
git clone https://github.com/jdants/reconpipe.git
cd reconpipe
```

### Step 2: Activate a Venv and Install Python Dependencies

```bash
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

### Step 3: Install Required Tools

#### Masscan
```bash
sudo apt-get update
sudo apt-get install -y masscan
```

#### Nmap
```bash
sudo apt-get install -y nmap
```

#### theHarvester
```bash
pip3 install theHarvester
# Or from source:
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip3 install -r requirements.txt
```

#### EyeWitness
```bash
sudo apt-get install -y python3-pip chromium-browser git
cd /opt
sudo git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup
sudo ./setup.sh
```

### Step 4: Verify Installation

```bash
# Test all tools are accessible
masscan --version
nmap --version
theHarvester --version
python3 /opt/EyeWitness/Python/EyeWitness.py --version

# Test Python imports
python -c "from tools.eyewitness_wrapper import run_eyewitness; print('✓ All modules loaded')"
```

---

## Quick Start

### 1. Create Target List

Create a `targets.txt` file with your authorized targets:

```
# IP addresses and CIDR ranges
192.168.1.0/24

# Domains
example.com
testsite.org
```

### 2. Run Basic Scan

```bash
sudo python run_recon.py targets.txt
```

### 3. View Results

```bash
# View comprehensive report
cat out/report.md

# Browse EyeWitness screenshots
xdg-open out/eyewitness/report/report.html

# Check JSON inventory
cat out/inventory.json
```

---

## Usage

### Basic Usage

```bash
sudo python run_recon.py <targets_file> [options]
```

### Command-Line Options

```
positional arguments:
  targets               File containing target IPs/domains (one per line)

optional arguments:
  -h, --help            Show this help message and exit
  -o, --output DIR      Output directory (default: out)
  -v, --verbose         Enable verbose logging
  
Scanning Options:
  --skip-masscan        Skip Masscan phase
  --skip-nmap           Skip Nmap phase
  --skip-harvester      Skip theHarvester phase
  --skip-eyewitness     Skip EyeWitness screenshot capture
  --no-sudo             Run without sudo (limited functionality)
  --no-report           Skip Markdown report generation

CVE Lookup Options:
  --cve-lookup          Enable CVE vulnerability lookup via NVD API
  --nvd-api-key KEY     NVD API key for higher rate limits
  --cve-max-age DAYS    Only lookup CVEs from last N days (default: 365)
```

### Common Use Cases

#### Full Assessment with CVE Lookup
```bash
sudo python run_recon.py targets.txt --cve-lookup --nvd-api-key YOUR_KEY
```

#### Fast Scan (Skip Screenshots)
```bash
sudo python run_recon.py targets.txt --skip-eyewitness
```

#### OSINT Only (No Network Scanning)
```bash
python run_recon.py targets.txt --skip-masscan --skip-nmap --no-sudo
```

#### Network Scan Only (No OSINT)
```bash
sudo python run_recon.py targets.txt --skip-harvester
```

---

## Output Structure

After running ReconPipe, your output directory contains:

```
out/
├── report.md                    # Comprehensive Markdown report with screenshots
├── inventory.json               # Complete structured data (machine-readable)
├── inventory.csv                # Spreadsheet-compatible format
├── summary_report.txt           # Text-based summary
├── vulnerability_report.txt     # Detailed CVE assessment (if --cve-lookup used)
├── recon_pipeline.log           # Detailed execution log
│
├── masscan.json                 # Raw Masscan output
│
├── nmap/                        # Nmap outputs
│   ├── nmap_192_168_1_1.xml    # XML format
│   ├── nmap_192_168_1_1.txt    # Human-readable format
│   └── ...
│
├── harvester/                   # theHarvester outputs
│   ├── harvester_example_com.json
│   └── ...
│
└── eyewitness/                  # EyeWitness outputs
    └── report/
        ├── report.html          # EyeWitness HTML report
        ├── results.json         # Screenshot metadata
        └── screens/             # Screenshot images
            ├── http_192_168_1_1_80.png
            ├── https_192_168_1_1_443.png
            └── ...
```

---

## Configuration

### config.py

Customize scan parameters by editing `config.py`:

```python
# Masscan Configuration
MASSCAN_CONFIG = {
    'ports': '1-1000',          # Port range to scan
    'rate': 1000,               # Packets per second
    'wait': 10,                 # Seconds to wait for responses
}

# Nmap Configuration
NMAP_CONFIG = {
    'scan_type': '-sV',         # Service version detection
    'timing': '-T4',            # Aggressive timing
    'additional_flags': '-sC',  # Default scripts
    'timeout': 600,             # Timeout per host (seconds)
}

# theHarvester Configuration
HARVESTER_CONFIG = {
    'sources': 'all',           # Data sources to use
    'limit': 500,               # Results per source
    'timeout': 300,             # Timeout per domain (seconds)
}
```

### Environment Variables

```bash
# Set NVD API key for CVE lookup
export NVD_API_KEY="your-api-key-here"

# Run with API key
sudo -E python run_recon.py targets.txt --cve-lookup
```

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

---

## Examples

### Example 1: Corporate Network Assessment

```bash
# Create target list
cat > corporate_targets.txt << EOF
10.0.0.0/24
192.168.1.0/24
intranet.company.com
mail.company.com
EOF

# Run full assessment
sudo python run_recon.py corporate_targets.txt \
  --cve-lookup \
  --nvd-api-key abc123 \
  -o corporate_assessment

# View report
cat corporate_assessment/report.md
```

### Example 2: External Perimeter Scan

```bash
# External targets only
cat > external_targets.txt << EOF
example.com
www.example.com
api.example.com
EOF

# Focus on web services and OSINT
sudo python run_recon.py external_targets.txt \
  --skip-masscan \
  -o external_scan
```

### Example 3: Quick Port Scan

```bash
# Fast scan without extras
sudo python run_recon.py targets.txt \
  --skip-harvester \
  --skip-eyewitness \
  --no-report
```

---

##  Architecture

### Pipeline Flow

```
┌─────────────┐
│ targets.txt │
└──────┬──────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 1: Masscan (Fast Discovery)   │
│ - Scans ports 1-1000                 │
│ - Identifies open ports              │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 2: Nmap (Detailed Detection)  │
│ - Service version detection          │
│ - OS fingerprinting                  │
│ - Script scanning                    │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 3: theHarvester (OSINT)       │
│ - Email addresses                    │
│ - Subdomains                         │
│ - IP addresses                       │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 4: Aggregation                 │
│ - Combines all data                  │
│ - Creates inventory.json             │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 5: EyeWitness (Screenshots)   │
│ - Detects web services               │
│ - Captures screenshots               │
│ - Updates inventory                  │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 6: CVE Lookup (Optional)      │
│ - Queries NVD database               │
│ - Matches service versions           │
│ - Generates vulnerability report     │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Phase 7: Report Generation           │
│ - Creates report.md                  │
│ - Embeds screenshots                 │
│ - Provides recommendations           │
└──────┬───────────────────────────────┘
       │
       v
┌──────────────────────────────────────┐
│ Complete Assessment Package          │
│ - out/ directory with all results    │
└──────────────────────────────────────┘
```

### Module Structure

```
reconpipe/
├── run_recon.py              # Main orchestrator
├── tools/                    # Tool wrappers
│   ├── masscan_wrapper.py    # Masscan integration
│   ├── nmap_wrapper.py       # Nmap integration
│   ├── harvester_wrapper.py  # theHarvester integration
│   ├── eyewitness_wrapper.py # EyeWitness integration
│   ├── cve_lookup.py         # NVD API integration
│   ├── aggregate.py          # Data aggregation
│   └── report_generator.py   # Markdown report generation
├── config.py                 # Configuration settings
├── targets.txt               # Target list
└── requirements.txt          # Python dependencies
```



---

## Legal Disclaimer

**IMPORTANT:** This tool is for **authorized security testing only**.


**Unauthorized use of this tool may be illegal in your jurisdiction.**

The authors and contributors are not responsible for any misuse or damage caused by this tool. Use at your own risk and responsibility.

---

## Troubleshooting

### Common Issues

#### Issue: "Permission denied" errors
```bash
Solution: Run with sudo
sudo python run_recon.py targets.txt
```

#### Issue: "EyeWitness not found"
```bash
Solution: Install EyeWitness
cd /opt
sudo git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup && sudo ./setup.sh
```

#### Issue: No screenshots captured
```bash
Causes:
- No web services found
- EyeWitness crashed (check logs)
- Services require authentication

Solution: Check recon_pipeline.log for details
```

#### Issue: Screenshots not in report.md
```bash
Cause: Bug in eyewitness_wrapper.py with None values

Solution: Edit tools/eyewitness_wrapper.py line 149-150:
Change: service.get('service', '').lower()
To: (service.get('service') or '').lower()
```

### Debug Mode

```bash
# Enable verbose logging
python run_recon.py targets.txt -v

# Check logs
tail -f recon_pipeline.log

# Test individual components
python -c "from tools.nmap_wrapper import check_nmap_installed; print(check_nmap_installed())"
```

---

### External Resources

- [Masscan Documentation](https://github.com/robertdavidgraham/masscan)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [theHarvester Wiki](https://github.com/laramies/theHarvester/wiki)
- [EyeWitness Documentation](https://github.com/FortyNorthSecurity/EyeWitness)
- [NVD API Documentation](https://nvd.nist.gov/developers)

---

## Acknowledgments

This tool integrates the following excellent projects:

- [Masscan](https://github.com/robertdavidgraham/masscan) by Robert Graham
- [Nmap](https://nmap.org/) by Gordon Lyon (Fyodor)
- [theHarvester](https://github.com/laramies/theHarvester) by Christian Martorella
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) by FortyNorth Security
- [NVD API](https://nvd.nist.gov/) by NIST

Special thanks to the security community for continuous feedback and improvements.
