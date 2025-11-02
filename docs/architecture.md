# Architecture Diagram: EyeWitness Integration

## Complete Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         RECONNAISSANCE PIPELINE                      │
│                     (Updated with EyeWitness & Reports)              │
└─────────────────────────────────────────────────────────────────────┘

┌───────────────┐
│ targets.txt   │  (Input: IPs, CIDR ranges, domains)
└───────┬───────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 1: MASSCAN - Fast Port Discovery                           │
│ • Scans ports 1-1000 on IP targets                               │
│ • Output: masscan.json                                            │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 2: NMAP - Detailed Service Detection                       │
│ • Service version detection (-sV)                                 │
│ • OS fingerprinting (-O)                                          │
│ • Default scripts (-sC)                                           │
│ • Output: nmap/*.xml                                              │
│                                                                   │
│ Discovers services like:                                          │
│   • 80/tcp   http     Apache/2.4.41                              │
│   • 443/tcp  https    nginx/1.18.0                               │
│   • 8080/tcp http     Tomcat/9.0                                 │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 3: THEHARVESTER - OSINT Collection                         │
│ • Gathers emails, subdomains, IPs                                │
│ • Output: harvester/*.json                                        │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 4: AGGREGATION - Combine Results                           │
│ • Merges Masscan + Nmap + Harvester data                         │
│ • Creates unified inventory structure                             │
│ • Output: inventory.json, inventory.csv                           │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 5: EYEWITNESS - Web Screenshots & Analysis ⭐ NEW           │
│                                                                   │
│ 1. Extract web services from inventory:                          │
│    ┌─────────────────────────────────────────────┐              │
│    │ For each host in inventory:                 │              │
│    │   For each service:                          │              │
│    │     if port in [80,443,8080,...] OR         │              │
│    │        service in [http,https,...] OR       │              │
│    │        product in [apache,nginx,...]        │              │
│    │     then: add to web_services list          │              │
│    └─────────────────────────────────────────────┘              │
│                                                                   │
│ 2. Generate URL list:                                            │
│    • http://10.0.3.1:80                                          │
│    • https://10.0.3.1:443                                        │
│    • http://example.com:8080                                     │
│                                                                   │
│ 3. Execute EyeWitness:                                           │
│    python3 EyeWitness.py -f urls.txt -d eyewitness/report       │
│                                                                   │
│ 4. Capture for each URL:                                         │
│    • Screenshot (PNG)                                            │
│    • Response code (200, 401, 403, etc.)                         │
│    • Page title                                                  │
│    • Server header                                               │
│    • Content length                                              │
│                                                                   │
│ 5. Update inventory.json:                                        │
│    hosts:                                                         │
│      10.0.3.1:                                                   │
│        services:                                                 │
│          "80/tcp":                                               │
│            service: "http"                                       │
│            eyewitness:  ← NEW                                    │
│              url: "http://10.0.3.1:80"                          │
│              screenshot: "eyewitness/report/screens/..."         │
│              response_code: 200                                  │
│              page_title: "Apache Default"                        │
│                                                                   │
│ Output: eyewitness/report/                                       │
│   ├── report.html                                                │
│   ├── results.json                                               │
│   └── screens/                                                   │
│       ├── http_10_0_3_1_80.png                                  │
│       └── https_10_0_3_1_443.png                                │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 6: CVE LOOKUP - Vulnerability Assessment (Optional)        │
│ • Queries NVD API for known CVEs                                 │
│ • Updates inventory with vulnerability data                       │
│ • Output: vulnerability_report.txt                                │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│ PHASE 7: REPORT GENERATION - Create report.md ⭐ NEW             │
│                                                                   │
│ Generates comprehensive Markdown report:                         │
│                                                                   │
│ ┌─────────────────────────────────────────────────────┐         │
│ │ # Reconnaissance Assessment Report                  │         │
│ │                                                       │         │
│ │ ## Executive Summary                                 │         │
│ │ - Total Hosts: 5                                     │         │
│ │ - Open Ports: 27                                     │         │
│ │ - Web Services: 8                                    │         │
│ │ - Screenshots Captured: 8 ⭐                         │         │
│ │                                                       │         │
│ │ ## Host Findings                                     │         │
│ │ ### Host: 10.0.3.1                                   │         │
│ │ | Port | Service | Version |                         │         │
│ │ | 80   | http    | Apache 2.4.41 |                   │         │
│ │                                                       │         │
│ │ ## Web Services Analysis ⭐ NEW                     │         │
│ │ ### http://10.0.3.1:80                              │         │
│ │                                                       │         │
│ │ #### Screenshot                                      │         │
│ │ ![](eyewitness/report/screens/http_10_0_3_1_80.png) │         │
│ │                                                       │         │
│ │ #### Analysis                                        │         │
│ │ ✅ Service accessible                                │         │
│ │ ⚠️  Default Apache page                              │         │
│ │                                                       │         │
│ │ ## Vulnerability Assessment                          │         │
│ │ (If CVE lookup enabled)                              │         │
│ │                                                       │         │
│ │ ## Recommendations                                   │         │
│ │ 1. Patch critical vulnerabilities                    │         │
│ │ 2. Remove default pages                              │         │
│ └─────────────────────────────────────────────────────┘         │
│                                                                   │
│ Output: report.md                                                │
└───────┬───────────────────────────────────────────────────────────┘
        │
        v
┌───────────────────────────────────────────────────────────────────┐
│                        COMPLETE OUTPUT PACKAGE                    │
│                                                                   │
│ out/                                                              │
│ ├── report.md ⭐ NEW - Comprehensive report with screenshots     │
│ ├── inventory.json - Complete structured data                    │
│ ├── inventory.csv - Spreadsheet format                           │
│ ├── summary_report.txt - Text summary                            │
│ ├── vulnerability_report.txt - CVE details (if enabled)          │
│ ├── masscan.json                                                 │
│ ├── nmap/                                                        │
│ │   └── *.xml, *.txt                                            │
│ ├── harvester/                                                   │
│ │   └── *.json                                                  │
│ └── eyewitness/ ⭐ NEW                                           │
│     └── report/                                                  │
│         ├── report.html                                          │
│         ├── results.json                                         │
│         └── screens/                                             │
│             ├── http_10_0_3_1_80.png                            │
│             ├── https_10_0_3_1_443.png                          │
│             └── http_example_com_8080.png                       │
└───────────────────────────────────────────────────────────────────┘
```

## Data Flow: Web Service Detection

```
Nmap discovers service
       │
       v
Port: 80, Service: "http", Product: "Apache/2.4.41"
       │
       v
Stored in inventory.json
       │
       v
EyeWitness extracts web services
       │
       ├─ Check 1: Is service name in ['http', 'https', 'ssl/http', ...]?
       ├─ Check 2: Is port in [80, 443, 8080, 8443, ...]?
       └─ Check 3: Is product in ['apache', 'nginx', 'iis', ...]?
       │
       v
If ANY check passes → Add to web_services list
       │
       v
Create URL: "http://10.0.3.1:80"
       │
       v
EyeWitness captures:
  • Screenshot → http_10_0_3_1_80.png
  • Metadata  → response_code: 200, title: "Apache"
       │
       v
Update inventory.json with screenshot info
       │
       v
Report generator embeds screenshot in report.md
```

## Module Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      run_recon.py                          │
│                  (Main Orchestrator)                       │
│                                                            │
│  Coordinates all phases and manages workflow              │
└─────────┬──────────────────────────────────────────────────┘
          │
          │ Imports and calls:
          │
          ├──> tools/masscan_wrapper.py
          │      • run_masscan()
          │      • parse_masscan_output()
          │
          ├──> tools/nmap_wrapper.py
          │      • run_nmap()
          │      • parse_nmap_xml()
          │
          ├──> tools/harvester_wrapper.py
          │      • run_harvester()
          │      • parse_harvester_output()
          │
          ├──> tools/aggregate.py
          │      • aggregate_results()
          │      • process_nmap_data()
          │      • process_harvester_data()
          │
          ├──> tools/eyewitness_wrapper.py ⭐ NEW
          │      • run_eyewitness(inventory, output_dir)
          │      • extract_web_services(inventory)
          │      • parse_eyewitness_results()
          │      • update_inventory_with_screenshots()
          │
          ├──> tools/cve_lookup.py
          │      • lookup_cves_for_inventory()
          │      • query_nvd_api()
          │
          └──> tools/report_generator.py ⭐ NEW
                 • generate_markdown_report(inventory, output_dir)
                 • write_header()
                 • write_executive_summary()
                 • write_host_findings()
                 • write_web_services_analysis() ⭐
                 • write_vulnerability_assessment()
                 • write_recommendations()
```

## Web Services Analysis Section Flow

```
report_generator.py: write_web_services_analysis()
    │
    ├─ 1. Collect all web services from inventory
    │      For each host:
    │        For each service:
    │          If service has 'eyewitness' key:
    │            Add to web_services list
    │
    ├─ 2. For each web service:
    │      │
    │      ├─ Write URL header
    │      │    ### http://10.0.3.1:80
    │      │
    │      ├─ Write service details table
    │      │    | Property | Value |
    │      │    | Response Code | 200 |
    │      │    | Page Title | Apache Default |
    │      │
    │      ├─ Embed screenshot ⭐
    │      │    ![URL](eyewitness/report/screens/screenshot.png)
    │      │
    │      └─ Write automated analysis
    │           ✅ Service is accessible
    │           ⚠️ Default page detected
    │
    └─ 3. Generate section summary
```

## Screenshot Storage & Embedding

```
EyeWitness captures screenshot:
    http://10.0.3.1:80
         ↓
Saved to: out/eyewitness/report/screens/http_10_0_3_1_80.png
         ↓
Stored in inventory.json:
    "eyewitness": {
        "screenshot": "eyewitness/report/screens/http_10_0_3_1_80.png"
    }
         ↓
Embedded in report.md using relative path:
    ![http://10.0.3.1:80](eyewitness/report/screens/http_10_0_3_1_80.png)
         ↓
When viewing report.md from project root:
    • Markdown viewer loads image from relative path
    • Screenshot appears inline in report
```

## Integration Points

### 1. inventory.json Structure (Updated)

```json
{
  "metadata": {
    "scan_date": "2025-11-02T17:30:00",
    "tools_used": ["masscan", "nmap", "theHarvester", "eyewitness"],
    "eyewitness_enabled": true,        ← NEW
    "screenshots_captured": 8           ← NEW
  },
  "hosts": {
    "10.0.3.1": {
      "ip": "10.0.3.1",
      "services": {
        "80/tcp": {
          "port": 80,
          "service": "http",
          "product": "Apache",
          "version": "2.4.41",
          "eyewitness": {                ← NEW
            "url": "http://10.0.3.1:80",
            "screenshot": "eyewitness/report/screens/http_10_0_3_1_80.png",
            "response_code": 200,
            "page_title": "Apache Default",
            "server_header": "Apache/2.4.41 (Ubuntu)"
          }
        }
      }
    }
  }
}
```

### 2. Command-Line Options (Updated)

```
New options:
  --skip-eyewitness     Skip EyeWitness screenshot capture
  --no-report           Skip Markdown report generation

Unchanged:
  --skip-masscan        Skip Masscan
  --skip-nmap           Skip Nmap
  --skip-harvester      Skip theHarvester
  --cve-lookup          Enable CVE vulnerability lookup
  --nvd-api-key KEY     NVD API key
```

## Performance Impact

```
Phase Timing (10 hosts):
┌────────────────────────────────────────────────┐
│ Phase               │ Without EW │ With EW     │
├────────────────────────────────────────────────┤
│ Masscan             │ 1-2 min    │ 1-2 min     │
│ Nmap                │ 3-5 min    │ 3-5 min     │
│ Harvester           │ 1-2 min    │ 1-2 min     │
│ Aggregation         │ <10 sec    │ <10 sec     │
│ EyeWitness          │ -          │ +3-5 min ⭐ │
│ CVE Lookup          │ 1-2 min    │ 1-2 min     │
│ Report Generation   │ -          │ +10-30 sec⭐│
├────────────────────────────────────────────────┤
│ TOTAL               │ 5-10 min   │ 10-15 min   │
└────────────────────────────────────────────────┘

Additional Resources:
• CPU: +Moderate (Chromium rendering)
• RAM: +500MB (per screenshot thread)
• Disk: +100-500KB per screenshot
```

## Security Considerations

```
┌────────────────────────────────────────────────────┐
│              SECURITY BEST PRACTICES                │
├────────────────────────────────────────────────────┤
│                                                     │
│ 1. Screenshots may contain sensitive data:         │
│    • Login forms with default usernames            │
│    • Session tokens in URLs                        │
│    • Internal system names                         │
│    • Employee information                          │
│                                                     │
│ 2. Treat report.md as confidential:                │
│    • Complete attack surface mapping               │
│    • Service versions                              │
│    • Vulnerability details                         │
│    • Security architecture                         │
│                                                     │
│ 3. Secure storage:                                 │
│    tar czf assessment.tar.gz out/                  │
│    gpg -c assessment.tar.gz                        │
│    rm -rf out/ assessment.tar.gz                   │
│                                                     │
│ 4. Always obtain written authorization             │
│                                                     │
└────────────────────────────────────────────────────┘
```

---

## Legend

⭐ = New feature added
← = New field in existing structure
✅ = Successful status
⚠️ = Warning/attention needed
🔴 = Critical severity
🟠 = High severity
🟡 = Medium severity
🟢 = Low severity
