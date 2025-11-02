"""
Report Generator - Create comprehensive Markdown reports with screenshots
"""

import os
import logging
import shutil
from typing import Dict, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_markdown_report(inventory: Dict, output_dir: str) -> str:
    """
    Generate a comprehensive Markdown report with screenshots and analysis
    
    Args:
        inventory: Complete inventory with all reconnaissance data
        output_dir: Directory containing all outputs
    
    Returns:
        Path to generated report.md
    """
    
    logger.info("Generating comprehensive Markdown report...")
    
    output_path = Path(output_dir)
    report_file = output_path / 'report.md'
    
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            # Write report header
            write_header(f, inventory)
            
            # Write executive summary
            write_executive_summary(f, inventory)
            
            # Write methodology
            write_methodology(f, inventory)
            
            # Write detailed host findings
            write_host_findings(f, inventory, output_path)
            
            # Write domain intelligence
            write_domain_intelligence(f, inventory)
            
            # Write vulnerability assessment (if CVE lookup was enabled)
            if inventory['metadata'].get('cve_lookup_enabled'):
                write_vulnerability_assessment(f, inventory)
            
            # Write web services analysis (if EyeWitness was used)
            if inventory['metadata'].get('eyewitness_enabled'):
                write_web_services_analysis(f, inventory, output_path)
            
            # Write statistics and summary
            write_statistics(f, inventory)
            
            # Write recommendations
            write_recommendations(f, inventory)
            
            # Write appendices
            write_appendices(f, inventory, output_path)
        
        logger.info(f"✓ Generated Markdown report: {report_file}")
        return str(report_file)
        
    except Exception as e:
        logger.error(f"Error generating Markdown report: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return None


def write_header(f, inventory: Dict):
    """Write report header"""
    meta = inventory['metadata']
    scan_date = datetime.fromisoformat(meta['scan_date']).strftime('%B %d, %Y at %H:%M:%S')
    
    f.write("# Reconnaissance Assessment Report\n\n")
    f.write("---\n\n")
    f.write(f"**Report Generated:** {scan_date}\n\n")
    f.write(f"**Tools Used:** {', '.join(meta.get('tools_used', []))}\n\n")
    f.write("---\n\n")
    f.write("## Document Information\n\n")
    f.write("This report contains the results of an authorized reconnaissance assessment. ")
    f.write("All scanning activities were performed in accordance with proper authorization.\n\n")
    f.write("⚠️ **CONFIDENTIAL** - This document contains sensitive security information.\n\n")
    f.write("---\n\n")


def write_executive_summary(f, inventory: Dict):
    """Write executive summary section"""
    meta = inventory['metadata']
    
    f.write("## Executive Summary\n\n")
    f.write("This reconnaissance assessment identified the following key findings:\n\n")
    
    # Summary statistics
    f.write("### Key Metrics\n\n")
    f.write(f"- **Total Hosts Discovered:** {meta.get('total_hosts', 0)}\n")
    f.write(f"- **Total Open Ports:** {meta.get('total_ports', 0)}\n")
    f.write(f"- **Total Services Identified:** {meta.get('total_services', 0)}\n")
    f.write(f"- **Domains Analyzed:** {meta.get('total_domains', 0)}\n")
    f.write(f"- **Email Addresses Found:** {meta.get('total_emails', 0)}\n")
    
    if meta.get('eyewitness_enabled'):
        f.write(f"- **Web Services Screenshotted:** {meta.get('screenshots_captured', 0)}\n")
    
    if meta.get('cve_lookup_enabled'):
        f.write(f"- **Known Vulnerabilities Found:** {meta.get('total_cves_found', 0)}\n")
    
    f.write("\n")
    
    # Risk assessment
    f.write("### Risk Assessment\n\n")
    
    if meta.get('cve_lookup_enabled'):
        critical_count = sum(
            host.get('vulnerability_summary', {}).get('by_severity', {}).get('CRITICAL', 0)
            for host in inventory['hosts'].values()
        )
        high_count = sum(
            host.get('vulnerability_summary', {}).get('by_severity', {}).get('HIGH', 0)
            for host in inventory['hosts'].values()
        )
        
        if critical_count > 0:
            f.write(f"🔴 **CRITICAL:** {critical_count} critical vulnerabilities identified across the environment.\n\n")
        elif high_count > 0:
            f.write(f"🟠 **HIGH:** {high_count} high-severity vulnerabilities identified.\n\n")
        else:
            f.write(f"🟡 **MODERATE:** Some security concerns identified but no critical vulnerabilities.\n\n")
    else:
        exposed_services = sum(len(host.get('services', {})) for host in inventory['hosts'].values())
        if exposed_services > 50:
            f.write("🟠 **HIGH:** Large attack surface with numerous exposed services.\n\n")
        elif exposed_services > 20:
            f.write("🟡 **MODERATE:** Moderate number of exposed services requiring review.\n\n")
        else:
            f.write("🟢 **LOW:** Limited attack surface identified.\n\n")
    
    f.write("---\n\n")


def write_methodology(f, inventory: Dict):
    """Write methodology section"""
    meta = inventory['metadata']
    tools = meta.get('tools_used', [])
    
    f.write("## Methodology\n\n")
    f.write("This reconnaissance assessment employed a multi-phase approach:\n\n")
    
    if 'masscan' in tools:
        f.write("### Phase 1: Fast Port Discovery (Masscan)\n\n")
        f.write("- **Tool:** Masscan\n")
        f.write("- **Purpose:** Rapid identification of open ports across the target network\n")
        f.write("- **Scope:** TCP ports 1-1000\n")
        f.write("- **Rate:** 1000 packets per second\n\n")
    
    if 'nmap' in tools:
        f.write("### Phase 2: Detailed Service Detection (Nmap)\n\n")
        f.write("- **Tool:** Nmap\n")
        f.write("- **Purpose:** In-depth service version detection and OS fingerprinting\n")
        f.write("- **Techniques:** Service detection (-sV), default scripts (-sC), OS detection (-O)\n")
        f.write("- **Timing:** Aggressive timing (-T4) for faster results\n\n")
    
    if 'theHarvester' in tools:
        f.write("### Phase 3: OSINT Collection (theHarvester)\n\n")
        f.write("- **Tool:** theHarvester\n")
        f.write("- **Purpose:** Gather open-source intelligence on domains\n")
        f.write("- **Sources:** Multiple public data sources\n")
        f.write("- **Data Collected:** Email addresses, subdomains, IP addresses\n\n")
    
    if meta.get('eyewitness_enabled'):
        f.write("### Phase 4: Web Service Analysis (EyeWitness)\n\n")
        f.write("- **Tool:** EyeWitness\n")
        f.write("- **Purpose:** Visual reconnaissance of web services\n")
        f.write("- **Output:** Screenshots and metadata of web applications\n\n")
    
    if meta.get('cve_lookup_enabled'):
        f.write("### Phase 5: Vulnerability Assessment (NVD API)\n\n")
        f.write("- **Tool:** NVD CVE Lookup\n")
        f.write("- **Purpose:** Identify known vulnerabilities in detected services\n")
        f.write("- **Source:** National Vulnerability Database\n")
        cve_date = meta.get('cve_lookup_date')
        if cve_date:
            f.write(f"- **Lookup Date:** {datetime.fromisoformat(cve_date).strftime('%B %d, %Y')}\n")
        f.write("\n")
    
    f.write("---\n\n")


def write_host_findings(f, inventory: Dict, output_path: Path):
    """Write detailed host findings section"""
    f.write("## Detailed Host Findings\n\n")
    
    if not inventory['hosts']:
        f.write("*No hosts discovered during reconnaissance.*\n\n")
        return
    
    # Sort hosts by number of services (most interesting first)
    sorted_hosts = sorted(
        inventory['hosts'].items(),
        key=lambda x: len(x[1].get('services', {})),
        reverse=True
    )
    
    for ip, host_data in sorted_hosts:
        write_single_host(f, ip, host_data, output_path)
    
    f.write("---\n\n")


def write_single_host(f, ip: str, host_data: Dict, output_path: Path):
    """Write details for a single host"""
    hostname = host_data.get('hostname')
    
    f.write(f"### Host: {ip}\n\n")
    
    # Basic information table
    f.write("#### Host Information\n\n")
    f.write("| Property | Value |\n")
    f.write("|----------|-------|\n")
    f.write(f"| IP Address | `{ip}` |\n")
    
    if hostname:
        f.write(f"| Hostname | `{hostname}` |\n")
    
    f.write(f"| Status | {host_data.get('status', 'unknown')} |\n")
    
    if host_data.get('os'):
        os_name = host_data['os']
        os_acc = host_data.get('os_accuracy', 'N/A')
        f.write(f"| Operating System | {os_name} (Accuracy: {os_acc}%) |\n")
    
    if host_data.get('mac_address'):
        f.write(f"| MAC Address | `{host_data['mac_address']}` |\n")
        if host_data.get('vendor'):
            f.write(f"| Vendor | {host_data['vendor']} |\n")
    
    f.write("\n")
    
    # Services table
    services = host_data.get('services', {})
    if services:
        f.write("#### Open Ports and Services\n\n")
        f.write("| Port | Protocol | Service | Version | Banner |\n")
        f.write("|------|----------|---------|---------|--------|\n")
        
        for port_key, service in sorted(services.items()):
            port = service.get('port', 'N/A')
            protocol = service.get('protocol', 'tcp')
            service_name = service.get('service', 'unknown')
            version = service.get('version', '')
            product = service.get('product', '')
            banner = service.get('banner', service_name)
            
            # Build version string
            version_str = f"{product} {version}".strip() if product or version else ''
            
            # Truncate long banners
            if len(banner) > 50:
                banner = banner[:47] + '...'
            
            f.write(f"| {port} | {protocol} | {service_name} | {version_str} | {banner} |\n")
        
        f.write("\n")
    
    # Vulnerability information (if available)
    if host_data.get('vulnerability_summary'):
        write_host_vulnerabilities(f, host_data)
    
    f.write("\n")


def write_host_vulnerabilities(f, host_data: Dict):
    """Write vulnerability information for a host"""
    vuln_summary = host_data.get('vulnerability_summary', {})
    
    f.write("#### Vulnerability Assessment\n\n")
    
    severity = vuln_summary.get('by_severity', {})
    total = vuln_summary.get('total_cves', 0)
    
    f.write(f"**Total CVEs Found:** {total}\n\n")
    
    if severity.get('CRITICAL', 0) > 0:
        f.write(f"- 🔴 **CRITICAL:** {severity['CRITICAL']}\n")
    if severity.get('HIGH', 0) > 0:
        f.write(f"- 🟠 **HIGH:** {severity['HIGH']}\n")
    if severity.get('MEDIUM', 0) > 0:
        f.write(f"- 🟡 **MEDIUM:** {severity['MEDIUM']}\n")
    if severity.get('LOW', 0) > 0:
        f.write(f"- 🟢 **LOW:** {severity['LOW']}\n")
    
    f.write(f"\n**Risk Score:** {vuln_summary.get('risk_score', 0)}\n\n")
    
    # Show top CVEs
    services = host_data.get('services', {})
    all_cves = []
    
    for service in services.values():
        if 'cves' in service:
            all_cves.extend(service['cves'])
    
    # Sort by severity and CVSS score
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    all_cves.sort(key=lambda x: (severity_order.get(x.get('severity', 'UNKNOWN'), 4), 
                                  -x.get('cvss_score', 0)))
    
    if all_cves:
        f.write("**Top Vulnerabilities:**\n\n")
        f.write("| CVE ID | Severity | CVSS | Description |\n")
        f.write("|--------|----------|------|-------------|\n")
        
        for cve in all_cves[:10]:  # Top 10
            cve_id = cve.get('cve_id', 'N/A')
            sev = cve.get('severity', 'UNKNOWN')
            cvss = cve.get('cvss_score', 0.0)
            desc = cve.get('description', '')[:80] + '...'
            
            f.write(f"| [{cve_id}]({cve.get('nvd_url', '#')}) | {sev} | {cvss} | {desc} |\n")
        
        f.write("\n")


def write_domain_intelligence(f, inventory: Dict):
    """Write domain intelligence section"""
    f.write("## Domain Intelligence (OSINT)\n\n")
    
    domains = inventory.get('domains', {})
    
    if not domains:
        f.write("*No domain OSINT data collected.*\n\n")
        return
    
    for domain, data in sorted(domains.items()):
        f.write(f"### Domain: {domain}\n\n")
        
        # Statistics
        f.write("#### Statistics\n\n")
        f.write(f"- **Email Addresses Found:** {len(data.get('emails', []))}\n")
        f.write(f"- **Subdomains Discovered:** {len(data.get('subdomains', []))}\n")
        f.write(f"- **Total Hosts:** {len(data.get('hosts', []))}\n")
        f.write(f"- **IP Addresses:** {len(data.get('ips', []))}\n\n")
        
        # Subdomains
        if data.get('subdomains'):
            f.write("#### Subdomains\n\n")
            subdomains = data['subdomains'][:20]  # Limit to 20
            for subdomain in subdomains:
                f.write(f"- `{subdomain}`\n")
            
            if len(data['subdomains']) > 20:
                f.write(f"\n*... and {len(data['subdomains']) - 20} more*\n")
            f.write("\n")
        
        # Email addresses (redacted for report)
        if data.get('emails'):
            f.write("#### Email Addresses\n\n")
            f.write(f"*{len(data['emails'])} email addresses identified (see full inventory for details)*\n\n")
        
        # IP addresses
        if data.get('ips'):
            f.write("#### Associated IP Addresses\n\n")
            for ip_addr in data['ips'][:10]:
                f.write(f"- `{ip_addr}`\n")
            
            if len(data['ips']) > 10:
                f.write(f"\n*... and {len(data['ips']) - 10} more*\n")
            f.write("\n")
        
        f.write("\n")
    
    f.write("---\n\n")


def write_vulnerability_assessment(f, inventory: Dict):
    """Write vulnerability assessment section"""
    f.write("## Vulnerability Assessment\n\n")
    
    meta = inventory['metadata']
    
    f.write(f"**Services Checked:** {meta.get('services_checked', 0)}\n\n")
    f.write(f"**Total CVEs Found:** {meta.get('total_cves_found', 0)}\n\n")
    
    # Aggregate severity counts
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    
    for host in inventory['hosts'].values():
        vuln_summary = host.get('vulnerability_summary', {})
        severity = vuln_summary.get('by_severity', {})
        total_critical += severity.get('CRITICAL', 0)
        total_high += severity.get('HIGH', 0)
        total_medium += severity.get('MEDIUM', 0)
        total_low += severity.get('LOW', 0)
    
    f.write("### Vulnerability Distribution\n\n")
    f.write("| Severity | Count |\n")
    f.write("|----------|-------|\n")
    f.write(f"| 🔴 CRITICAL | {total_critical} |\n")
    f.write(f"| 🟠 HIGH | {total_high} |\n")
    f.write(f"| 🟡 MEDIUM | {total_medium} |\n")
    f.write(f"| 🟢 LOW | {total_low} |\n\n")
    
    # Top vulnerable hosts
    f.write("### Most Vulnerable Hosts\n\n")
    
    hosts_by_risk = sorted(
        [(ip, host) for ip, host in inventory['hosts'].items() 
         if host.get('vulnerability_summary')],
        key=lambda x: x[1].get('vulnerability_summary', {}).get('risk_score', 0),
        reverse=True
    )
    
    if hosts_by_risk:
        f.write("| IP Address | Hostname | Risk Score | Critical | High | Medium | Low |\n")
        f.write("|------------|----------|------------|----------|------|--------|-----|\n")
        
        for ip, host in hosts_by_risk[:10]:
            hostname = host.get('hostname', 'N/A')
            vuln = host.get('vulnerability_summary', {})
            sev = vuln.get('by_severity', {})
            
            f.write(f"| {ip} | {hostname} | {vuln.get('risk_score', 0)} | ")
            f.write(f"{sev.get('CRITICAL', 0)} | {sev.get('HIGH', 0)} | ")
            f.write(f"{sev.get('MEDIUM', 0)} | {sev.get('LOW', 0)} |\n")
        
        f.write("\n")
    
    f.write("*See full vulnerability report (vulnerability_report.txt) for complete details.*\n\n")
    f.write("---\n\n")


def write_web_services_analysis(f, inventory: Dict, output_path: Path):
    """Write web services analysis section with screenshots"""
    f.write("## Web Services Analysis\n\n")
    
    meta = inventory['metadata']
    f.write(f"**Web Services Analyzed:** {meta.get('screenshots_captured', 0)}\n\n")
    
    # Collect all web services
    web_services = []
    
    for ip, host_data in inventory['hosts'].items():
        hostname = host_data.get('hostname') or ip
        
        for port_key, service in host_data.get('services', {}).items():
            if 'eyewitness' in service:
                web_services.append({
                    'ip': ip,
                    'hostname': hostname,
                    'port': service.get('port'),
                    'service': service.get('service'),
                    'eyewitness': service['eyewitness']
                })
    
    if not web_services:
        f.write("*No web services found or screenshots unavailable.*\n\n")
        return
    
    # Sort by IP and port
    web_services.sort(key=lambda x: (x['ip'], x['port']))
    
    for ws in web_services:
        url = ws['eyewitness'].get('url', f"http://{ws['hostname']}:{ws['port']}")
        
        f.write(f"### {url}\n\n")
        
        # Service information
        f.write("#### Service Details\n\n")
        f.write(f"- **IP Address:** `{ws['ip']}`\n")
        f.write(f"- **Port:** {ws['port']}\n")
        f.write(f"- **Service:** {ws['service']}\n")
        
        ew_data = ws['eyewitness']
        
        if ew_data.get('response_code'):
            f.write(f"- **Response Code:** {ew_data['response_code']}\n")
        
        if ew_data.get('page_title'):
            f.write(f"- **Page Title:** {ew_data['page_title']}\n")
        
        if ew_data.get('server_header'):
            f.write(f"- **Server Header:** `{ew_data['server_header']}`\n")
        
        if ew_data.get('content_length'):
            f.write(f"- **Content Length:** {ew_data['content_length']} bytes\n")
        
        f.write("\n")
        
        # Screenshot
        screenshot = ew_data.get('screenshot')
        if screenshot:
            # Make screenshot path relative to report location
            screenshot_path = Path(screenshot)
            if screenshot_path.exists():
                # Copy screenshot to report directory for easier distribution
                rel_path = screenshot_path.relative_to(output_path.parent) if output_path.parent in screenshot_path.parents else screenshot_path
                f.write("#### Screenshot\n\n")
                f.write(f"![{url}]({rel_path})\n\n")
            else:
                f.write(f"*Screenshot not found: {screenshot}*\n\n")
        
        # Analysis
        f.write("#### Analysis\n\n")
        
        if ew_data.get('error'):
            f.write(f"⚠️ **Error:** {ew_data['error']}\n\n")
        else:
            # Basic analysis based on response
            response = ew_data.get('response_code')
            if response:
                if response == 200:
                    f.write("✅ Service is accessible and responding normally.\n\n")
                elif response == 401:
                    f.write("🔒 Service requires authentication.\n\n")
                elif response == 403:
                    f.write("🚫 Access forbidden - potential security restriction.\n\n")
                elif response >= 500:
                    f.write("⚠️ Server error detected - service may be misconfigured.\n\n")
        
        f.write("---\n\n")
    
    f.write("\n")


def write_statistics(f, inventory: Dict):
    """Write statistics section"""
    f.write("## Summary Statistics\n\n")
    
    summary = inventory.get('summary', {})
    
    # Top services
    top_services = summary.get('top_services', {})
    if top_services:
        f.write("### Most Common Services\n\n")
        f.write("| Service | Count |\n")
        f.write("|---------|-------|\n")
        
        for service, count in list(top_services.items())[:10]:
            f.write(f"| {service} | {count} |\n")
        
        f.write("\n")
    
    # Top ports
    top_ports = summary.get('top_ports', {})
    if top_ports:
        f.write("### Most Common Ports\n\n")
        f.write("| Port | Count |\n")
        f.write("|------|-------|\n")
        
        for port, count in list(top_ports.items())[:10]:
            f.write(f"| {port} | {count} |\n")
        
        f.write("\n")
    
    # OS distribution
    os_dist = summary.get('os_distribution', {})
    if os_dist:
        f.write("### Operating System Distribution\n\n")
        f.write("| Operating System | Count |\n")
        f.write("|------------------|-------|\n")
        
        for os_name, count in os_dist.items():
            f.write(f"| {os_name} | {count} |\n")
        
        f.write("\n")
    
    f.write("---\n\n")


def write_recommendations(f, inventory: Dict):
    """Write recommendations section"""
    f.write("## Recommendations\n\n")
    
    meta = inventory['metadata']
    
    f.write("### Priority Actions\n\n")
    
    # Vulnerability-based recommendations
    if meta.get('cve_lookup_enabled'):
        has_critical = any(
            host.get('vulnerability_summary', {}).get('has_critical', False)
            for host in inventory['hosts'].values()
        )
        has_high = any(
            host.get('vulnerability_summary', {}).get('has_high', False)
            for host in inventory['hosts'].values()
        )
        
        if has_critical:
            f.write("1. **URGENT:** Patch all services with CRITICAL severity vulnerabilities immediately\n")
        if has_high:
            f.write("2. **HIGH PRIORITY:** Address HIGH severity vulnerabilities within 30 days\n")
        f.write("3. Review and update all software to latest stable versions\n")
    
    # Service exposure recommendations
    total_services = meta.get('total_services', 0)
    if total_services > 50:
        f.write("4. Reduce attack surface by closing unnecessary services\n")
    
    # OSINT-based recommendations
    if meta.get('total_emails', 0) > 20:
        f.write("5. Review exposed email addresses for potential phishing risks\n")
    
    f.write("\n### General Security Measures\n\n")
    f.write("- Implement network segmentation to isolate critical systems\n")
    f.write("- Deploy intrusion detection/prevention systems (IDS/IPS)\n")
    f.write("- Enable logging and monitoring for all exposed services\n")
    f.write("- Conduct regular security assessments and penetration testing\n")
    f.write("- Implement strong authentication mechanisms (MFA where possible)\n")
    f.write("- Review and harden all web application configurations\n")
    f.write("- Establish an incident response plan\n")
    f.write("- Provide security awareness training for staff\n\n")
    
    f.write("---\n\n")


def write_appendices(f, inventory: Dict, output_path: Path):
    """Write appendices section"""
    f.write("## Appendices\n\n")
    
    f.write("### A. Additional Reports\n\n")
    f.write("The following additional files are available in the output directory:\n\n")
    
    files = [
        ("inventory.json", "Complete structured inventory in JSON format"),
        ("inventory.csv", "Tabular inventory suitable for spreadsheet analysis"),
        ("summary_report.txt", "Text-based summary report"),
    ]
    
    if inventory['metadata'].get('cve_lookup_enabled'):
        files.append(("vulnerability_report.txt", "Detailed vulnerability assessment"))
    
    if inventory['metadata'].get('eyewitness_enabled'):
        files.append(("eyewitness/report/", "EyeWitness HTML report with all screenshots"))
    
    f.write("| Filename | Description |\n")
    f.write("|----------|-------------|\n")
    
    for filename, description in files:
        f.write(f"| `{filename}` | {description} |\n")
    
    f.write("\n")
    
    # Raw scan data
    f.write("### B. Raw Scan Data\n\n")
    f.write("Raw output from individual tools is available in:\n\n")
    f.write("- `nmap/` - Nmap XML and text outputs\n")
    f.write("- `harvester/` - theHarvester JSON and text outputs\n")
    
    if (output_path / 'masscan.json').exists():
        f.write("- `masscan.json` - Masscan JSON output\n")
    
    f.write("\n")
    
    # Scan metadata
    f.write("### C. Scan Metadata\n\n")
    f.write("```json\n")
    
    import json
    f.write(json.dumps(inventory['metadata'], indent=2))
    f.write("\n```\n\n")
    
    f.write("---\n\n")
    f.write("**End of Report**\n")
