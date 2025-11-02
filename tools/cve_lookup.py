"""
CVE Lookup Module - Maps service versions to known vulnerabilities
Uses NVD (National Vulnerability Database) API
"""

import json
import logging
import time
import requests
from typing import List, Dict, Optional
from urllib.parse import quote
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# NVD API Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_RATE_LIMIT = 0.6  # Seconds between requests (without API key: 5 req/30sec)
NVD_API_KEY = None  # Set via environment variable or parameter

# Cache to avoid duplicate API calls
CVE_CACHE = {}


def set_nvd_api_key(api_key: str):
    """Set NVD API key for higher rate limits"""
    global NVD_API_KEY
    NVD_API_KEY = api_key
    logger.info("NVD API key configured (50 requests/30 seconds)")


def lookup_cves_for_inventory(inventory: Dict, max_age_days: int = 365) -> Dict:
    """
    Lookup CVEs for all services in the inventory
    
    Args:
        inventory: The inventory dictionary from aggregate_results
        max_age_days: Only include CVEs from the last N days (default: 1 year)
    
    Returns:
        Updated inventory with CVE information
    """
    logger.info("Starting CVE lookup for discovered services...")
    logger.info(f"Filter: CVEs published in last {max_age_days} days")
    
    total_services = 0
    total_cves = 0
    
    # Calculate date threshold
    date_threshold = datetime.now() - timedelta(days=max_age_days)
    
    # Process each host
    for ip, host_data in inventory['hosts'].items():
        services = host_data.get('services', {})
        
        if not services:
            continue
        
        logger.info(f"Checking {ip} ({len(services)} services)...")
        
        for port_key, service_info in services.items():
            product = service_info.get('product')
            version = service_info.get('version')
            service_name = service_info.get('service')
            
            # Skip if we don't have product and version
            if not product or not version:
                logger.debug(f"  Skipping {port_key}: Missing product/version")
                continue
            
            total_services += 1
            
            # Build search query
            search_key = f"{product} {version}".lower()
            
            # Check cache first
            if search_key in CVE_CACHE:
                cves = CVE_CACHE[search_key]
                logger.debug(f"  {port_key}: {product} {version} (cached)")
            else:
                # Query NVD API
                logger.info(f"  Querying: {product} {version}")
                cves = query_nvd_api(product, version, date_threshold)
                CVE_CACHE[search_key] = cves
                
                # Rate limiting
                time.sleep(NVD_API_RATE_LIMIT)
            
            if cves:
                service_info['cves'] = cves
                service_info['cve_count'] = len(cves)
                total_cves += len(cves)
                
                # Log critical/high severity CVEs
                critical = [c for c in cves if c.get('severity') == 'CRITICAL']
                high = [c for c in cves if c.get('severity') == 'HIGH']
                
                if critical or high:
                    logger.warning(f"  ⚠️  {port_key}: {product} {version}")
                    if critical:
                        logger.warning(f"      {len(critical)} CRITICAL CVEs")
                    if high:
                        logger.warning(f"      {len(high)} HIGH CVEs")
                else:
                    logger.info(f"  ✓ {port_key}: {len(cves)} CVEs found")
            else:
                logger.debug(f"  ✓ {port_key}: No CVEs found")
        
        # Add host-level vulnerability summary
        host_cves = []
        for service_info in services.values():
            if 'cves' in service_info:
                host_cves.extend(service_info['cves'])
        
        if host_cves:
            host_data['vulnerabilities'] = deduplicate_cves(host_cves)
            host_data['vulnerability_summary'] = generate_vulnerability_summary(host_cves)
    
    # Update inventory metadata
    inventory['metadata']['cve_lookup_enabled'] = True
    inventory['metadata']['cve_lookup_date'] = datetime.now().isoformat()
    inventory['metadata']['total_cves_found'] = total_cves
    inventory['metadata']['services_checked'] = total_services
    
    logger.info(f"\n✓ CVE Lookup Complete:")
    logger.info(f"  Services checked: {total_services}")
    logger.info(f"  Total CVEs found: {total_cves}")
    
    return inventory


def query_nvd_api(product: str, version: str, 
                  date_threshold: Optional[datetime] = None) -> List[Dict]:
    """
    Query NVD API for CVEs related to a product and version
    
    Args:
        product: Product name (e.g., "nginx", "openssh")
        version: Version string (e.g., "1.18.0", "7.4")
        date_threshold: Only return CVEs published after this date
    
    Returns:
        List of CVE dictionaries
    """
    cves = []
    
    try:
        # Build keyword search query
        # Format: "product version"
        keyword = f"{product} {version}"
        
        # Build request parameters
        params = {
            'keywordSearch': keyword,
            'keywordExactMatch': False,
            'resultsPerPage': 50  # Max allowed
        }
        
        # Add date filter if provided
        if date_threshold:
            params['pubStartDate'] = date_threshold.strftime('%Y-%m-%dT%H:%M:%S.000')
            params['pubEndDate'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        
        # Add API key if available
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        
        # Make request
        response = requests.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Parse vulnerabilities
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln_item in vulnerabilities:
                cve_data = vuln_item.get('cve', {})
                
                cve_id = cve_data.get('id')
                
                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = next(
                    (d.get('value') for d in descriptions if d.get('lang') == 'en'),
                    'No description available'
                )
                
                # Get CVSS scores
                metrics = cve_data.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
                cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if metrics.get('cvssMetricV2') else {}
                
                # Prefer CVSS v3
                if cvss_v3:
                    cvss_data = cvss_v3.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    vector_string = cvss_data.get('vectorString', '')
                elif cvss_v2:
                    cvss_data = cvss_v2.get('cvssData', {})
                    base_score = cvss_data.get('baseScore', 0.0)
                    # Map CVSS v2 score to severity
                    if base_score >= 7.0:
                        severity = 'HIGH'
                    elif base_score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                    vector_string = cvss_data.get('vectorString', '')
                else:
                    base_score = 0.0
                    severity = 'UNKNOWN'
                    vector_string = ''
                
                # Get published date
                published = cve_data.get('published', '')
                
                # Get references
                references = []
                for ref in cve_data.get('references', [])[:3]:  # Limit to 3
                    references.append({
                        'url': ref.get('url'),
                        'source': ref.get('source')
                    })
                
                cve_entry = {
                    'cve_id': cve_id,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'severity': severity,
                    'cvss_score': base_score,
                    'cvss_vector': vector_string,
                    'published': published,
                    'references': references,
                    'nvd_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
                
                cves.append(cve_entry)
            
            logger.debug(f"  Found {len(cves)} CVEs for {product} {version}")
            
        elif response.status_code == 403:
            logger.error("NVD API access forbidden. Check API key or rate limits.")
        elif response.status_code == 404:
            logger.debug(f"No CVEs found for {product} {version}")
        else:
            logger.warning(f"NVD API returned status code: {response.status_code}")
    
    except requests.exceptions.Timeout:
        logger.error("NVD API request timed out")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying NVD API: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during CVE lookup: {e}")
    
    return cves


def deduplicate_cves(cves: List[Dict]) -> List[Dict]:
    """Remove duplicate CVEs based on CVE ID"""
    seen = set()
    unique = []
    
    for cve in cves:
        cve_id = cve.get('cve_id')
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve)
    
    return unique


def generate_vulnerability_summary(cves: List[Dict]) -> Dict:
    """Generate summary statistics for CVEs"""
    
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0
    }
    
    for cve in cves:
        severity = cve.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Calculate risk score (weighted by severity)
    risk_score = (
        severity_counts['CRITICAL'] * 10 +
        severity_counts['HIGH'] * 5 +
        severity_counts['MEDIUM'] * 2 +
        severity_counts['LOW'] * 1
    )
    
    return {
        'total_cves': len(cves),
        'by_severity': severity_counts,
        'risk_score': risk_score,
        'has_critical': severity_counts['CRITICAL'] > 0,
        'has_high': severity_counts['HIGH'] > 0
    }


def export_vulnerability_report(inventory: Dict, output_file: str):
    """
    Export a detailed vulnerability report
    
    Args:
        inventory: Inventory with CVE data
        output_file: Path to output file
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("VULNERABILITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            meta = inventory['metadata']
            f.write(f"Scan Date: {meta.get('scan_date', 'N/A')}\n")
            f.write(f"CVE Lookup Date: {meta.get('cve_lookup_date', 'N/A')}\n")
            f.write(f"Services Checked: {meta.get('services_checked', 0)}\n")
            f.write(f"Total CVEs Found: {meta.get('total_cves_found', 0)}\n\n")
            
            # Sort hosts by risk score
            hosts_with_vulns = []
            for ip, host in inventory['hosts'].items():
                vuln_summary = host.get('vulnerability_summary', {})
                if vuln_summary:
                    hosts_with_vulns.append((ip, host, vuln_summary))
            
            hosts_with_vulns.sort(
                key=lambda x: x[2].get('risk_score', 0),
                reverse=True
            )
            
            f.write("=" * 80 + "\n")
            f.write("HOSTS WITH VULNERABILITIES (Sorted by Risk)\n")
            f.write("=" * 80 + "\n\n")
            
            for ip, host, vuln_summary in hosts_with_vulns:
                f.write(f"Host: {ip}\n")
                if host.get('hostname'):
                    f.write(f"  Hostname: {host['hostname']}\n")
                
                f.write(f"  Risk Score: {vuln_summary['risk_score']}\n")
                f.write(f"  Total CVEs: {vuln_summary['total_cves']}\n")
                
                severity = vuln_summary['by_severity']
                if severity['CRITICAL'] > 0:
                    f.write(f"  🔴 CRITICAL: {severity['CRITICAL']}\n")
                if severity['HIGH'] > 0:
                    f.write(f"  🟠 HIGH: {severity['HIGH']}\n")
                if severity['MEDIUM'] > 0:
                    f.write(f"  🟡 MEDIUM: {severity['MEDIUM']}\n")
                if severity['LOW'] > 0:
                    f.write(f"  🟢 LOW: {severity['LOW']}\n")
                
                f.write("\n  Vulnerable Services:\n")
                
                for port_key, service in host.get('services', {}).items():
                    if 'cves' in service and service['cves']:
                        product = service.get('product', 'unknown')
                        version = service.get('version', 'unknown')
                        cve_count = len(service['cves'])
                        
                        f.write(f"    {port_key:<12} {product} {version} ({cve_count} CVEs)\n")
                        
                        # List CVEs
                        for cve in service['cves'][:5]:  # Limit to 5 per service
                            cve_id = cve.get('cve_id')
                            severity = cve.get('severity')
                            score = cve.get('cvss_score', 0.0)
                            f.write(f"      - {cve_id:<20} {severity:<10} (CVSS: {score})\n")
                            desc = cve.get('description', '')[:100]
                            f.write(f"        {desc}...\n")
                            f.write(f"        {cve.get('nvd_url')}\n")
                        
                        if len(service['cves']) > 5:
                            f.write(f"      ... and {len(service['cves']) - 5} more CVEs\n")
                
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")
            f.write("1. Prioritize patching services with CRITICAL severity CVEs\n")
            f.write("2. Review HIGH severity CVEs and assess exploitability\n")
            f.write("3. Update all services to latest stable versions\n")
            f.write("4. Implement network segmentation for high-risk hosts\n")
            f.write("5. Enable security monitoring and alerting\n\n")
            
            f.write("=" * 80 + "\n")
        
        logger.info(f"✓ Vulnerability report saved: {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to export vulnerability report: {e}")


def get_nvd_api_info():
    """Display information about NVD API usage"""
    info = """
NVD API Information:
- Public API (no key): 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds
- Get free API key: https://nvd.nist.gov/developers/request-an-api-key

To use API key:
1. Set environment variable: export NVD_API_KEY=your-key-here
2. Or pass to script: --nvd-api-key your-key-here
    """
    return info
