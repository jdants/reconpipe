"""
Aggregation Module - Combines all reconnaissance data into unified inventory
"""

import json
import csv
import logging
from typing import List, Dict
from datetime import datetime
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)


def aggregate_results(masscan_data: List[Dict], nmap_data: List[Dict], 
                     harvester_data: List[Dict], output_dir: str) -> Dict:
    """
    Aggregate all reconnaissance results into unified inventory
    
    Args:
        masscan_data: Masscan results
        nmap_data: Nmap results
        harvester_data: theHarvester results
        output_dir: Directory to save inventory files
    
    Returns:
        Complete inventory dictionary
    """
    
    logger.info("Aggregating reconnaissance data...")
    
    # Build unified inventory structure
    inventory = {
        'metadata': {
            'scan_date': datetime.now().isoformat(),
            'scan_timestamp': int(datetime.now().timestamp()),
            'total_hosts': 0,
            'total_ports': 0,
            'total_services': 0,
            'total_domains': len(harvester_data),
            'total_emails': 0,
            'tools_used': []
        },
        'hosts': {},
        'domains': {},
        'summary': {
            'top_services': {},
            'top_ports': {},
            'os_distribution': {}
        }
    }
    
    # Track which tools were used
    if masscan_data:  # Empty list is falsy, but we should check length
        inventory['metadata']['tools_used'].append('masscan')
    if nmap_data:
        inventory['metadata']['tools_used'].append('nmap')
    if harvester_data:
        inventory['metadata']['tools_used'].append('theHarvester')
    
    # Process Masscan data (even if empty, try processing)
    if masscan_data:
        logger.info("Processing Masscan results...")
        process_masscan_data(inventory, masscan_data)
    else:
        logger.debug("No Masscan data to process")
    
    # Process Nmap data (even if empty, try processing)
    if nmap_data:
        logger.info("Processing Nmap results...")
        process_nmap_data(inventory, nmap_data)
    else:
        logger.debug("No Nmap data to process")
    
    # Process theHarvester data (even if empty, try processing)
    if harvester_data:
        logger.info("Processing theHarvester results...")
        process_harvester_data(inventory, harvester_data)
    else:
        logger.debug("No theHarvester data to process")
    
    # Generate summary statistics
    logger.info("Generating summary statistics...")
    generate_summary_stats(inventory)
    
    # Update metadata
    inventory['metadata']['total_hosts'] = len(inventory['hosts'])
    inventory['metadata']['total_ports'] = sum(
        len(h.get('ports_masscan', [])) + len(h.get('ports_nmap', []))
        for h in inventory['hosts'].values()
    )
    inventory['metadata']['total_services'] = sum(
        len(h.get('services', {}))
        for h in inventory['hosts'].values()
    )
    inventory['metadata']['total_emails'] = sum(
        len(d.get('emails', []))
        for d in inventory['domains'].values()
    )
    
    # Save outputs
    output_path = Path(output_dir)
    
    # Save JSON inventory
    json_output = output_path / 'inventory.json'
    save_json_inventory(inventory, json_output)
    
    # Save CSV inventory
    csv_output = output_path / 'inventory.csv'
    save_csv_inventory(inventory, csv_output)
    
    # Save summary report
    report_output = output_path / 'summary_report.txt'
    save_summary_report(inventory, report_output)
    
    # Print summary to console
    print_summary(inventory)
    
    return inventory


def process_masscan_data(inventory: Dict, masscan_data: List[Dict]):
    """Process and integrate Masscan results"""
    
    for entry in masscan_data:
        ip = entry['ip']
        
        if ip not in inventory['hosts']:
            inventory['hosts'][ip] = create_host_entry(ip)
        
        # Add port information
        port_entry = {
            'port': entry['port'],
            'protocol': entry['protocol'],
            'status': entry.get('status', 'open'),
            'discovered_at': entry.get('timestamp')
        }
        
        inventory['hosts'][ip]['ports_masscan'].append(port_entry)


def process_nmap_data(inventory: Dict, nmap_data: List[Dict]):
    """Process and integrate Nmap results"""
    
    for host_data in nmap_data:
        ip = host_data.get('ip')
        if not ip:
            continue
        
        if ip not in inventory['hosts']:
            inventory['hosts'][ip] = create_host_entry(ip)
        
        host = inventory['hosts'][ip]
        
        # Update host information
        host['hostname'] = host_data.get('hostname')
        host['status'] = host_data.get('status', 'unknown')
        host['os'] = host_data.get('os')
        host['os_accuracy'] = host_data.get('os_accuracy')
        host['mac_address'] = host_data.get('mac_address')
        host['vendor'] = host_data.get('vendor')
        host['uptime'] = host_data.get('uptime')
        
        # Process ports and services
        for port in host_data.get('ports', []):
            port_key = f"{port['port']}/{port['protocol']}"
            
            # Add to ports_nmap list
            port_entry = {
                'port': port['port'],
                'protocol': port['protocol'],
                'state': port.get('state', 'open'),
                'service': port.get('service', 'unknown')
            }
            host['ports_nmap'].append(port_entry)
            
            # Add detailed service information
            host['services'][port_key] = {
                'port': port['port'],
                'protocol': port['protocol'],
                'service': port.get('service', 'unknown'),
                'product': port.get('product'),
                'version': port.get('version'),
                'extrainfo': port.get('extrainfo'),
                'banner': port.get('banner'),
                'cpe': port.get('cpe')
            }
        
        # Store reference to XML file
        host['nmap_xml'] = host_data.get('xml_file')


def process_harvester_data(inventory: Dict, harvester_data: List[Dict]):
    """Process and integrate theHarvester results"""
    
    logger.info(f"Processing {len(harvester_data)} harvester results...")
    
    for domain_data in harvester_data:
        domain = domain_data.get('domain')
        
        if not domain:
            logger.warning("Harvester result missing 'domain' key!")
            continue
        
        logger.debug(f"Processing domain: {domain}")
        
        inventory['domains'][domain] = {
            'domain': domain,
            'emails': sorted(domain_data.get('emails', [])),
            'hosts': sorted(domain_data.get('hosts', [])),
            'subdomains': [],
            'ips': sorted(domain_data.get('ips', [])),
            'urls': domain_data.get('urls', []),
            'asns': domain_data.get('asns', []),
            'shodan_info': domain_data.get('shodan_info', [])
        }
        
        # Separate subdomains from hosts
        hosts = domain_data.get('hosts', [])
        subdomains = [h for h in hosts if h != domain and h.endswith(domain)]
        inventory['domains'][domain]['subdomains'] = sorted(list(set(subdomains)))
        
        logger.debug(f"  Added domain {domain} with {len(inventory['domains'][domain]['emails'])} emails")
    
    logger.info(f"Processed {len(inventory['domains'])} domains into inventory")


def generate_summary_stats(inventory: Dict):
    """Generate summary statistics from inventory data"""
    
    service_counts = defaultdict(int)
    port_counts = defaultdict(int)
    os_counts = defaultdict(int)
    
    # Analyze hosts
    for host in inventory['hosts'].values():
        # Count services
        for service_info in host.get('services', {}).values():
            service_name = service_info.get('service', 'unknown')
            service_counts[service_name] += 1
            
            # Count ports
            port = service_info.get('port')
            if port:
                port_counts[port] += 1
        
        # Count OS
        os_name = host.get('os')
        if os_name:
            os_counts[os_name] += 1
    
    # Sort and store top items
    inventory['summary']['top_services'] = dict(
        sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    
    inventory['summary']['top_ports'] = dict(
        sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    
    inventory['summary']['os_distribution'] = dict(
        sorted(os_counts.items(), key=lambda x: x[1], reverse=True)
    )


def create_host_entry(ip: str) -> Dict:
    """Create a new host entry with default structure"""
    return {
        'ip': ip,
        'hostname': None,
        'mac_address': None,
        'vendor': None,
        'status': 'unknown',
        'os': None,
        'os_accuracy': None,
        'uptime': None,
        'ports_masscan': [],
        'ports_nmap': [],
        'services': {},
        'nmap_xml': None,
        'vulnerabilities': [],
        'notes': []
    }


def save_json_inventory(inventory: Dict, output_file: Path):
    """Save inventory as JSON"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(inventory, f, indent=2, ensure_ascii=False)
        logger.info(f"✓ Saved JSON inventory: {output_file}")
    except Exception as e:
        logger.error(f"Failed to save JSON inventory: {e}")


def save_csv_inventory(inventory: Dict, output_file: Path):
    """Save inventory as CSV format"""
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'ip', 'hostname', 'mac_address', 'vendor', 'status', 'os', 
                'port', 'protocol', 'service', 'product', 'version', 
                'banner', 'source'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for ip, host_data in inventory['hosts'].items():
                base_row = {
                    'ip': ip,
                    'hostname': host_data.get('hostname', ''),
                    'mac_address': host_data.get('mac_address', ''),
                    'vendor': host_data.get('vendor', ''),
                    'status': host_data.get('status', 'unknown'),
                    'os': host_data.get('os', '')
                }
                
                rows_written = False
                
                # Write services from Nmap
                for port_key, service in host_data.get('services', {}).items():
                    row = base_row.copy()
                    row.update({
                        'port': service.get('port', ''),
                        'protocol': service.get('protocol', ''),
                        'service': service.get('service', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'banner': service.get('banner', ''),
                        'source': 'nmap'
                    })
                    writer.writerow(row)
                    rows_written = True
                
                # Write Masscan-only ports (not in Nmap results)
                nmap_ports = {f"{p['port']}/{p['protocol']}" 
                             for p in host_data.get('ports_nmap', [])}
                
                for port_info in host_data.get('ports_masscan', []):
                    port_key = f"{port_info['port']}/{port_info['protocol']}"
                    if port_key not in nmap_ports:
                        row = base_row.copy()
                        row.update({
                            'port': port_info['port'],
                            'protocol': port_info['protocol'],
                            'service': '',
                            'product': '',
                            'version': '',
                            'banner': '',
                            'source': 'masscan'
                        })
                        writer.writerow(row)
                        rows_written = True
                
                # If no ports found, write at least the host info
                if not rows_written:
                    row = base_row.copy()
                    row.update({
                        'port': '', 'protocol': '', 'service': '',
                        'product': '', 'version': '', 'banner': '', 'source': ''
                    })
                    writer.writerow(row)
        
        logger.info(f"✓ Saved CSV inventory: {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to save CSV inventory: {e}")


def save_summary_report(inventory: Dict, output_file: Path):
    """Save a human-readable summary report"""
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("RECONNAISSANCE SUMMARY REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            meta = inventory['metadata']
            f.write(f"Scan Date: {meta['scan_date']}\n")
            f.write(f"Tools Used: {', '.join(meta['tools_used'])}\n")
            f.write(f"Total Hosts: {meta['total_hosts']}\n")
            f.write(f"Total Ports: {meta['total_ports']}\n")
            f.write(f"Total Services: {meta['total_services']}\n")
            f.write(f"Total Domains: {meta['total_domains']}\n")
            f.write(f"Total Emails: {meta['total_emails']}\n\n")
            
            # Host details
            f.write("-" * 80 + "\n")
            f.write("HOST DETAILS\n")
            f.write("-" * 80 + "\n\n")
            
            for ip, host in sorted(inventory['hosts'].items()):
                f.write(f"Host: {ip}\n")
                if host.get('hostname'):
                    f.write(f"  Hostname: {host['hostname']}\n")
                if host.get('mac_address'):
                    f.write(f"  MAC: {host['mac_address']}")
                    if host.get('vendor'):
                        f.write(f" ({host['vendor']})")
                    f.write("\n")
                if host.get('os'):
                    f.write(f"  OS: {host['os']}")
                    if host.get('os_accuracy'):
                        f.write(f" (Accuracy: {host['os_accuracy']}%)")
                    f.write("\n")
                f.write(f"  Status: {host.get('status', 'unknown')}\n")
                
                if host.get('services'):
                    f.write("  Services:\n")
                    for port_key, service in sorted(host['services'].items()):
                        service_name = service.get('service', 'unknown')
                        banner = service.get('banner', '')
                        f.write(f"    {port_key:<12} {service_name:<15}")
                        if banner:
                            f.write(f" {banner}")
                        f.write("\n")
                
                f.write("\n")
            
            # Domain details
            if inventory['domains']:
                f.write("-" * 80 + "\n")
                f.write("DOMAIN INTELLIGENCE\n")
                f.write("-" * 80 + "\n\n")
                
                for domain, data in sorted(inventory['domains'].items()):
                    f.write(f"Domain: {domain}\n")
                    
                    if data.get('subdomains'):
                        f.write(f"  Subdomains ({len(data['subdomains'])}):\n")
                        for subdomain in data['subdomains'][:10]:
                            f.write(f"    - {subdomain}\n")
                        if len(data['subdomains']) > 10:
                            f.write(f"    ... and {len(data['subdomains']) - 10} more\n")
                    
                    if data.get('emails'):
                        f.write(f"  Emails ({len(data['emails'])}):\n")
                        for email in data['emails'][:10]:
                            f.write(f"    - {email}\n")
                        if len(data['emails']) > 10:
                            f.write(f"    ... and {len(data['emails']) - 10} more\n")
                    
                    if data.get('ips'):
                        f.write(f"  IP Addresses: {', '.join(data['ips'])}\n")
                    
                    f.write("\n")
            
            # Summary statistics
            f.write("-" * 80 + "\n")
            f.write("STATISTICS\n")
            f.write("-" * 80 + "\n\n")
            
            summary = inventory['summary']
            
            if summary.get('top_services'):
                f.write("Top Services:\n")
                for service, count in list(summary['top_services'].items())[:10]:
                    f.write(f"  {service:<20} {count:>5} instances\n")
                f.write("\n")
            
            if summary.get('top_ports'):
                f.write("Top Ports:\n")
                for port, count in list(summary['top_ports'].items())[:10]:
                    f.write(f"  {port:<20} {count:>5} instances\n")
                f.write("\n")
            
            if summary.get('os_distribution'):
                f.write("Operating Systems:\n")
                for os_name, count in summary['os_distribution'].items():
                    f.write(f"  {os_name:<50} {count:>3}\n")
            
            f.write("\n" + "=" * 80 + "\n")
        
        logger.info(f"✓ Saved summary report: {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to save summary report: {e}")


def print_summary(inventory: Dict):
    """Print a concise summary to console"""
    
    meta = inventory['metadata']
    summary = inventory['summary']
    
    print("\n" + "=" * 80)
    print("RECONNAISSANCE SUMMARY")
    print("=" * 80)
    
    print(f"\nScan Date: {meta['scan_date']}")
    print(f"Tools Used: {', '.join(meta['tools_used'])}")
    print(f"\nDiscovery Results:")
    print(f"  • Hosts Discovered: {meta['total_hosts']}")
    print(f"  • Open Ports: {meta['total_ports']}")
    print(f"  • Services Identified: {meta['total_services']}")
    print(f"  • Domains Analyzed: {meta['total_domains']}")
    print(f"  • Email Addresses: {meta['total_emails']}")
    
    if inventory['hosts']:
        print(f"\nTop 5 Hosts by Open Ports:")
        host_by_ports = sorted(
            inventory['hosts'].items(),
            key=lambda x: len(x[1].get('services', {})),
            reverse=True
        )[:5]
        
        for i, (ip, data) in enumerate(host_by_ports, 1):
            hostname = data.get('hostname') or 'N/A'  # Fix: handle None hostname
            port_count = len(data.get('services', {}))
            print(f"  {i}. {ip:<15} ({hostname:<30}) - {port_count:>3} services")
    
    if summary.get('top_services'):
        print(f"\nTop 5 Services:")
        for service, count in list(summary['top_services'].items())[:5]:
            print(f"  • {service:<20} {count:>3} instances")
    
    if inventory['domains']:
        print(f"\nDomain Intelligence:")
        for domain, data in list(inventory['domains'].items())[:3]:
            email_count = len(data.get('emails', []))
            subdomain_count = len(data.get('subdomains', []))
            print(f"  • {domain}: {subdomain_count} subdomains, {email_count} emails")
    
    print("\n" + "=" * 80)
    print("Files generated:")
    print("  • inventory.json - Complete structured data")
    print("  • inventory.csv - Spreadsheet format")
    print("  • summary_report.txt - Human-readable report")
    print("=" * 80 + "\n")
