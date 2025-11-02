#!/usr/bin/env python3
"""
Test aggregation with actual output files
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, '.')

from tools.masscan_wrapper import parse_masscan_output
from tools.nmap_wrapper import parse_nmap_xml
from tools.aggregate import aggregate_results

def test_aggregation(output_dir='out'):
    """Test aggregation with existing output files"""
    
    print("=" * 60)
    print("TESTING AGGREGATION")
    print("=" * 60)
    print()
    
    output_path = Path(output_dir)
    
    # Parse Masscan output
    print("1. Parsing Masscan output...")
    masscan_file = output_path / 'masscan.json'
    if masscan_file.exists():
        masscan_data = parse_masscan_output(str(masscan_file))
        print(f"   Parsed {len(masscan_data)} Masscan results")
        if masscan_data:
            print(f"   Sample: {masscan_data[0]}")
    else:
        masscan_data = []
        print(f"   No masscan.json found")
    print()
    
    # Parse Nmap outputs
    print("2. Parsing Nmap outputs...")
    nmap_dir = output_path / 'nmap'
    nmap_data = []
    if nmap_dir.exists():
        for xml_file in nmap_dir.glob('*.xml'):
            print(f"   Parsing {xml_file.name}...")
            
            # Use multi-host parser for CIDR scans
            from tools.nmap_wrapper import parse_nmap_xml_multi
            results = parse_nmap_xml_multi(str(xml_file))
            
            if results:
                for result in results:
                    nmap_data.append(result)
                    print(f"     ✓ IP: {result.get('ip')}, Ports: {len(result.get('ports', []))}")
            else:
                print(f"     ✗ No data")
        print(f"   Total: {len(nmap_data)} Nmap results")
    else:
        print(f"   No nmap directory found")
    print()
    
    # Harvester (usually empty for IP-only scans)
    harvester_data = []
    
    # Run aggregation
    print("3. Running aggregation...")
    print(f"   masscan_data: {len(masscan_data)} items")
    print(f"   nmap_data: {len(nmap_data)} items")
    print(f"   harvester_data: {len(harvester_data)} items")
    print()
    
    try:
        inventory = aggregate_results(
            masscan_data=masscan_data,
            nmap_data=nmap_data,
            harvester_data=harvester_data,
            output_dir=output_dir
        )
        
        print()
        print("4. Aggregation Results:")
        print(f"   Hosts in inventory: {len(inventory.get('hosts', {}))}")
        print(f"   Domains in inventory: {len(inventory.get('domains', {}))}")
        
        if inventory.get('hosts'):
            print()
            print("   Host IPs:")
            for ip in list(inventory['hosts'].keys())[:5]:
                host = inventory['hosts'][ip]
                services = len(host.get('services', {}))
                print(f"     - {ip}: {services} services")
        else:
            print()
            print("   ❌ NO HOSTS IN INVENTORY!")
            print()
            print("   This means the data isn't being processed correctly.")
            print("   Check the logs above for parsing errors.")
        
    except Exception as e:
        print(f"   ❌ Aggregation failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 60)


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'out'
    test_aggregation(output_dir)
