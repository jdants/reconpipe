#!/usr/bin/env python3
"""
Test full aggregation with all three tools
"""

import sys
from pathlib import Path
import json

sys.path.insert(0, '.')

from tools.masscan_wrapper import parse_masscan_output
from tools.nmap_wrapper import parse_nmap_xml_multi
from tools.harvester_wrapper import run_harvester
from tools.aggregate import aggregate_results

def test_full(output_dir='out'):
    """Test complete aggregation flow"""
    
    print("=" * 60)
    print("FULL AGGREGATION TEST")
    print("=" * 60)
    print()
    
    output_path = Path(output_dir)
    
    # 1. Parse Masscan
    print("1. Masscan Results:")
    masscan_file = output_path / 'masscan.json'
    if masscan_file.exists():
        masscan_data = parse_masscan_output(str(masscan_file))
        print(f"   ✓ {len(masscan_data)} results")
    else:
        masscan_data = []
        print(f"   ⚠ No masscan.json")
    print()
    
    # 2. Parse Nmap
    print("2. Nmap Results:")
    nmap_dir = output_path / 'nmap'
    nmap_data = []
    if nmap_dir.exists():
        for xml_file in nmap_dir.glob('*.xml'):
            results = parse_nmap_xml_multi(str(xml_file))
            nmap_data.extend(results)
            print(f"   {xml_file.name}: {len(results)} hosts")
        print(f"   ✓ Total: {len(nmap_data)} hosts")
    else:
        print(f"   ⚠ No nmap directory")
    print()
    
    # 3. Parse theHarvester
    print("3. theHarvester Results:")
    harvester_dir = output_path / 'harvester'
    harvester_data = []
    
    if harvester_dir.exists():
        # Find domains from raw files
        raw_files = list(harvester_dir.glob('harvester_*_raw.txt'))
        print(f"   Found {len(raw_files)} raw output files")
        
        for raw_file in raw_files:
            # Extract domain from filename
            # harvester_hackthissite_org_raw.txt -> hackthissite.org
            domain_part = raw_file.stem.replace('harvester_', '').replace('_raw', '')
            domain = domain_part.replace('_', '.')
            
            print(f"   Processing: {domain}")
            
            # Read raw output
            with open(raw_file) as f:
                stdout = f.read()
            
            # Parse
            from tools.harvester_wrapper import parse_harvester_output
            base_file = str(harvester_dir / f"harvester_{domain_part}")
            result = parse_harvester_output(domain, stdout, base_file)
            
            if result:
                harvester_data.append(result)
                print(f"     Emails: {len(result.get('emails', []))}")
                print(f"     Hosts: {len(result.get('hosts', []))}")
                print(f"     IPs: {len(result.get('ips', []))}")
        
        print(f"   ✓ Total: {len(harvester_data)} domains")
    else:
        print(f"   ⚠ No harvester directory")
    print()
    
    # 4. Show what we're passing to aggregation
    print("4. Data Summary Before Aggregation:")
    print(f"   masscan_data: {len(masscan_data)} items")
    print(f"   nmap_data: {len(nmap_data)} items")
    print(f"   harvester_data: {len(harvester_data)} items")
    
    if harvester_data:
        print(f"   Harvester domains: {[d['domain'] for d in harvester_data]}")
    
    print()
    
    # 5. Run aggregation
    print("5. Running Aggregation...")
    try:
        inventory = aggregate_results(
            masscan_data=masscan_data,
            nmap_data=nmap_data,
            harvester_data=harvester_data,
            output_dir=output_dir
        )
        
        print()
        print("6. Aggregation Results:")
        print(f"   Hosts: {len(inventory.get('hosts', {}))}")
        print(f"   Domains: {len(inventory.get('domains', {}))}")
        
        meta = inventory.get('metadata', {})
        print(f"   Tools used: {meta.get('tools_used', [])}")
        
        # Verify domains
        if inventory.get('domains'):
            print()
            print("   Domains in inventory:")
            for domain, data in inventory['domains'].items():
                print(f"     - {domain}: {len(data.get('emails', []))} emails, {len(data.get('hosts', []))} hosts")
        else:
            print()
            print("   ❌ NO DOMAINS IN INVENTORY!")
            print("   But harvester_data had domains before aggregation!")
            print("   This means process_harvester_data() is failing!")
        
        # Verify hosts
        if inventory.get('hosts'):
            print()
            print(f"   Hosts in inventory: {list(inventory['hosts'].keys())[:5]}")
        
    except Exception as e:
        print(f"   ❌ Aggregation failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 60)


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'out'
    test_full(output_dir)
