#!/usr/bin/env python3
"""
Debug script to check why inventory.json is empty
"""

import json
import sys
from pathlib import Path

def check_outputs(output_dir='out'):
    """Check all output files and diagnose issues"""
    
    print("=" * 60)
    print("INVENTORY DEBUG SCRIPT")
    print("=" * 60)
    print()
    
    output_path = Path(output_dir)
    
    if not output_path.exists():
        print(f"❌ Output directory doesn't exist: {output_path}")
        return
    
    print(f"✓ Output directory exists: {output_path.absolute()}")
    print()
    
    # Check masscan.json
    print("1. Checking Masscan output...")
    masscan_file = output_path / 'masscan.json'
    if masscan_file.exists():
        print(f"  ✓ File exists: {masscan_file}")
        with open(masscan_file) as f:
            content = f.read()
            print(f"  File size: {len(content)} bytes")
            
            if content.strip():
                print(f"  First 200 chars: {content[:200]}")
                
                # Try to parse
                try:
                    # Masscan uses JSONL format
                    lines = [l.strip().rstrip(',') for l in content.strip().split('\n') 
                            if l.strip() and not l.startswith('#')]
                    print(f"  Found {len(lines)} JSON lines")
                    
                    results = []
                    for i, line in enumerate(lines, 1):
                        try:
                            obj = json.loads(line)
                            if 'ip' in obj and 'ports' in obj:
                                results.append(obj)
                                print(f"    Line {i}: IP={obj.get('ip')}, Ports={len(obj.get('ports', []))}")
                        except json.JSONDecodeError as e:
                            print(f"    Line {i}: Parse error: {e}")
                    
                    print(f"  ✓ Successfully parsed {len(results)} results")
                    
                except Exception as e:
                    print(f"  ❌ Error parsing: {e}")
            else:
                print(f"  ⚠ File is empty")
    else:
        print(f"  ❌ File doesn't exist: {masscan_file}")
    print()
    
    # Check Nmap outputs
    print("2. Checking Nmap outputs...")
    nmap_dir = output_path / 'nmap'
    if nmap_dir.exists():
        xml_files = list(nmap_dir.glob('*.xml'))
        print(f"  ✓ Found {len(xml_files)} XML files")
        
        for xml_file in xml_files[:3]:  # Show first 3
            print(f"    - {xml_file.name} ({xml_file.stat().st_size} bytes)")
            
            # Try to parse
            try:
                import xmltodict
                with open(xml_file) as f:
                    data = xmltodict.parse(f.read())
                
                host = data.get('nmaprun', {}).get('host', {})
                if isinstance(host, list):
                    print(f"      Multiple hosts: {len(host)}")
                elif host:
                    addr = host.get('address')
                    if isinstance(addr, list):
                        ip = next((a.get('@addr') for a in addr if a.get('@addrtype') == 'ipv4'), 'N/A')
                    else:
                        ip = addr.get('@addr') if addr else 'N/A'
                    
                    ports = host.get('ports', {}).get('port', [])
                    if not isinstance(ports, list):
                        ports = [ports] if ports else []
                    
                    print(f"      IP: {ip}, Ports: {len(ports)}")
                else:
                    print(f"      ⚠ No host data found")
                    
            except Exception as e:
                print(f"      ❌ Parse error: {e}")
        
        if len(xml_files) > 3:
            print(f"    ... and {len(xml_files) - 3} more")
    else:
        print(f"  ❌ Nmap directory doesn't exist: {nmap_dir}")
    print()
    
    # Check inventory.json
    print("3. Checking inventory.json...")
    inventory_file = output_path / 'inventory.json'
    if inventory_file.exists():
        print(f"  ✓ File exists: {inventory_file}")
        with open(inventory_file) as f:
            inv = json.load(f)
        
        print(f"  Metadata:")
        meta = inv.get('metadata', {})
        for key, value in meta.items():
            print(f"    {key}: {value}")
        
        print(f"  Hosts: {len(inv.get('hosts', {}))}")
        print(f"  Domains: {len(inv.get('domains', {}))}")
        
        if not inv.get('hosts'):
            print()
            print("  ⚠ INVENTORY IS EMPTY!")
            print("  This means aggregation didn't process the data correctly.")
    else:
        print(f"  ❌ File doesn't exist: {inventory_file}")
    print()
    
    # Diagnostic suggestions
    print("=" * 60)
    print("DIAGNOSIS")
    print("=" * 60)
    
    if masscan_file.exists() and masscan_file.stat().st_size > 0:
        print("✓ Masscan has output")
    else:
        print("⚠ Masscan has no output (this is OK if skipped or no results)")
    
    if nmap_dir.exists() and list(nmap_dir.glob('*.xml')):
        print("✓ Nmap has output files")
        
        # Check if XMLs have actual data
        xml_with_hosts = 0
        for xml_file in nmap_dir.glob('*.xml'):
            try:
                import xmltodict
                with open(xml_file) as f:
                    data = xmltodict.parse(f.read())
                if data.get('nmaprun', {}).get('host'):
                    xml_with_hosts += 1
            except:
                pass
        
        print(f"✓ {xml_with_hosts} XML files contain host data")
        
        if xml_with_hosts == 0:
            print()
            print("❌ PROBLEM: Nmap XMLs exist but contain no host data!")
            print("   Possible causes:")
            print("   - All hosts were down/filtered")
            print("   - Nmap scan was incomplete")
            print("   - Permission issues")
    else:
        print("⚠ Nmap has no output files")
    
    if inventory_file.exists():
        with open(inventory_file) as f:
            inv = json.load(f)
        
        if inv.get('hosts'):
            print("✓ Inventory has host data")
        else:
            print()
            print("❌ PROBLEM: Inventory is empty!")
            print("   The aggregation script didn't process the scan data.")
            print()
            print("   DEBUG STEPS:")
            print("   1. Check if tools_used in metadata is empty")
            print(f"      tools_used: {inv.get('metadata', {}).get('tools_used', [])}")
            print()
            print("   2. Run aggregation manually:")
            print("      python3 -c \"from tools.aggregate import aggregate_results; \\")
            print("                   aggregate_results([], [], [], 'out')\"")
            print()
            print("   3. Check aggregate.py logic for empty list handling")
    else:
        print("❌ Inventory file doesn't exist - aggregation failed completely")
    
    print()
    print("=" * 60)


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'out'
    check_outputs(output_dir)
