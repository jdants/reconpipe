"""
Nmap Wrapper - Detailed port scanning and service detection
"""

import os
import subprocess
import logging
import xmltodict
from typing import List, Dict, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


def run_nmap(targets: List[str], output_dir: str, 
             scan_type: str = '-sV', additional_flags: str = '',
             max_workers: int = 3, sudo_password: Optional[str] = None) -> List[Dict]:
    """
    Execute Nmap for detailed scanning and fingerprinting
    
    Args:
        targets: List of IP addresses
        output_dir: Directory to save XML outputs
        scan_type: Nmap scan type (default: -sV for version detection)
        additional_flags: Additional Nmap flags
        max_workers: Number of parallel scans
        sudo_password: Sudo password for privileged scans
    
    Returns:
        List of parsed Nmap results
    """
    results = []
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Check if nmap is installed
    if not check_nmap_installed():
        logger.error("Nmap not found. Install with: sudo apt-get install nmap")
        return results
    
    logger.info(f"Starting Nmap scans on {len(targets)} target(s)")
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(
                scan_single_target, 
                target, 
                output_path, 
                scan_type, 
                additional_flags,
                sudo_password
            ): target 
            for target in targets
        }
        
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result:
                    # Result is always a list now (even for single hosts)
                    if isinstance(result, list):
                        results.extend(result)
                    else:
                        # Shouldn't happen, but handle it just in case
                        results.append(result)
            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
    
    logger.info(f"Nmap completed scanning {len(results)}/{len(targets)} hosts")
    return results


def scan_single_target(target: str, output_path: Path, scan_type: str, 
                      additional_flags: str, sudo_password: Optional[str] = None) -> Optional[Dict]:
    """Scan a single target with Nmap"""
    
    logger.info(f"Scanning {target} with Nmap...")
    
    # Sanitize target for filename
    safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
    xml_output = output_path / f"nmap_{safe_target}.xml"
    
    # Build nmap command
    cmd = ['nmap']
    
    # Add sudo if password provided
    if sudo_password:
        cmd = ['sudo', '-S'] + cmd
    
    cmd.extend([
        scan_type,
        '-sC',  # Default scripts
        '-O',   # OS detection
        '-T4',  # Aggressive timing
        '--open',  # Only show open ports
        '-oX', str(xml_output),  # XML output
        '-oN', str(xml_output.with_suffix('.txt')),  # Normal output too
        '-oA', str(xml_output.with_suffix(''))  # All formats
    ])
    
    if additional_flags:
        cmd.extend(additional_flags.split())
    
    cmd.append(target)
    
    logger.debug(f"Running: {' '.join(cmd).replace('-S', '')}")  # Hide -S flag in logs
    
    try:
        # Execute nmap
        if sudo_password:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=sudo_password + '\n', timeout=600)
            returncode = process.returncode
        else:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            stdout = process.stdout
            stderr = process.stderr
            returncode = process.returncode
        
        if returncode != 0:
            logger.error(f"Nmap failed for {target}: {stderr}")
            return None
        
        # Parse XML output
        # Parse XML output
        host_data = parse_nmap_xml(str(xml_output)) # host_data is a List[Dict]
        if host_data:
            # Change the log to count the number of hosts parsed from this file
            logger.info(f"   ✓ {target}: Parsed {len(host_data)} host(s) from {os.path.basename(xml_output)}")
            return host_data # Return the full list
        else:
            logger.warning(f"   ✗ {target}: No results")
            return None
        #host_data = parse_nmap_xml(str(xml_output))
        #if host_data:
        #    logger.info(f"  ✓ {target}: {len(host_data.get('ports', []))} open ports")
        #    return host_data
        #else:
        #    logger.warning(f"  ✗ {target}: No results")
        #    return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"Nmap timed out for {target}")
        return None
    except Exception as e:
        logger.error(f"Nmap error for {target}: {e}")
        return None


def parse_nmap_xml(xml_file: str) -> List[Dict]:
    """
    Parse Nmap XML output - handles multiple hosts (CIDR scans)
    
    Returns:
        List of host dictionaries (empty list if no hosts)
        
    NOTE: This now returns a LIST even for single hosts for consistency
    """
    return parse_nmap_xml_multi(xml_file)


def parse_nmap_xml_multi(xml_file: str) -> List[Dict]:
    """
    Parse Nmap XML output - handles multiple hosts (CIDR scans)
    
    Returns:
        List of host dictionaries (empty list if no hosts)
    """
    results = []
    
    try:
        if not os.path.exists(xml_file):
            logger.error(f"XML file not found: {xml_file}")
            return results

        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if not content.strip():
            logger.warning(f"XML file is empty: {xml_file}")
            return results
            
        data = xmltodict.parse(content)

        nmaprun = data.get('nmaprun')
        if not nmaprun:
            logger.warning(f"No nmaprun element in XML: {xml_file}")
            return results
            
        hosts = nmaprun.get('host')
        if not hosts:
            logger.warning(f"No host elements in XML (no results): {xml_file}")
            return results

        # Convert single host to list for uniform processing
        if isinstance(hosts, dict):
            hosts = [hosts]
        
        # Process each host
        for host in hosts:
            if not host:
                continue
                
            host_data = parse_single_host(host, xml_file)
            if host_data:
                results.append(host_data)
        
        logger.info(f"Parsed {len(results)} hosts from {os.path.basename(xml_file)}")
        return results

    except FileNotFoundError:
        logger.error(f"XML file not found: {xml_file}")
    except Exception as e:
        logger.error(f"Error parsing Nmap XML ({xml_file}): {e}")
        import traceback
        logger.debug(traceback.format_exc())

    return results


def parse_single_host(host: dict, xml_file: str) -> Optional[Dict]:
    """
    Parse a single host element from Nmap XML
    
    Args:
        host: Host dictionary from xmltodict
        xml_file: Path to source XML file
    
    Returns:
        Host data dictionary or None
    """
    try:
        result = {
            'ip': None,
            'hostname': None,
            'status': 'unknown',
            'ports': [],
            'os': None,
            'mac_address': None,
            'vendor': None,
            'xml_file': xml_file
        }

        # Get addresses - SAFER extraction
        addresses = host.get('address')
        if addresses:
            if not isinstance(addresses, list):
                addresses = [addresses]
            for addr in addresses:
                if not addr:  # Skip None entries
                    continue
                addr_type = addr.get('@addrtype')
                if addr_type == 'ipv4':
                    result['ip'] = addr.get('@addr')
                elif addr_type == 'mac':
                    result['mac_address'] = addr.get('@addr')
                    result['vendor'] = addr.get('@vendor')

        # Get hostnames - SAFER extraction
        hostnames_obj = host.get('hostnames')
        if hostnames_obj and isinstance(hostnames_obj, dict):
            hostname = hostnames_obj.get('hostname')
            if hostname:
                if isinstance(hostname, list):
                    result['hostname'] = hostname[0].get('@name') if hostname[0] else None
                elif isinstance(hostname, dict):
                    result['hostname'] = hostname.get('@name')

        # Get status - SAFER extraction
        status = host.get('status')
        if status and isinstance(status, dict):
            result['status'] = status.get('@state', 'unknown')

        # Get ports - SAFER extraction
        ports_obj = host.get('ports')
        if ports_obj and isinstance(ports_obj, dict):
            ports_data = ports_obj.get('port', [])
            if not isinstance(ports_data, list):
                ports_data = [ports_data] if ports_data else []

            for port in ports_data:
                if not port:  # Skip None entries
                    continue
                    
                state = port.get('state', {})
                service = port.get('service', {})

                if state and state.get('@state') == 'open':
                    port_info = {
                        'port': int(port.get('@portid', 0)),
                        'protocol': port.get('@protocol', 'tcp'),
                        'state': state.get('@state'),
                        'service': service.get('@name', 'unknown') if service else 'unknown',
                        'product': service.get('@product') if service else None,
                        'version': service.get('@version') if service else None,
                        'extrainfo': service.get('@extrainfo') if service else None,
                        'cpe': service.get('cpe') if service else None
                    }

                    banner_parts = []
                    if port_info['product']:
                        banner_parts.append(port_info['product'])
                    if port_info['version']:
                        banner_parts.append(port_info['version'])
                    if port_info['extrainfo']:
                        banner_parts.append(f"({port_info['extrainfo']})")

                    port_info['banner'] = ' '.join(banner_parts) if banner_parts else port_info['service']
                    result['ports'].append(port_info)

        # Get OS - SAFER extraction
        os_data = host.get('os')
        if os_data and isinstance(os_data, dict):
            osmatch = os_data.get('osmatch')
            if osmatch:
                if isinstance(osmatch, list):
                    best_match = max(osmatch, key=lambda x: int(x.get('@accuracy', 0)) if x else 0)
                    if best_match:
                        result['os'] = best_match.get('@name')
                        result['os_accuracy'] = best_match.get('@accuracy')
                elif isinstance(osmatch, dict):
                    result['os'] = osmatch.get('@name')
                    result['os_accuracy'] = osmatch.get('@accuracy')

        # Get uptime - SAFER extraction
        uptime = host.get('uptime')
        if uptime and isinstance(uptime, dict):
            result['uptime'] = {
                'seconds': uptime.get('@seconds'),
                'lastboot': uptime.get('@lastboot')
            }

        # Only return if we got at least an IP
        if result['ip']:
            return result
        else:
            logger.debug(f"No IP found in host element")
            return None
            
    except Exception as e:
        logger.error(f"Error parsing single host: {e}")
        return None
    """
    Parse Nmap XML output
    
    Returns:
        Dictionary with host information
    """
    try:
        if not os.path.exists(xml_file):
            logger.error(f"XML file not found: {xml_file}")
            return None
        
        with open(xml_file, 'r', encoding='utf-8') as f:
            data = xmltodict.parse(f.read())
        
        nmaprun = data.get('nmaprun', {})
        host = nmaprun.get('host', {})
        
        if not host:
            return None
        
        # Handle case where host is a list (multiple hosts)
        if isinstance(host, list):
            host = host[0]
        
        # Extract basic host info
        result = {
            'ip': None,
            'hostname': None,
            'status': 'unknown',
            'ports': [],
            'os': None,
            'mac_address': None,
            'vendor': None,
            'xml_file': xml_file
        }
        
        # Get IP address and MAC
        addresses = host.get('address')
        if addresses:
            if not isinstance(addresses, list):
                addresses = [addresses]
            
            for addr in addresses:
                addr_type = addr.get('@addrtype')
                if addr_type == 'ipv4':
                    result['ip'] = addr.get('@addr')
                elif addr_type == 'mac':
                    result['mac_address'] = addr.get('@addr')
                    result['vendor'] = addr.get('@vendor')
        
        # Get hostname
        hostnames = host.get('hostnames', {}).get('hostname')
        if hostnames:
            if isinstance(hostnames, list):
                result['hostname'] = hostnames[0].get('@name')
            elif isinstance(hostnames, dict):
                result['hostname'] = hostnames.get('@name')
        
        # Get status
        status = host.get('status', {})
        result['status'] = status.get('@state', 'unknown')
        
        # Get ports
        ports_data = host.get('ports', {}).get('port', [])
        if not isinstance(ports_data, list):
            ports_data = [ports_data] if ports_data else []
        
        for port in ports_data:
            state = port.get('state', {})
            service = port.get('service', {})
            
            if state.get('@state') == 'open':
                port_info = {
                    'port': int(port.get('@portid', 0)),
                    'protocol': port.get('@protocol', 'tcp'),
                    'state': state.get('@state'),
                    'service': service.get('@name', 'unknown'),
                    'product': service.get('@product'),
                    'version': service.get('@version'),
                    'extrainfo': service.get('@extrainfo'),
                    'cpe': service.get('cpe')
                }
                
                # Build a nice service banner
                banner_parts = []
                if port_info['product']:
                    banner_parts.append(port_info['product'])
                if port_info['version']:
                    banner_parts.append(port_info['version'])
                if port_info['extrainfo']:
                    banner_parts.append(f"({port_info['extrainfo']})")
                
                port_info['banner'] = ' '.join(banner_parts) if banner_parts else port_info['service']
                
                result['ports'].append(port_info)
        
        # Get OS detection
        os_data = host.get('os', {})
        if os_data:
            osmatch = os_data.get('osmatch')
            if osmatch:
                if isinstance(osmatch, list):
                    # Get the highest accuracy match
                    best_match = max(osmatch, key=lambda x: int(x.get('@accuracy', 0)))
                    result['os'] = best_match.get('@name')
                    result['os_accuracy'] = best_match.get('@accuracy')
                elif isinstance(osmatch, dict):
                    result['os'] = osmatch.get('@name')
                    result['os_accuracy'] = osmatch.get('@accuracy')
        
        # Get uptime if available
        uptime = host.get('uptime')
        if uptime:
            result['uptime'] = {
                'seconds': uptime.get('@seconds'),
                'lastboot': uptime.get('@lastboot')
            }
        
        return result
        
    except FileNotFoundError:
        logger.error(f"XML file not found: {xml_file}")
    except Exception as e:
        logger.error(f"Error parsing Nmap XML ({xml_file}): {e}")
    
    return None


def check_nmap_installed() -> bool:
    """Check if nmap is installed"""
    try:
        subprocess.run(['nmap', '--version'], 
                      capture_output=True, 
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
