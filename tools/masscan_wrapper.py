"""
Masscan Wrapper - Fast port scanner
"""

import json
import subprocess
import logging
import shutil
import socket
import re
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Try to find masscan executable
MASSCAN_PATH = None
for path in ['masscan', '/usr/bin/masscan', '/usr/local/bin/masscan', '/usr/sbin/masscan']:
    if shutil.which(path) or path.startswith('/') and subprocess.run([path, '--version'], capture_output=True).returncode == 0:
        MASSCAN_PATH = path
        break


def run_masscan(targets: List[str], output_file: str, 
                ports: str = '1-1000', rate: int = 1000,
                sudo_password: Optional[str] = None) -> List[Dict]:
    """
    Execute Masscan for fast host/port discovery
    
    Args:
        targets: List of IP addresses or CIDR ranges
        output_file: Path to save JSON output
        ports: Port range to scan (default: 1-1000)
        rate: Packets per second (default: 1000)
        sudo_password: Sudo password for root privileges
    
    Returns:
        List of discovered hosts/ports
    """
    results = []
    
    # Check if masscan is installed
    if not check_masscan_installed():
        logger.error("Masscan not found in common locations")
        logger.error("Tried: masscan, /usr/bin/masscan, /usr/local/bin/masscan, /usr/sbin/masscan")
        logger.error("Install with: sudo apt-get install masscan")
        logger.error("Or specify path in code")
        return results
    
    # Validate and filter targets for Masscan
    # Masscan ONLY accepts IP addresses and CIDR ranges, NOT hostnames
    valid_targets = []
    hostname_targets = []
    
    for target in targets:
        if is_valid_ip_or_cidr(target):
            valid_targets.append(target)
        else:
            # This is a hostname/domain
            hostname_targets.append(target)
            logger.info(f"Skipping hostname for Masscan (will use Nmap): {target}")
            
            # Try to resolve to IP
            try:
                ip = socket.gethostbyname(target)
                logger.info(f"  Resolved {target} → {ip}")
                if ip not in valid_targets:
                    valid_targets.append(ip)
            except socket.gaierror:
                logger.warning(f"  Could not resolve {target}")
    
    if not valid_targets:
        logger.warning("No valid IP targets for Masscan (only hostnames provided)")
        logger.warning("Masscan requires IP addresses or CIDR ranges")
        logger.warning("These targets will be scanned by Nmap instead")
        return results
    
    logger.info(f"Masscan will scan {len(valid_targets)} IP targets")
    if hostname_targets:
        logger.info(f"Nmap will handle {len(hostname_targets)} hostname targets")
    
    try:
        # Build masscan command - use detected path
        masscan_cmd = MASSCAN_PATH if MASSCAN_PATH else 'masscan'
        cmd = [masscan_cmd]
        
        # Add sudo if password provided
        if sudo_password:
            cmd = ['sudo', '-S'] + cmd
        
        cmd.extend([
            '-p', ports,
            '--rate', str(rate),
            '-oJ', output_file,
            '--open',  # Only show open ports
            '--wait', '10'  # Wait 10 seconds for responses
        ])
        
        # Add ONLY valid IP targets (no hostnames!)
        cmd.extend(valid_targets)
        
        logger.info(f"Running Masscan on {len(targets)} targets")
        logger.info(f"Port range: {ports}, Rate: {rate} packets/sec")
        
        # Important: Show the actual command (helps debug)
        cmd_display = ' '.join(cmd).replace('-S', '')
        logger.info(f"Command: {cmd_display}")
        
        # Common Masscan issues to warn about
        logger.warning("⚠️  Masscan common issues:")
        logger.warning("  1. Requires root/sudo privileges")
        logger.warning("  2. May find no results if ports are filtered")
        logger.warning("  3. Fast scans may miss slow hosts (increase --wait)")
        logger.warning("  4. Some networks block fast scanning")
        logger.warning("  5. Local scans (127.0.0.1, 192.168.x.x) may not work without special config")
        
        # Execute masscan
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
            logger.error(f"Masscan failed with exit code {returncode}")
            if stderr:
                logger.error(f"Error output: {stderr[:500]}")
            if "permission denied" in stderr.lower() or "operation not permitted" in stderr.lower():
                logger.error("Masscan requires root privileges")
                logger.error("Solution: Run with sudo or provide sudo password when prompted")
            if "FAIL: failed to detect IP address" in stderr:
                logger.error("Masscan cannot detect IP address")
                logger.error("Solution: Specify adapter with --adapter or check network")
            if "adapter" in stderr.lower():
                logger.error("Network adapter issue detected")
                logger.error("Try: masscan --adapter-list  (to see available adapters)")
            return results
        
        # Show stdout for debugging
        if stdout:
            logger.debug(f"Masscan stdout: {stdout[:500]}")
        
        logger.info(f"Masscan completed, parsing results from {output_file}")
        
        # Parse JSON output
        results = parse_masscan_output(output_file)
        
        if results:
            logger.info(f"✓ Masscan discovered {len(results)} open ports")
            
            # Log some sample results
            sample_size = min(5, len(results))
            logger.info(f"Sample results (showing {sample_size} of {len(results)}):")
            for i, result in enumerate(results[:sample_size], 1):
                logger.info(f"  {i}. {result['ip']}:{result['port']}/{result['protocol']}")
        else:
            logger.warning("Masscan completed but found no open ports")
            logger.warning("Possible reasons:")
            logger.warning("  - Targets may be offline or filtered")
            logger.warning("  - Port range may not include open ports")
            logger.warning("  - Network connectivity issues")
        
    except FileNotFoundError:
        logger.error("Masscan not found. Install: apt-get install masscan")
    except subprocess.TimeoutExpired:
        logger.error("Masscan timed out (10 minute limit)")
        logger.error("Try reducing the target scope or port range")
    except Exception as e:
        logger.error(f"Masscan error: {e}")
    
    return results


def parse_masscan_output(output_file: str) -> List[Dict]:
    """
    Parse Masscan JSON output
    
    Masscan outputs JSON in a non-standard format where each result
    is a separate JSON object on its own line (JSONL format).
    """
    results = []
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        if not content.strip():
            logger.warning(f"Masscan output file is empty: {output_file}")
            return results
        
        # Parse line by line (JSONL format)
        for line_num, line in enumerate(content.strip().split('\n'), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Remove trailing comma if present
            line = line.rstrip(',')
            
            try:
                obj = json.loads(line)
                
                # Masscan format: {"ip": "x.x.x.x", "timestamp": ..., "ports": [...]}
                if 'ip' in obj and 'ports' in obj:
                    ip = obj['ip']
                    timestamp = obj.get('timestamp')
                    
                    # Process each port
                    ports_data = obj['ports']
                    if not isinstance(ports_data, list):
                        ports_data = [ports_data]
                    
                    for port_info in ports_data:
                        result = {
                            'ip': ip,
                            'port': port_info.get('port'),
                            'protocol': port_info.get('proto', 'tcp'),
                            'status': port_info.get('status', 'open'),
                            'timestamp': timestamp,
                            'reason': port_info.get('reason', 'syn-ack')
                        }
                        results.append(result)
                        
            except json.JSONDecodeError as e:
                logger.debug(f"Could not parse line {line_num} as JSON: {e}")
                logger.debug(f"Line content: {line[:100]}")
                continue
        
        # Deduplicate results (same IP/port/protocol)
        unique_results = {}
        for result in results:
            key = (result['ip'], result['port'], result['protocol'])
            if key not in unique_results:
                unique_results[key] = result
        
        results = list(unique_results.values())
        
        logger.debug(f"Parsed {len(results)} unique results from {output_file}")
        
    except FileNotFoundError:
        logger.error(f"Masscan output file not found: {output_file}")
    except Exception as e:
        logger.error(f"Error parsing Masscan output: {e}")
    
    return results


def check_masscan_installed() -> bool:
    """Check if masscan is installed"""
    try:
        # Try common locations
        masscan_paths = [
            'masscan',
            '/usr/bin/masscan',
            '/usr/local/bin/masscan',
            '/usr/sbin/masscan'
        ]
        
        for masscan_path in masscan_paths:
            try:
                result = subprocess.run(
                    [masscan_path, '--version'], 
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0 or 'Masscan' in result.stdout.decode():
                    logger.debug(f"Found masscan at: {masscan_path}")
                    return True
            except FileNotFoundError:
                continue
        
        return False
    except Exception as e:
        logger.debug(f"Error checking for masscan: {e}")
        return False


def get_masscan_version() -> Optional[str]:
    """Get installed Masscan version"""
    try:
        result = subprocess.run(
            ['masscan', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Parse version from output
            for line in result.stdout.split('\n'):
                if 'Masscan version' in line:
                    return line.strip()
        return None
    except Exception:
        return None


def is_valid_ip_or_cidr(target: str) -> bool:
    """
    Check if target is a valid IP address or CIDR range
    Masscan only accepts these, not hostnames
    
    Args:
        target: Target string to validate
    
    Returns:
        True if valid IP or CIDR, False otherwise
    """
    # Check for CIDR notation (e.g., 192.168.1.0/24)
    if '/' in target:
        parts = target.split('/')
        if len(parts) == 2:
            ip_part = parts[0]
            cidr_part = parts[1]
            
            # Validate IP part
            try:
                socket.inet_aton(ip_part)
            except socket.error:
                return False
            
            # Validate CIDR part (0-32)
            try:
                cidr = int(cidr_part)
                return 0 <= cidr <= 32
            except ValueError:
                return False
    
    # Check for single IP address
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}'

    if re.match(ipv4_pattern, target):
        # Validate each octet is 0-255
        octets = target.split('.')
        try:
            return all(0 <= int(octet) <= 255 for octet in octets)
        except ValueError:
            return False
    
    # Check if it's a valid IP using socket (handles IPv6 too)
    try:
        socket.inet_aton(target)  # IPv4
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, target)  # IPv6
            return True
        except socket.error:
            return False
    
    return False
