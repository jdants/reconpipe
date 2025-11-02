"""
theHarvester Wrapper - OSINT data collection
"""

import json
import subprocess
import logging
import re
from typing import List, Dict, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import configuration
try:
    from config import HARVESTER_CONFIG
except ImportError:
    # Fallback defaults if config.py doesn't exist
    HARVESTER_CONFIG = {
        'sources': 'google,bing,duckduckgo',
        'limit': 500,
        'timeout': 300,
    }

logger = logging.getLogger(__name__)


def run_harvester(domains: List[str], output_dir: str, 
                  sources: str = None, max_workers: int = 2) -> List[Dict]:
    """
    Execute theHarvester for OSINT collection
    
    Args:
        domains: List of domain names
        output_dir: Directory to save outputs
        sources: Comma-separated list of sources (None = use config)
        max_workers: Number of parallel harvests
    
    Returns:
        List of harvested information per domain
    """
    # Use config if not specified
    if sources is None:
        sources = HARVESTER_CONFIG.get('sources', 'google,bing,duckduckgo')
    """
    Execute theHarvester for OSINT collection
    
    Args:
        domains: List of domain names
        output_dir: Directory to save outputs
        sources: Comma-separated list of sources
        max_workers: Number of parallel harvests
    
    Returns:
        List of harvested information per domain
    """
    results = []
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Check if theHarvester is installed
    if not check_harvester_installed():
        logger.warning("theHarvester not found. Install with: pip install theHarvester")
        logger.warning("Skipping OSINT collection phase")
        return results
    
    logger.info(f"Starting theHarvester on {len(domains)} domain(s)")
    logger.info(f"Sources: {sources}")
    
    # Use ThreadPoolExecutor for parallel harvesting
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(
                harvest_single_domain, 
                domain, 
                output_path, 
                sources
            ): domain 
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error harvesting {domain}: {e}")
    
    logger.info(f"theHarvester completed for {len(results)}/{len(domains)} domains")
    return results


def harvest_single_domain(domain: str, output_path: Path, sources: str) -> Optional[Dict]:
    """Harvest OSINT data for a single domain"""
    
    logger.info(f"Harvesting {domain}...")
    
    safe_domain = domain.replace('.', '_').replace('/', '_')
    output_base = output_path / f"harvester_{safe_domain}"
    
    # Build theHarvester command
    cmd = [
        'theHarvester',
        '-d', domain,
        '-b', sources,
        '-f', str(output_base)  # Base filename (theHarvester adds extensions)
    ]
    
    logger.debug(f"Running: {' '.join(cmd)}")
    
    try:
        # Execute theHarvester
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # theHarvester often returns non-zero even on success
        if process.returncode != 0 and "No hosts found" not in process.stdout:
            logger.warning(f"theHarvester warning for {domain}: {process.stderr[:200]}")
        
        # Save raw output
        raw_output_file = output_path / f"harvester_{safe_domain}_raw.txt"
        with open(raw_output_file, 'w') as f:
            f.write(process.stdout)
        
        # Parse output
        domain_data = parse_harvester_output(
            domain, 
            process.stdout, 
            str(output_base)
        )
        
        if domain_data:
            total_items = (len(domain_data.get('emails', [])) + 
                          len(domain_data.get('hosts', [])) + 
                          len(domain_data.get('ips', [])))
            logger.info(f"  ✓ {domain}: {total_items} items found")
            return domain_data
        else:
            logger.warning(f"  ✗ {domain}: No data found")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"theHarvester timed out for {domain}")
        return None
    except Exception as e:
        logger.error(f"theHarvester error for {domain}: {e}")
        return None


def parse_harvester_output(domain: str, stdout: str, output_base: str) -> Optional[Dict]:
    """
    Parse theHarvester output from multiple sources
    
    Returns:
        Dictionary with harvested information
    """
    result = {
        'domain': domain,
        'emails': [],
        'hosts': [],
        'ips': [],
        'urls': [],
        'asns': [],
        'shodan_info': []
    }
    
    try:
        # Method 1: Try to parse JSON output (newer versions)
        json_file = Path(f"{output_base}.json")
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    json_data = json.load(f)
                
                # Extract data from JSON
                result['emails'] = list(set(json_data.get('emails', [])))
                result['hosts'] = list(set(json_data.get('hosts', [])))
                result['ips'] = list(set(json_data.get('ip', [])))
                result['asns'] = list(set(json_data.get('asns', [])))
                
                logger.debug(f"Parsed JSON output for {domain}")
                
            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse JSON for {domain}: {e}")
        
        # Method 2: Parse from stdout using regex (fallback)
        if not result['emails'] and not result['hosts']:
            result.update(parse_stdout_regex(stdout, domain))
        
        # Method 3: Try XML output (some versions)
        xml_file = Path(f"{output_base}.xml")
        if xml_file.exists():
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                for email in root.findall('.//email'):
                    if email.text:
                        result['emails'].append(email.text)
                
                for host in root.findall('.//host'):
                    if host.text:
                        result['hosts'].append(host.text)
                        
            except Exception as e:
                logger.debug(f"Could not parse XML: {e}")
        
        # Deduplicate and sort
        result['emails'] = sorted(list(set(result['emails'])))
        result['hosts'] = sorted(list(set(result['hosts'])))
        result['ips'] = sorted(list(set(result['ips'])))
        
        # Log findings
        logger.info(f"  Found for {domain}:")
        logger.info(f"    - {len(result['emails'])} emails")
        logger.info(f"    - {len(result['hosts'])} hosts/subdomains")
        logger.info(f"    - {len(result['ips'])} IPs")
        
        return result if (result['emails'] or result['hosts'] or result['ips']) else None
        
    except Exception as e:
        logger.error(f"Error parsing theHarvester output for {domain}: {e}")
        return None


def parse_stdout_regex(stdout: str, domain: str) -> Dict:
    """Parse theHarvester stdout using regular expressions"""
    
    result = {
        'emails': [],
        'hosts': [],
        'ips': []
    }
    
    # Extract emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, stdout)
    # Filter to only emails from the target domain
    result['emails'] = [e for e in set(emails) if domain in e.lower()]
    
    # Extract hosts/subdomains (lines containing the domain)
    lines = stdout.split('\n')
    for line in lines:
        if domain in line.lower():
            # Look for subdomain patterns
            host_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(domain) + r'\b'
            matches = re.findall(host_pattern, line, re.IGNORECASE)
            result['hosts'].extend(matches)
    
    # Extract IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, stdout)
    # Filter out common false positives
    result['ips'] = [ip for ip in set(ips) 
                     if not ip.startswith('127.') 
                     and not ip.startswith('0.')
                     and not ip == '255.255.255.255']
    
    # Deduplicate
    result['emails'] = list(set(result['emails']))
    result['hosts'] = list(set(result['hosts']))
    result['ips'] = list(set(result['ips']))
    
    return result


def check_harvester_installed() -> bool:
    """Check if theHarvester is installed"""
    try:
        result = subprocess.run(
            ['theHarvester', '-h'], 
            capture_output=True,
            timeout=5
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))
