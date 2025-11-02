"""
EyeWitness Wrapper - Web service screenshot and analysis
"""

import os
import subprocess
import logging
import json
import shutil
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


def run_eyewitness(inventory: Dict, output_dir: str, timeout: int = 300) -> Dict:
    """
    Execute EyeWitness for web service screenshots and analysis
    
    Args:
        inventory: The inventory dictionary from aggregate_results
        output_dir: Directory to save EyeWitness outputs
        timeout: Timeout per URL (seconds)
    
    Returns:
        Updated inventory with EyeWitness data
    """
    
    # Check if EyeWitness is installed
    if not check_eyewitness_installed():
        logger.warning("EyeWitness not found. Install with:")
        logger.warning("  git clone https://github.com/FortyNorthSecurity/EyeWitness.git")
        logger.warning("  cd EyeWitness/Python/setup && ./setup.sh")
        logger.warning("Skipping screenshot phase")
        return inventory
    
    logger.info("Starting EyeWitness for web service screenshots...")
    
    output_path = Path(output_dir)
    eyewitness_dir = output_path / 'eyewitness'
    eyewitness_dir.mkdir(exist_ok=True)
    
    # Extract web services from inventory
    web_urls = extract_web_services(inventory)
    
    if not web_urls:
        logger.warning("No web services found to screenshot")
        return inventory
    
    logger.info(f"Found {len(web_urls)} web services to screenshot")
    
    # Create URL list file
    urls_file = eyewitness_dir / 'urls.txt'
    with open(urls_file, 'w') as f:
        for url in web_urls:
            f.write(f"{url}\n")
    
    logger.info(f"Saved URL list to {urls_file}")
    
    # Run EyeWitness
    try:
        eyewitness_output = eyewitness_dir / 'report'
        
        # Find EyeWitness executable
        eyewitness_path = find_eyewitness_path()
        if not eyewitness_path:
            logger.error("Could not locate EyeWitness executable")
            return inventory
        
        cmd = [
            'python3', eyewitness_path,
            '-f', str(urls_file),
            '-d', str(eyewitness_output),
            '--no-prompt',
            '--timeout', str(timeout),
            '--threads', '5',
            '--web'
        ]
        
        logger.info(f"Running EyeWitness: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=len(web_urls) * timeout + 300  # Extra time for processing
        )
        
        if process.returncode != 0:
            logger.warning(f"EyeWitness completed with warnings: {process.stderr[:500]}")
        else:
            logger.info("✓ EyeWitness completed successfully")
        
        # Parse EyeWitness results
        eyewitness_data = parse_eyewitness_results(eyewitness_output)
        
        # Update inventory with screenshot information
        update_inventory_with_screenshots(inventory, eyewitness_data)
        
        # Add metadata
        inventory['metadata']['eyewitness_enabled'] = True
        inventory['metadata']['eyewitness_date'] = datetime.now().isoformat()
        inventory['metadata']['screenshots_captured'] = len(eyewitness_data)
        
        logger.info(f"✓ Captured {len(eyewitness_data)} screenshots")
        
    except subprocess.TimeoutExpired:
        logger.error("EyeWitness timed out")
    except Exception as e:
        logger.error(f"EyeWitness error: {e}")
        import traceback
        logger.debug(traceback.format_exc())
    
    return inventory


def extract_web_services(inventory: Dict) -> List[str]:
    """
    Extract web service URLs from inventory
    
    Returns:
        List of URLs to screenshot
    """
    urls = []
    web_ports = {
        80: 'http',
        443: 'https',
        8080: 'http',
        8443: 'https',
        8000: 'http',
        8888: 'http',
        3000: 'http',
        5000: 'http',
        9000: 'http'
    }
    
    web_services = [
        'http', 'https', 'ssl/http', 'http-proxy', 'http-alt',
        'https-alt', 'ssl/https', 'www', 'apache', 'nginx',
        'lighttpd', 'httpd', 'tomcat', 'webmin', 'ssl/ssl'
    ]
    
    for ip, host_data in inventory['hosts'].items():
        hostname = host_data.get('hostname') or ip
        
        for port_key, service in host_data.get('services', {}).items():
            port = service.get('port')
            service_name = (service.get('service') or '').lower()
            product = (service.get('product') or '').lower() 
            # Determine if this is a web service
            is_web = False
            protocol = 'http'
            
            # Check by service name
            if any(ws in service_name for ws in web_services):
                is_web = True
                if 'ssl' in service_name or 'https' in service_name:
                    protocol = 'https'
            
            # Check by port number
            elif port in web_ports:
                is_web = True
                protocol = web_ports[port]
            
            # Check by product name
            elif any(p in product for p in ['apache', 'nginx', 'iis', 'tomcat', 'lighttpd']):
                is_web = True
                # Guess protocol by port
                if port == 443 or port == 8443:
                    protocol = 'https'
            
            if is_web:
                url = f"{protocol}://{hostname}:{port}"
                urls.append(url)
                logger.debug(f"Found web service: {url} ({service_name})")
    
    return sorted(list(set(urls)))


def parse_eyewitness_results(output_dir: Path) -> Dict:
    """
    Parse EyeWitness results from output directory
    
    Returns:
        Dictionary mapping URLs to screenshot data
    """
    results = {}
    
    try:
        # Check for report files
        report_json = output_dir / 'results.json'
        
        if report_json.exists():
            with open(report_json, 'r') as f:
                data = json.load(f)
            
            for entry in data:
                url = entry.get('url')
                if url:
                    results[url] = {
                        'url': url,
                        'screenshot': entry.get('screenshot_path'),
                        'response_code': entry.get('response_code'),
                        'page_title': entry.get('page_title'),
                        'server_header': entry.get('server_header'),
                        'content_length': entry.get('content_length'),
                        'error': entry.get('error')
                    }
        
        # Also check for screenshots directory
        screenshots_dir = output_dir / 'screens'
        if screenshots_dir.exists():
            for screenshot in screenshots_dir.glob('*.png'):
                # Extract URL from filename if not already in results
                filename = screenshot.stem
                if filename not in [r.get('url', '').replace('://', '_').replace('/', '_').replace(':', '_') 
                                   for r in results.values()]:
                    results[filename] = {
                        'screenshot': str(screenshot.relative_to(output_dir.parent.parent))
                    }
        
        logger.debug(f"Parsed {len(results)} EyeWitness results")
        
    except Exception as e:
        logger.error(f"Error parsing EyeWitness results: {e}")
    
    return results


def update_inventory_with_screenshots(inventory: Dict, eyewitness_data: Dict):
    """Update inventory with EyeWitness screenshot data"""
    
    for ip, host_data in inventory['hosts'].items():
        hostname = host_data.get('hostname') or ip
        
        for port_key, service in host_data.get('services', {}).items():
            port = service.get('port')
            
            # Try to match with eyewitness results
            for protocol in ['http', 'https']:
                url = f"{protocol}://{hostname}:{port}"
                
                if url in eyewitness_data:
                    service['eyewitness'] = eyewitness_data[url]
                    logger.debug(f"Added screenshot data for {url}")
                    break


def check_eyewitness_installed() -> bool:
    """Check if EyeWitness is installed"""
    eyewitness_path = find_eyewitness_path()
    return eyewitness_path is not None


def find_eyewitness_path() -> Optional[str]:
    """Find EyeWitness executable path"""
    
    # Common installation paths
    common_paths = [
        '/opt/EyeWitness/Python/EyeWitness.py',
        '/usr/local/bin/EyeWitness.py',
        '/usr/share/eyewitness/EyeWitness.py',
        '~/EyeWitness/Python/EyeWitness.py',
        './EyeWitness/Python/EyeWitness.py',
    ]
    
    # Expand home directory
    common_paths = [os.path.expanduser(p) for p in common_paths]
    
    for path in common_paths:
        if os.path.exists(path):
            logger.debug(f"Found EyeWitness at: {path}")
            return path
    
    # Try which command
    try:
        result = subprocess.run(
            ['which', 'EyeWitness.py'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            path = result.stdout.strip()
            logger.debug(f"Found EyeWitness via which: {path}")
            return path
    except Exception:
        pass
    
    return None


def get_eyewitness_info():
    """Display information about EyeWitness"""
    info = """
EyeWitness Installation:

1. Install dependencies:
   sudo apt-get install -y python3-pip
   sudo apt-get install -y chromium-browser

2. Clone and install:
   git clone https://github.com/FortyNorthSecurity/EyeWitness.git
   cd EyeWitness/Python/setup
   sudo ./setup.sh

3. Verify installation:
   python3 /opt/EyeWitness/Python/EyeWitness.py --help

Alternative - Docker:
   docker pull moomootank/eyewitness:latest
    """
    return info
