#!/usr/bin/env python3
"""
Reconnaissance Orchestration Pipeline
Automates: Masscan → Nmap → theHarvester → Aggregation
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Import tool wrappers
from tools.masscan_wrapper import run_masscan
from tools.nmap_wrapper import run_nmap
from tools.harvester_wrapper import run_harvester
from tools.aggregate import aggregate_results
from tools.cve_lookup import lookup_cves_for_inventory, export_vulnerability_report, set_nvd_api_key

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_pipeline.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SudoManager:
    """Simplified: only checks whether we're root. No password storage."""
    def __init__(self):
        self.is_root = (os.geteuid() == 0)

    def check_sudo_required(self):
        return not self.is_root

    def verify_sudo(self):
        """Verify whether we are running as root. Do not prompt or store passwords."""
        if self.is_root:
            logger.info("Running as root, privileged scans allowed")
            return True

        # Check if sudo timestamp is valid (no password prompt)
        try:
            result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
            if result.returncode == 0:
                logger.info("Sudo access is available (cached credentials)")
                return True
        except Exception:
            pass

        # Not running as root and no cached sudo: fail fast and tell user what to do.
        logger.warning("Not running as root and no cached sudo credentials found.")
        logger.warning("Please run the script with sudo (e.g. `sudo python run_recon.py targets.txt`) or use --no-sudo to continue without privileged scans.")
        return False


class ReconPipeline:
    """Main orchestration class for the reconnaissance pipeline"""
    def __init__(self, targets_file, output_dir='out', skip_masscan=False,
                 skip_nmap=False, skip_harvester=False, no_sudo=False,
                 cve_lookup=False, nvd_api_key=None, cve_max_age=365):
        self.targets_file = targets_file
        self.output_dir = Path(output_dir)
        self.skip_masscan = skip_masscan
        self.skip_nmap = skip_nmap
        self.skip_harvester = skip_harvester
        self.no_sudo = no_sudo
        self.cve_lookup = cve_lookup
        self.cve_max_age = cve_max_age

        # Configure NVD API key if provided
        if nvd_api_key:
            set_nvd_api_key(nvd_api_key)
        elif cve_lookup:
            env_key = os.environ.get('NVD_API_KEY')
            if env_key:
                set_nvd_api_key(env_key)
                logger.info("Using NVD API key from environment variable")
            else:
                logger.warning("No NVD API key provided - rate limited")

        # Sudo manager
        self.sudo_manager = SudoManager()

        # Create output directories
        self.setup_directories()

        # Load targets
        self.targets = self.load_targets()

        # Results storage
        self.masscan_results = []
        self.nmap_results = []
        self.harvester_results = []

    def setup_directories(self):
        """Create necessary output directories"""
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / 'nmap').mkdir(exist_ok=True)
        (self.output_dir / 'harvester').mkdir(exist_ok=True)
        logger.info(f"Output directory: {self.output_dir.absolute()}")

    def load_targets(self):
        """Load targets from file"""
        try:
            with open(self.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            if not targets:
                logger.error(f"No targets found in {self.targets_file}")
                sys.exit(1)

            logger.info(f"Loaded {len(targets)} targets from {self.targets_file}")
            print("\nTargets to scan:")
            for i, target in enumerate(targets[:10], 1):
                print(f"  {i}. {target}")
            if len(targets) > 10:
                print(f"  ... and {len(targets) - 10} more")
            print()
            return targets
        except FileNotFoundError:
            logger.error(f"Targets file not found: {self.targets_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error loading targets: {e}")
            sys.exit(1)

    def verify_sudo_if_needed(self):
        """Verify sudo access if needed by any phase"""
        if self.no_sudo:
            logger.warning("Running without sudo - some features may be limited")
            return True

        needs_sudo = not self.skip_masscan or not self.skip_nmap
        if needs_sudo:
            return self.sudo_manager.verify_sudo()
        return True

    def run(self):
        """Execute the full reconnaissance pipeline"""
        logger.info("=" * 80)
        logger.info("RECONNAISSANCE PIPELINE STARTING")
        logger.info("=" * 80)

        start_time = datetime.now()

        # Verify sudo if needed
        if not self.verify_sudo_if_needed():
            logger.error("Cannot proceed with privileged scans without sudo/root.")
            logger.error("Run with: sudo python run_recon.py targets.txt  OR use --no-sudo to continue without privileged scans.")
            sys.exit(1)

        # Phase 1: Masscan
        hosts_to_scan = [t for t in self.targets if not any(c.isalpha() for c in t.replace('.', ''))]
        if not hosts_to_scan:
            logger.info("\n" + "=" * 80)
            logger.warning("No IP or networks found in targets.txt, skipping Masscan...")
            logger.info("=" * 80)
            self.skip_masscan = True
        if not self.skip_masscan:
            logger.info("\n" + "=" * 80)
            logger.info("[Phase 1/3] MASSCAN - Fast Host Discovery")
            logger.info("=" * 80)
            try:
                self.masscan_results = run_masscan(
                    hosts_to_scan,
                    output_file=str(self.output_dir / 'masscan.json')
                )
                logger.info(f"✓ Masscan discovered {len(self.masscan_results)} open ports")
            except Exception as e:
                logger.error(f"Masscan phase failed: {e}")
        else:
            logger.info("\n[Phase 1/3] Skipping Masscan")
            masscan_file = self.output_dir / 'masscan.json'
            if masscan_file.exists():
                try:
                    with open(masscan_file) as f:
                        self.masscan_results = json.load(f)
                    logger.info(f"Loaded {len(self.masscan_results)} results from existing file")
                except Exception as e:
                    logger.warning(f"Could not load existing Masscan results: {e}")

        # Phase 2: Nmap - Detailed scanning
        if not self.skip_nmap:
            logger.info("\n" + "=" * 80)
            logger.info("[Phase 2/3] NMAP - Detailed Service Detection")
            logger.info("=" * 80)
    
            try:
                # Extract unique hosts from masscan results
                hosts_to_scan = list(set([r['ip'] for r in self.masscan_results]))
        
                if not hosts_to_scan:
                    logger.warning("No hosts from Masscan, scanning original targets")
                    # Get only IP addresses/CIDR from targets (not domains)
                    hosts_to_scan = [t for t in self.targets 
                                   if not any(c.isalpha() for c in t.replace('.', '').replace('/', ''))]
        
                if not hosts_to_scan:
                    logger.warning("No IP targets found, skipping Nmap")
                    self.skip_nmap = True
                else:
                    logger.info(f"Scanning {len(hosts_to_scan)} hosts with Nmap")
            
                    # run_nmap now returns a LIST of hosts
                    self.nmap_results = run_nmap(
                        hosts_to_scan,
                        output_dir=str(self.output_dir / 'nmap')
                    )
            
                    logger.info(f"✓ Nmap scanned {len(self.nmap_results)} hosts")
            except Exception as e:
                logger.error(f"Nmap phase failed: {e}")
                import traceback
                logger.error(traceback.format_exc())            

        # Phase 3: theHarvester
        if not self.skip_harvester:
            logger.info("\n" + "=" * 80)
            logger.info("[Phase 3/3] THEHARVESTER - OSINT Collection")
            logger.info("=" * 80)
            try:
                domains = [t for t in self.targets if '.' in t and any(c.isalpha() for c in t)]
                if domains:
                    logger.info(f"Harvesting OSINT for {len(domains)} domains")
                    self.harvester_results = run_harvester(
                        domains,
                        output_dir=str(self.output_dir / 'harvester')
                    )
                    logger.info(f"✓ theHarvester collected data for {len(self.harvester_results)} domains")
                else:
                    logger.warning("No domains found for theHarvester")
            except Exception as e:
                logger.error(f"theHarvester phase failed: {e}")
        else:
            logger.info("\n[Phase 3/3] Skipping theHarvester")

        # Aggregation
        logger.info("\n" + "=" * 80)
        logger.info("[Aggregation] Combining Results")
        logger.info("=" * 80)
        try:
            inventory = aggregate_results(
                masscan_data=self.masscan_results,
                nmap_data=self.nmap_results,
                harvester_data=self.harvester_results,
                output_dir=str(self.output_dir)
            )
        except Exception as e:
            logger.error(f"Aggregation phase failed: {e}")
            inventory = None

        # CVE lookup (optional)
        if self.cve_lookup and inventory:
            logger.info("\n" + "=" * 80)
            logger.info("[CVE Lookup] Vulnerability Assessment")
            logger.info("=" * 80)
            try:
                inventory = lookup_cves_for_inventory(inventory, max_age_days=self.cve_max_age)
                json_output = self.output_dir / 'inventory.json'
                with open(json_output, 'w', encoding='utf-8') as f:
                    json.dump(inventory, f, indent=2, ensure_ascii=False)
                logger.info(f"✓ Updated inventory.json with CVE data")
                vuln_report = self.output_dir / 'vulnerability_report.txt'
                export_vulnerability_report(inventory, str(vuln_report))
            except Exception as e:
                logger.error(f"CVE lookup phase failed: {e}")
        elif self.cve_lookup:
            logger.warning("Skipping CVE lookup - no inventory data available")

        # Summary
        end_time = datetime.now()
        duration = end_time - start_time

        logger.info("\n" + "=" * 80)
        logger.info("PIPELINE COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Duration: {duration}")
        logger.info(f"Results location: {self.output_dir.absolute()}")
        logger.info("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Reconnaissance Pipeline Orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python run_recon.py targets.txt    # run with sudo (recommended)
  python run_recon.py targets.txt --no-sudo   # run without sudo (limited)
"""
    )

    parser.add_argument('targets', help='File containing target IPs/domains (one per line)')
    parser.add_argument('-o', '--output', default='out', help='Output directory (default: out)')
    parser.add_argument('--skip-masscan', action='store_true', help='Skip Masscan phase')
    parser.add_argument('--skip-nmap', action='store_true', help='Skip Nmap phase')
    parser.add_argument('--skip-harvester', action='store_true', help='Skip theHarvester phase')
    parser.add_argument('--no-sudo', action='store_true', help='Run without sudo (limited functionality)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')

    cve_group = parser.add_argument_group('CVE Lookup Options')
    cve_group.add_argument('--cve-lookup', action='store_true', help='Enable CVE vulnerability lookup via NVD API')
    cve_group.add_argument('--nvd-api-key', type=str, help='NVD API key (or set NVD_API_KEY env variable)')
    cve_group.add_argument('--cve-max-age', type=int, default=365, help='Only lookup CVEs from last N days (default: 365)')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("\n" + "!" * 80)
    print("WARNING: AUTHORIZED SCANNING ONLY")
    print("!" * 80)
    print("Only scan systems you own or have explicit written authorization to test.")
    print("!" * 80 + "\n")

    pipeline = ReconPipeline(
        targets_file=args.targets,
        output_dir=args.output,
        skip_masscan=args.skip_masscan,
        skip_nmap=args.skip_nmap,
        skip_harvester=args.skip_harvester,
        no_sudo=args.no_sudo,
        cve_lookup=args.cve_lookup,
        nvd_api_key=args.nvd_api_key,
        cve_max_age=args.cve_max_age
    )

    try:
        pipeline.run()
    except KeyboardInterrupt:
        logger.warning("\n\nPipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

