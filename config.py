"""
Configuration settings for the reconnaissance pipeline
"""

# Masscan Configuration
MASSCAN_CONFIG = {
    'ports': '1-1000',          # Port range to scan
    'rate': 1000,               # Packets per second (be careful with high values!)
    'wait': 10,                 # Seconds to wait for responses
}

# Nmap Configuration
NMAP_CONFIG = {
    'scan_type': '-sV',         # Service version detection
    'timing': '-T4',            # Aggressive timing, e.g, -T4
    'additional_flags': '-sC',     # Add custom flags here
    'timeout': 600,             # Timeout per host (seconds)
}

# theHarvester Configuration
HARVESTER_CONFIG = {
    'sources': 'all',  # Data sources (free ones)
    'limit': 500,               # Results per source
    'timeout': 300,             # Timeout per domain (seconds)
}

# Output Configuration
OUTPUT_CONFIG = {
    'directory': 'out',         # Default output directory
    'json_indent': 2,           # JSON formatting
    'csv_delimiter': ',',       # CSV delimiter
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',            # DEBUG, INFO, WARNING, ERROR
    'format': '%(asctime)s - %(levelname)s - %(message)s',
    'log_file': 'recon_pipeline.log',
}

# Safety Checks
SAFETY_CONFIG = {
    'max_targets': 1000,        # Maximum targets to prevent accidents
    'confirm_large_scans': True,  # Prompt for confirmation on large scans
    'backup_results': True,     # Keep backups of previous scans
}
