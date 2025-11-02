reconpipe/
├── run_recon.py              # Main orchestration script
├── tools/
│   ├── __init__.py
│   ├── masscan_wrapper.py    # Masscan execution & parsing
│   ├── nmap_wrapper.py       # Nmap execution & parsing
│   ├── harvester_wrapper.py  # theHarvester wrapper
│   └── aggregate.py          # Output aggregation
├── targets.txt               # Authorized targets
├── config.py                 # Configuration settings
├── requirements.txt
└── out/                      # Output directory (created at runtime)
    ├── masscan.json
    ├── nmap/
    ├── harvester/
    ├── inventory.json
    └── inventory.csv
```

### 2. **Implementation Strategy**

**Key Design Principles:**
- **Modular design**: Each tool gets its own wrapper module
- **Error handling**: Graceful failures if a tool isn't installed
- **Logging**: Track progress and errors
- **Parallel execution where safe**: Nmap can scan multiple hosts concurrently
- **Output parsing**: Use proper parsers (xmltodict for Nmap, json for Masscan)

### 3. **Workflow Logic**
```
1. Read targets from targets.txt
2. Run Masscan for fast host/port discovery
3. Parse Masscan results to get live hosts + open ports
4. Run Nmap on discovered hosts for detailed scanning
5. Run theHarvester on domain targets for OSINT
6. Aggregate all results into unified JSON/CSV inventory
