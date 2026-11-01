# vac-vuln-attack-path-analyzer

Takes a vulnerability report (JSON or CSV) and a network topology (JSON) as input. It keeps the report rows at or above a severity threshold and, for each kept node, records the unweighted shortest path in the topology graph to every other node, or None where no path exists. With `--aggregate_data`, it also fetches the NVD API v2 record for each report CVE and lists exploit links found on the ExploitDB search page for that CVE, and includes that data in the output next to the attack paths. It does not simulate exploits, compute a blast radius, correlate sources, or rank the paths.

A run that cannot read its inputs, finds a report missing the severity or node columns, or cannot write its output exits non-zero. A threshold that excludes every vulnerability prints a message saying no vulnerabilities qualified and exits non-zero.

## Install
`git clone https://github.com/ShadowGuard-AI/vac-vuln-attack-path-analyzer`

## Usage
`python main.py -v vulnerability_report.json -t network_topology.json -o attack_paths.json`

## Parameters
- `-h`: Show help message and exit
- `-v`: Path to the vulnerability report JSON/CSV file.
- `-t`: Path to the network topology JSON file.
- `-s`: Minimum severity score to consider (default: 7.0)
- `-o`: Path to the output file (JSON format) for attack paths. It must not resolve to either input file.
- `--aggregate_data`: Aggregate vulnerability data from NVD and ExploitDB.

## License
Copyright (c) ShadowGuard-AI
