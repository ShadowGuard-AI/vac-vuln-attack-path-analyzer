# vac-vuln-attack-path-analyzer
Takes a vulnerability report and network topology as input and identifies potential attack paths. It simulates possible exploits and highlights critical assets reachable from vulnerable entry points, showing the blast radius of each vulnerability. It uses a simplified graph traversal algorithm to find paths. - Focused on Aggregates vulnerability data from multiple sources (e.g., NVD, ExploitDB, custom APIs) and correlates them based on common identifiers (e.g., CVE, CWE). Provides a consolidated view of potential vulnerabilities, prioritizing based on severity and exploit availability. Enables users to rapidly assess their exposure landscape.

## Install
`git clone https://github.com/ShadowGuardAI/vac-vuln-attack-path-analyzer`

## Usage
`./vac-vuln-attack-path-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Path to the vulnerability report JSON/CSV file.
- `-t`: Path to the network topology JSON file.
- `-s`: No description provided
- `-o`: No description provided
- `--aggregate_data`: No description provided

## License
Copyright (c) ShadowGuardAI
