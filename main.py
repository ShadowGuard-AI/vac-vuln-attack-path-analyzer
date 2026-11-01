import argparse
import logging
import json
import sys
from pathlib import Path
import networkx as nx
import pandas as pd
import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants (e.g., API URLs, default values)
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0" # Adjusted for v2
EXPLOITDB_BASE_URL = "https://www.exploit-db.com/"
DEFAULT_SEVERITY_THRESHOLD = 7.0  # Consider only vulnerabilities with severity >= 7.0 by default

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Vulnerability Attack Path Analyzer")
    parser.add_argument("-v", "--vulnerability_report", required=True, help="Path to the vulnerability report JSON/CSV file.")
    parser.add_argument("-t", "--topology_file", required=True, help="Path to the network topology JSON file.")
    parser.add_argument("-s", "--severity_threshold", type=float, default=DEFAULT_SEVERITY_THRESHOLD,
                        help="Minimum severity score to consider (default: 7.0)")
    parser.add_argument("-o", "--output_file", help="Path to the output file (JSON format) for attack paths.")
    parser.add_argument("--aggregate_data", action="store_true", help="Aggregate vulnerability data from multiple sources (NVD, ExploitDB).")

    return parser

def load_vulnerability_report(file_path):
    """
    Loads the vulnerability report from a JSON or CSV file.
    Args:
        file_path (str): Path to the vulnerability report file.
    Returns:
        pandas.DataFrame: DataFrame containing the vulnerability data.
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is not supported.
    """
    try:
        if file_path.endswith('.json'):
            with open(file_path, 'r') as f:
                data = json.load(f)
            return pd.DataFrame(data)
        elif file_path.endswith('.csv'):
            return pd.read_csv(file_path)
        else:
            raise ValueError("Unsupported file format.  Supported formats are JSON and CSV.")
    except FileNotFoundError:
        logging.error(f"Vulnerability report file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from file {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading vulnerability report from {file_path}: {e}")
        raise

def load_network_topology(file_path):
    """
    Loads the network topology from a JSON file.
    Args:
        file_path (str): Path to the network topology JSON file.
    Returns:
        networkx.Graph: A NetworkX graph representing the network topology.
    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the JSON is invalid.
        Exception: For other errors during file loading or graph creation.
    """
    try:
        with open(file_path, 'r') as f:
            topology_data = json.load(f)

        # Assuming the JSON contains 'nodes' and 'edges' keys
        nodes = topology_data.get('nodes', [])
        edges = topology_data.get('edges', [])

        # The topology is undirected, so every path I report can be walked in
        # both directions. A one way segment in the real network, a firewall
        # rule or a unidirectional route, has no way to be expressed here.
        graph = nx.Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)
        return graph
    except FileNotFoundError:
        logging.error(f"Network topology file not found: {file_path}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from file {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading network topology from {file_path}: {e}")
        raise

def aggregate_vulnerability_data(cve_id):
    """
    Aggregates vulnerability data from NVD (API v2) and ExploitDB for a CVE ID.
    Parse failures for one source are contained and logged; they do not
    abort the run.
    """
    aggregated_data = {'nvd': None, 'exploitdb': []}
    try:
        response = requests.get(NVD_API_BASE_URL, params={"cveId": cve_id}, timeout=10)
        response.raise_for_status()
        nvd_data = response.json()
        vulns = nvd_data.get('vulnerabilities') or []
        if vulns:
            aggregated_data['nvd'] = vulns[0].get('cve')
        else:
            logging.warning(f"No data found in NVD for CVE: {cve_id}")
    except Exception as e:
        logging.error(f"Error fetching NVD data for CVE {cve_id}: {e}")
        aggregated_data['nvd'] = None
    try:
        response = requests.get(f"{EXPLOITDB_BASE_URL}search", params={"cve": cve_id}, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if '/exploits/' in href and href not in links:
                links.append(href)
        aggregated_data['exploitdb'] = links
    except Exception as e:
        logging.error(f"Error fetching ExploitDB data for CVE {cve_id}: {e}")
        aggregated_data['exploitdb'] = []
    return aggregated_data

def analyze_attack_paths(vulnerability_data, topology, severity_threshold):
    """
    Analyzes potential attack paths based on vulnerability data and network topology.
    Args:
        vulnerability_data (pandas.DataFrame): DataFrame containing vulnerability data.
        topology (networkx.Graph): NetworkX graph representing the network topology.
        severity_threshold (float): Minimum severity score to consider.
    Returns:
        dict: A dictionary containing the identified attack paths.
    """
    attack_paths = {}
    # Missing severity or node columns raise here, before any per path
    # handling exists, and main logs the error and still exits 0. The
    # threshold is the only use severity gets: path ranking below is
    # plain hop count, so a one hop path over a 7.0 node and a one hop
    # path over a 10.0 node are presented as equals.
    vulnerable_nodes = vulnerability_data[vulnerability_data['severity'] >= severity_threshold]['node'].unique()

    for start_node in vulnerable_nodes:
        attack_paths[start_node] = {}
        for target_node in topology.nodes:
            if start_node != target_node:
                try:
                    # Simple shortest path calculation
                    path = nx.shortest_path(topology, source=start_node, target=target_node)
                    attack_paths[start_node][target_node] = path
                except nx.NetworkXNoPath:
                    # None covers three different stories: no route exists, the start
                    # node is absent from the topology graph, or the search raised
                    # something else entirely and was logged a line above. The saved
                    # JSON keeps no trace of which one happened.
                    attack_paths[start_node][target_node] = None # No path found
                except Exception as e:
                    logging.error(f"Error finding path from {start_node} to {target_node}: {e}")
                    attack_paths[start_node][target_node] = None
    return attack_paths

def save_attack_paths(attack_paths, output_file):
    """
    Saves the identified attack paths to a JSON file.
    Args:
        attack_paths (dict): Dictionary containing the identified attack paths.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(attack_paths, f, indent=4)
        logging.info(f"Attack paths saved to: {output_file}")
        return True
    except Exception as e:
        logging.error(f"Error saving attack paths to {output_file}: {e}")
        return False

def main():
    parser = setup_argparse()
    args = parser.parse_args()

    if args.output_file:
        out_resolved = Path(args.output_file).resolve()
        for input_path in (args.vulnerability_report, args.topology_file):
            if out_resolved == Path(input_path).resolve():
                logging.error(f"Output file {args.output_file} resolves to an input file ({input_path}); refusing to overwrite it.")
                sys.exit(1)

    try:
        vulnerability_data = load_vulnerability_report(args.vulnerability_report)
        network_topology = load_network_topology(args.topology_file)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    missing = [c for c in ('severity', 'node') if c not in vulnerability_data.columns]
    if missing:
        logging.error(f"Vulnerability report is missing required column(s): {', '.join(missing)}. No analysis was performed.")
        sys.exit(1)
    if vulnerability_data.empty:
        logging.error("Vulnerability report is empty. No analysis was performed.")
        sys.exit(1)

    aggregated_by_cve = {}
    if args.aggregate_data:
        if 'cve' not in vulnerability_data.columns:
            logging.error("CVE column missing in vulnerability report. Cannot perform data aggregation.")
            sys.exit(1)
        for cve_id in vulnerability_data['cve'].dropna().unique():
            try:
                aggregated_by_cve[str(cve_id)] = aggregate_vulnerability_data(str(cve_id))
            except Exception as e:
                logging.error(f"Aggregation failed for CVE {cve_id}: {e}")
                aggregated_by_cve[str(cve_id)] = {'nvd': None, 'exploitdb': []}

    try:
        attack_paths = analyze_attack_paths(vulnerability_data, network_topology, args.severity_threshold)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    if not attack_paths:
        print(f"No vulnerabilities qualified at or above the severity threshold {args.severity_threshold}; no attack paths were produced.")
        sys.exit(1)

    result = attack_paths
    if args.aggregate_data:
        result = {"attack_paths": attack_paths, "aggregated_data": aggregated_by_cve}

    if args.output_file:
        if not save_attack_paths(result, args.output_file):
            sys.exit(1)
    else:
        print(json.dumps(result, indent=4, default=str))

if __name__ == "__main__":
    main()

# Example Usage (saved for reference):
# 1. Create sample vulnerability_report.json:
#    ```json
#    [
#      {"node": "server1", "cve": "CVE-2023-1234", "severity": 7.5},
#      {"node": "server2", "cve": "CVE-2023-5678", "severity": 6.2},
#      {"node": "workstation1", "cve": "CVE-2023-9012", "severity": 8.0}
#    ]
#    ```
# 2. Create sample network_topology.json:
#    ```json
#    {
#      "nodes": ["server1", "server2", "workstation1", "database"],
#      "edges": [["server1", "server2"], ["server2", "workstation1"], ["workstation1", "database"]]
#    }
#    ```
# 3. Run the script:
#    ```bash
#    python vac_vuln_attack_path_analyzer.py -v vulnerability_report.json -t network_topology.json -o attack_paths.json
#    ```
#    This will generate attack_paths.json containing the analyzed attack paths.
# 4. Run with severity threshold:
#   ```bash
#   python vac_vuln_attack_path_analyzer.py -v vulnerability_report.json -t network_topology.json -s 8.0 -o attack_paths.json
#   ```
#   This will only consider vulnerabilities with severity 8.0 or higher.
# 5. Run with data aggregation:
#   ```bash
#   python vac_vuln_attack_path_analyzer.py -v vulnerability_report.json -t network_topology.json --aggregate_data -o attack_paths.json
#   ```
#   This will attempt to aggregate vulnerability data from NVD and ExploitDB.