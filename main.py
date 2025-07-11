import argparse
import logging
import json
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
    Aggregates vulnerability data from multiple sources (NVD, ExploitDB) based on CVE ID.
    Args:
        cve_id (str): The CVE ID to search for.
    Returns:
        dict: A dictionary containing aggregated vulnerability information.
    """
    aggregated_data = {}
    try:
        # NVD Data
        nvd_url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
        response = requests.get(nvd_url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        nvd_data = response.json()
        if nvd_data and nvd_data['totalResults'] > 0:  # Check if results are present
            aggregated_data['nvd'] = nvd_data['result']['CVE_Items'][0]  # Access the actual result
        else:
            logging.warning(f"No data found in NVD for CVE: {cve_id}")
            aggregated_data['nvd'] = None  # Ensure the field is present even if empty


        # ExploitDB Data (Scraping) - Limited and subject to change
        exploitdb_url = f"{EXPLOITDB_BASE_URL}?ghdb=&desc={cve_id}&author=&platform=0&port=&type=0&osvdb=&cve="  # Updated URL
        try:
            response = requests.get(exploitdb_url)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            soup = BeautifulSoup(response.content, 'html.parser')
            #Example of scraping: You might need to refine this based on ExploitDB's HTML structure
            #exploit_links = [a['href'] for a in soup.find_all('a', href=True) if 'exploit-db' in a['href']]
            #aggregated_data['exploitdb'] = exploit_links
            aggregated_data['exploitdb'] =  "ExploitDB scraping logic needs to be implemented, scraping is not guaranteed" # Placeholder

        except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching from ExploitDB: {e}")
                aggregated_data['exploitdb'] = None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data for CVE {cve_id}: {e}")
        return None  # Return None if there's an error getting the data


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
    except Exception as e:
        logging.error(f"Error saving attack paths to {output_file}: {e}")

def main():
    """
    Main function to execute the vulnerability attack path analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        vulnerability_data = load_vulnerability_report(args.vulnerability_report)
        network_topology = load_network_topology(args.topology_file)

        # Data aggregation (optional)
        if args.aggregate_data:
            # Assuming vulnerability_data has a 'cve' column
            if 'cve' not in vulnerability_data.columns:
                logging.error("CVE column missing in vulnerability report. Cannot perform data aggregation.")
            else:
                vulnerability_data['aggregated_data'] = vulnerability_data['cve'].apply(aggregate_vulnerability_data)


        attack_paths = analyze_attack_paths(vulnerability_data, network_topology, args.severity_threshold)

        if args.output_file:
            save_attack_paths(attack_paths, args.output_file)
        else:
            print(json.dumps(attack_paths, indent=4))  # Print to console if no output file specified

    except Exception as e:
        logging.error(f"An error occurred: {e}")

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