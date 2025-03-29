import argparse
import logging
import json
import yaml
import pandas as pd
import os
import sys


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Audits system configurations against security best practices.")
    parser.add_argument("config_file", help="Path to the configuration file (YAML or JSON).")
    parser.add_argument("system_config_file", help="Path to the system configuration file to audit (e.g., SSH config).")
    parser.add_argument("-o", "--output", help="Path to the output file (CSV). If not specified, prints to console.", required=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.", required=False)
    return parser


def load_config(config_file):
    """
    Loads the configuration from a YAML or JSON file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: The configuration dictionary.
    Raises:
        FileNotFoundError: If the configuration file does not exist.
        ValueError: If the configuration file is not valid YAML or JSON.
    """
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    try:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                config = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                config = json.load(f)
            else:
                raise ValueError("Unsupported configuration file format. Use YAML or JSON.")
        return config
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        raise ValueError(f"Error loading configuration file: {e}")


def load_system_config(system_config_file):
     """
     Loads the system configuration from a file.  This is a placeholder.
     More complex parsing logic would be needed based on the file type.
     Args:
         system_config_file (str): Path to the system config file.
     Returns:
         dict:  A dictionary representation of the system configuration.
     Raises:
        FileNotFoundError: If the system config file does not exist.
        Exception: If the system config file cannot be loaded.
     """
     if not os.path.exists(system_config_file):
        raise FileNotFoundError(f"System configuration file not found: {system_config_file}")
     try:
          with open(system_config_file, 'r') as f:
               config_data = f.readlines()  #Read by line for now.
          return config_data  # return list of lines
     except Exception as e:
        raise Exception(f"Error loading system configuration file: {e}")

def audit_configuration(config, system_config_data):
    """
    Audits the system configuration against the rules defined in the configuration file.

    Args:
        config (dict): The configuration dictionary containing audit rules.
        system_config_data (list): System configuration as a list of strings.

    Returns:
        pandas.DataFrame: A DataFrame containing the audit results.
    """
    results = []
    for rule in config['rules']:
        rule_id = rule['id']
        description = rule['description']
        check = rule['check'] # Text to search for.
        severity = rule['severity']

        found = False
        for line in system_config_data:
            if check in line:
                found = True
                break

        result = {
            'id': rule_id,
            'description': description,
            'check': check,
            'severity': severity,
            'status': 'PASS' if found else 'FAIL'
        }
        results.append(result)

    df = pd.DataFrame(results)
    return df

def main():
    """
    Main function to execute the configuration auditor.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = load_config(args.config_file)
        system_config_data = load_system_config(args.system_config_file)
        audit_results = audit_configuration(config, system_config_data)

        if args.output:
            audit_results.to_csv(args.output, index=False)
            logging.info(f"Audit results saved to: {args.output}")
        else:
            print(audit_results.to_string())
            logging.info("Audit results printed to console.")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # Create example config file (config.yaml):
    # rules:
    #   - id: SSH-001
    #     description: "Check if PermitRootLogin is disabled"
    #     check: "PermitRootLogin no"
    #     severity: "High"
    #   - id: SSH-002
    #     description: "Check if PasswordAuthentication is disabled"
    #     check: "PasswordAuthentication no"
    #     severity: "High"
    #
    # Create example sshd_config file (sshd_config):
    # PermitRootLogin no
    # PasswordAuthentication no
    # Port 22
    #
    # Run the script:
    # python main.py config.yaml sshd_config -o audit_report.csv
    # Or
    # python main.py config.yaml sshd_config

    main()