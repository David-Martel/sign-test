import os
import sys
import json
import subprocess
import argparse

def check_file_for_signatures(input_file, verbose=False):
    try:
        # Use the "sigcheck" tool to check if the file has digital signatures
        result = subprocess.run(['sigcheck', '-e', input_file], capture_output=True, text=True, check=True)
        output = result.stdout

        # Parse the output to extract certificate information
        certificates = []
        lines = output.split('\n')
        for line in lines:
            if "Signers:" in line:
                signer_info = line.split(":")[1].strip()
                certificates.append(signer_info)

        # If no certificates found, exit
        if not certificates:
            if verbose:
                print("No digital signatures found in the file.")
            return

        # Create a JSON file with certificate information
        output_file = os.path.splitext(input_file)[0] + ".json"
        data = {"certificates": certificates}

        with open(output_file, 'w') as json_file:
            json.dump(data, json_file, indent=4)

        if verbose:
            print(f"Digital signatures found in '{input_file}'. Certificate information saved to '{output_file}'.")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Check for signatures and generate a JSON report."
    )
    parser.add_argument(
        "input_file", help="The file to check for signatures."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output."
    )

    args = parser.parse_args()

    input_file = args.input_file
    verbose = args.verbose

    check_file_for_signatures(input_file, verbose)


if __name__ == "__main__":
    main()

