import os
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import argparse
import mimetypes
import zipfile
import tempfile


def verify_signature_in_file(input_file, verbose=False):
    try:
        # Check the file type
        mime_type, _ = mimetypes.guess_type(input_file)
        if mime_type is None:
            if verbose:
                print(f"'{input_file}' unknown. Skipping.")
            return

        # Supported file types
        supported_types = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.'
            'wordprocessingml.document'
        ]
        if mime_type not in supported_types:
            if verbose:
                print(f"'{input_file}' is not a supported.")
            return

        # Read the contents of the input file
        with open(input_file, 'rb') as file:
            file_contents = file.read()

        # Verify if the file has a digital signature
        if b'-----BEGIN RSA SIGNATURE-----' not in file_contents:
            if verbose:
                print(f"No digital signature found in '{input_file}'.")
            return

        # Split the file into data and signature parts
        data, signature = file_contents.split(b'-----BEGIN RSA SIGNATURE-----')

        # Load the public key
        public_key_file = os.path.splitext(input_file)[0] + ".pub"
        with open(public_key_file, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())

        # Verify the signature
        h = SHA256.new(data)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            if verbose:
                print(f"Digital signature in '{input_file}' is valid.")
        except (ValueError, TypeError):
            if verbose:
                print(f"Digital signature in '{input_file}' is invalid.")
            return

        # Create a JSON file with certificate information
        output_file = os.path.splitext(input_file)[0] + ".json"
        certificate_info = {
            "Signature Status": "Valid",
            "Public Key Size (bits)": public_key.size_in_bits(),
            "Signer's Name": public_key.export_key().decode('utf-8').splitlines()[0].strip(),
        }

        with open(output_file, 'w') as json_file:
            json.dump(certificate_info, json_file, indent=4)

        if verbose:
            print(f"Certificate information saved to '{output_file}'.")

    except Exception as e:
        print(f"Error: {e}")


def verify_signatures_in_archive(input_file, verbose=False):
    try:
        # Extract the contents of the archive to a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(input_file, 'r') as archive:
                archive.extractall(temp_dir)

            # Verify signatures in extracted files
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    verify_signature_in_file(file_path, verbose)

    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Verify digital signatures in supported document formats and generate JSON reports.")
    parser.add_argument("input_file", help="The input file to verify digital signatures (PDF, DOCX, or archive).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    input_file = args.input_file
    verbose = args.verbose

    # Check if it's an archive file
    if mimetypes.guess_type(input_file)[0] == 'application/zip':
        verify_signatures_in_archive(input_file, verbose)
    else:
        verify_signature_in_file(input_file, verbose)


if __name__ == "__main__":
    main()
