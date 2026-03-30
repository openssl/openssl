# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Parse ASCON-AEAD128 test vectors from Ascon-C reference format to OpenSSL format.
#
# Input format:
#    Count = N
#    Key = ...
#    Nonce = ...
#    PT = ...
#    AD = ...
#    CT = ... (Ciphertext + Tag concatenated, where Tag is the last 16 bytes)
#    Result = ... (optional; "valid ..." or "invalid ...")
#
# Output format:
#     # <Result text> (if Result was present)
#     Cipher = ascon-aead128
#     Key = ...
#     IV = ...
#     Plaintext = ...
#     AAD = ...
#     Tag = ... (last 16 bytes of CT)
#     Ciphertext = ... (CT without the last 16 bytes)
#     Result = TAG_VALUE_MISMATCH (only if Result started with "invalid")

import hashlib
import os
import re
import sys


def parse_hex_field(value):
    """Parse a hex field value, handling empty strings."""
    if not value or value.strip() == '':
        return ''
    # Remove any whitespace
    return value.strip().upper()


def hex_to_bytes(hex_str):
    """Convert hex string to bytes."""
    if not hex_str:
        return b''
    return bytes.fromhex(hex_str)


def bytes_to_hex(byte_data):
    """Convert bytes to hex string (uppercase, no spaces)."""
    if not byte_data:
        return ''
    return byte_data.hex().upper()


def parse_test_vectors(input_file):
    """Parse test vectors from the input file."""
    vectors = []
    current_vector = {}

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines (but empty lines end a vector)
            if line.startswith('#'):
                continue

            if not line:
                # Empty line ends current vector
                if current_vector:
                    vectors.append(current_vector)
                    current_vector = {}
                continue

            # Parse key-value pairs
            match = re.match(r'(\w+)\s*=\s*(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()

                if key == 'Count':
                    # Start of new vector
                    if current_vector:
                        vectors.append(current_vector)
                    current_vector = {}
                elif key == 'Key':
                    current_vector['Key'] = parse_hex_field(value)
                elif key == 'Nonce':
                    current_vector['Nonce'] = parse_hex_field(value)
                elif key == 'PT':
                    current_vector['PT'] = parse_hex_field(value)
                elif key == 'AD':
                    current_vector['AD'] = parse_hex_field(value)
                elif key == 'CT':
                    current_vector['CT'] = parse_hex_field(value)
                elif key == 'Result':
                    current_vector['Result'] = value

    # Don't forget the last vector if file doesn't end with blank line
    if current_vector:
        vectors.append(current_vector)

    return vectors


def format_output(vectors, input_file):
    """Format vectors in the output format."""
    output_lines = []

    # Header: sha256 digest and source filename
    with open(input_file, 'rb') as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    basename = os.path.basename(input_file)
    output_lines.append(f"# {digest}")
    output_lines.append(f"Title = {basename}")
    output_lines.append("")

    for vec in vectors:
        # Get fields with defaults
        key = vec.get('Key', '')
        nonce = vec.get('Nonce', '')
        pt = vec.get('PT', '')
        ad = vec.get('AD', '')
        ct = vec.get('CT', '')
        result = vec.get('Result', '')

        # Split CT into Ciphertext (all but last 16 bytes) and Tag (last 16 bytes)
        ct_bytes = hex_to_bytes(ct)

        if len(ct_bytes) >= 16:
            # Tag is the last 16 bytes
            tag_bytes = ct_bytes[-16:]
            ciphertext_bytes = ct_bytes[:-16]
        else:
            # If CT is less than 16 bytes, it's all ciphertext, tag is empty
            tag_bytes = b''
            ciphertext_bytes = ct_bytes

        tag_hex = bytes_to_hex(tag_bytes)
        ciphertext_hex = bytes_to_hex(ciphertext_bytes)

        # Emit comment from Result field if present
        if result:
            output_lines.append(f"# {result}")

        # Format output
        output_lines.append("Cipher = ascon-aead128")
        output_lines.append(f"Key = {key}")
        output_lines.append(f"IV = {nonce}")
        output_lines.append(f"Plaintext = {pt}")
        output_lines.append(f"AAD = {ad}")
        output_lines.append(f"Tag = {tag_hex}")
        output_lines.append(f"Ciphertext = {ciphertext_hex}")

        # Negative test: Result starts with "invalid"
        if result.lower().startswith('invalid'):
            if len(pt) != len(ciphertext_hex):
                output_lines.append("Result = VALUE_MISMATCH")
            else:
                output_lines.append("Result = TAG_VALUE_MISMATCH")

        output_lines.append("")  # Blank line between vectors

    # Footer: test count
    output_lines.append(f"# TestCount: {len(vectors)}")
    output_lines.append("")

    return '\n'.join(output_lines)


def write_to_file(output_file, vectors, input_file):
    """Write parsed vectors to the output file."""
    try:
        with open(output_file, 'w') as f:
            output = format_output(vectors, input_file)
            f.write(output)
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 ascon_aead128_parse.py <input_file> [output_file]", file=sys.stderr)
        print("  If output_file is provided, results will be appended to it.", file=sys.stderr)
        print("  Otherwise, results will be printed to stdout.", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else None

    try:
        vectors = parse_test_vectors(input_file)
        if output_file:
            write_to_file(output_file, vectors, input_file)
        else:
            output = format_output(vectors, input_file)
            print(output)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
