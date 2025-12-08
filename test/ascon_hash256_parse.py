#!/usr/bin/env python3
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Parse ASCON-Hash256 test vectors from reference format to OpenSSL format.
# Input: Count = N, Msg = <hex>, MD = <hex>
# Output: Digest = ASCON-HASH256, Input = <hex>, Output = <hex>

import re
import sys


def parse_hex_field(value):
    return value.strip().upper() if value and value.strip() else ''


def parse_test_vectors(input_file):
    vectors = []
    current_vector = {}
    
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                if not line and current_vector:
                    vectors.append(current_vector)
                    current_vector = {}
                continue
            
            match = re.match(r'(\w+)\s*=\s*(.*)', line)
            if match:
                key, value = match.group(1).strip(), match.group(2).strip()
                if key == 'Count':
                    if current_vector:
                        vectors.append(current_vector)
                    current_vector = {}
                elif key == 'Msg':
                    current_vector['Msg'] = parse_hex_field(value)
                elif key == 'MD':
                    current_vector['MD'] = parse_hex_field(value)
    
    if current_vector:
        vectors.append(current_vector)
    return vectors


def format_output(vectors):
    output_lines = []
    for vec in vectors:
        output_lines.append("Digest = ASCON-HASH256")
        output_lines.append(f"Input = {vec.get('Msg', '')}")
        output_lines.append(f"Output = {vec.get('MD', '')}")
        output_lines.append("")
    return '\n'.join(output_lines)


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 ascon_hash256_parse.py <input_file> [output_file]", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else 'test/recipes/30-test_evp_data/evpmd_ascon_hash256.txt'
    
    try:
        vectors = parse_test_vectors(input_file)
        output = format_output(vectors)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(output)
            print(f"Appended {len(vectors)} test vectors to {output_file}", file=sys.stderr)
        else:
            print(output)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

