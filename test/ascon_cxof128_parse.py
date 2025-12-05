#!/usr/bin/env python3
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Parse ASCON-CXOF128 test vectors from reference format to OpenSSL format.
# 
# Input format:
#    Count = N
#    Msg = <hex>
#    Z = <hex>  (customization string)
#    MD = <hex>
# 
# Output format:
#    Digest = ASCON-CXOF128
#    Input = <hex>
#    Custom = <hex>
#    Output = <hex>

import re
import sys


def parse_hex_field(value):
    """Parse a hex field value, handling empty strings."""
    if not value or value.strip() == '':
        return ''
    # Remove any whitespace
    return value.strip().upper()


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
                elif key == 'Msg':
                    current_vector['Msg'] = parse_hex_field(value)
                elif key == 'Z':
                    current_vector['Z'] = parse_hex_field(value)
                elif key == 'MD':
                    current_vector['MD'] = parse_hex_field(value)
    
    # Don't forget the last vector if file doesn't end with blank line
    if current_vector:
        vectors.append(current_vector)
    
    return vectors


def format_output(vectors):
    """Format vectors in the OpenSSL test format."""
    output_lines = []
    
    for vec in vectors:
        # Get fields with defaults
        msg = vec.get('Msg', '')
        z = vec.get('Z', '')
        md = vec.get('MD', '')
        
        # Format output
        output_lines.append("Digest = ASCON-CXOF128")
        output_lines.append(f"Input = {msg}")
        output_lines.append(f"Custom = {z}")
        output_lines.append(f"Output = {md}")
        output_lines.append("")  # Blank line between vectors
    
    return '\n'.join(output_lines)


def append_to_file(output_file, vectors):
    """Append parsed vectors to the output file."""
    try:
        with open(output_file, 'a') as f:
            output = format_output(vectors)
            f.write(output)
    except IOError as e:
        print(f"Error writing to file '{output_file}': {e}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 convert_ascon_cxof128.py <input_file> [output_file]", file=sys.stderr)
        print("  If output_file is provided, results will be appended to it.", file=sys.stderr)
        print("  Otherwise, results will be printed to stdout.", file=sys.stderr)
        print("  Default output_file: test/recipes/30-test_evp_data/evpmd_ascon_cxof128.txt", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else 'test/recipes/30-test_evp_data/evpmd_ascon_cxof128.txt'
    
    try:
        vectors = parse_test_vectors(input_file)
        if output_file:
            append_to_file(output_file, vectors)
            print(f"Appended {len(vectors)} test vectors to {output_file}", file=sys.stderr)
        else:
            output = format_output(vectors)
            print(output)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

