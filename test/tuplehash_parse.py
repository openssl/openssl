#!/usr/bin/env python
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# A python program written to parse (version 42) of the ACVP test vectors for
# ML_KEM. The 2 files that can be processed by this utility can be downloaded
# from
#  https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
#  https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
# and output from this utility to
#  test/recipes/30-test_evp_data/evppkey_ml_kem_keygen.txt
#  test/recipes/30-test_evp_data/evppkey_ml_kem_encapdecap.txt
#
# e.g. python3 mlkem_parse.py ~/Downloads/keygen.json > ./test/recipes/30-test_evp_data/evppkey_ml_kem_keygen.txt
#
import json
import argparse
import datetime
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_label(label, value):
    print(label + " = " + value)

def print_hexlabel(label, tag, value):
    print(label + " = hex" + tag + ":" + value)

def print_hexBytes(label, hexStr): 
    print("static const uint8_t " + label + "[]= {", end='')

    hx = bytes.fromhex(hexStr)
    i = 0
    cols = 16
    indent = 4
    spacing = 1
    for b in hx:
        if i % cols == 0:
            print("\n{indent}".format(indent=' ' * indent), end='')
        else:
            print(' ' * spacing, end='')
        print('0x{:02x},'.format(b), end='')
        i += 1
    print("\n};")

def parse_tuple_aft(algorithm, groups):
    table_str = "static const TUPLEHASH_TEST tuplehash[] = {\n"
    for grp in groups:
        if grp["testType"] != "AFT":
            continue
        xof = grp['xof']
        for tst in grp['tests']:
            name = "tuplehash_test_" + str(tst['tcId'])
            nm_output = name + "_expected"
            print_hexBytes(nm_output, tst['md'])
            tuple_str = "static TUPLE " + name + "[] = {\n"
            count = 0
            for tuple in tst['tuple']:
                nm_tuple = name + "_tuple_" + str(count)
                if (tuple != ""):
                    print_hexBytes(nm_tuple, tuple)
                    tuple_str += "    { " + nm_tuple + ", " + str(len(tuple)>>1) + " },\n"
                else:
                    tuple_str += "    { NULL, 0 },\n"
                count += 1
            tuple_str += "};\n"

            print(tuple_str)

            table_str += "    {\n"
            table_str += "        \"" + algorithm + "\",\n"
            table_str += "        " + name + ", " + str(count) + ",\n"
            table_str += "        \"" + tst['customization'] + "\",\n"
            table_str += "        " + nm_output + ", " + str(len(tst['md'])>>1) + ",\n"
            table_str += "        "
            if xof:
                table_str += "1\n"
            else:
                table_str += "0\n"
            table_str += "    },\n"

    table_str += "};\n"
    print(table_str)

parser = argparse.ArgumentParser(description="")
parser.add_argument('filename', type=str)
args = parser.parse_args()

# Open and read the JSON file
with open(args.filename, 'r') as file:
    data = json.load(file)

year = datetime.date.today().year
version = data['vsId']
algorithm = data['algorithm']
revision = data['revision']

print("/*")
print(" * Copyright " + str(year) + " The OpenSSL Project Authors. All Rights Reserved.")
print(" *")
print(" * Licensed under the Apache License 2.0 (the \"License\").  You may not use")
print(" * this file except in compliance with the License.  You can obtain a copy")
print(" * in the file LICENSE in the source distribution or at")
print(" * https://www.openssl.org/source/license.html\n")
print(" * ACVP test data for " + algorithm + " generated from")
print(" * https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/"
      + algorithm + "/internalProjection.json")
print(" * [version " + str(version) + "]")
print(" * [revision " + str(revision) + "]")
print("*/")

print("")
print("typedef struct tuple_st {")
print("    const uint8_t *in;")
print("    size_t inlen;")
print("} TUPLE;")
print("")
print("typedef struct tuplehash_test_st {")
print("    char *alg;")
print("    TUPLE *tuples;")
print("    int num_tuples;")
print("    char *custom;")
print("    const uint8_t *out;")
print("    size_t outlen;")
print("    int xof;")
print("} TUPLEHASH_TEST;")

parse_tuple_aft(algorithm, data['testGroups'])
