# A python program written to parse (version 42) of the ACVP test vectors for
# ML_DSA. The 3 files that can be processed by this utility can be downloaded
# from
#  https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
#  https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json
#  https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
# and output from this utility to
#  test/recipes/30-test_evp_data/evppkey_ml_dsa_keygen.txt
#  test/recipes/30-test_evp_data/evppkey_ml_dsa_siggen.txt
#  test/recipes/30-test_evp_data/evppkey_ml_dsa_sigver.txt
#
# e.g. python3 mldsa_parse.py ~/Downloads/keygen.json > ./test/recipes/30-test_evp_data/evppkey_ml_dsa_keygen.txt
#
import json
import argparse
import datetime

def print_label(label, value):
    print(label + " = " + value)

def print_hexlabel(label, tag, value):
    print(label + " = hex" + tag + ":" + value)

def parse_ml_dsa_key_gen(groups):
    for grp in groups:
        for tst in grp['tests']:
            print_label("\nKeyGen", grp['parameterSet'])
            print_label("KeyName", "tcId" + str(tst['tcId']))
            print_hexlabel("Ctrl", "seed", tst['seed'])
            print_hexlabel("CtrlOut", "pub", tst['pk'])
            print_hexlabel("CtrlOut", "priv", tst['sk'])

def parse_ml_dsa_sig_gen(groups):
    for grp in groups:
        deter = grp['deterministic'] # Boolean
        externalMu = grp["externalMu"] # Boolean
        signInterfaceExternal = (grp['signatureInterface'] == "External")
        signPure = (grp['preHash'] == "pure")

        if externalMu or not signPure:
            continue

        name = grp['parameterSet'].replace('-', '_')
        for tst in grp['tests']:
            testname = name + "_" + str(tst['tcId'])
            print_label("\nPrivateKeyRaw", testname + ":" + grp['parameterSet'] + ":" + tst['sk'])
            print_label("\nSign-Message", grp['parameterSet'] + ":" + testname)
            print_label("Input", tst['message'])
            print_label("Output", tst['signature'])
            print_label("Ctrl", "message-encoding:1")
            print_label("Ctrl", "hexcontext-string:" + tst["context"])
            print_label("Ctrl", "deterministic:" + ("1" if deter else "0"))
            if not deter:
                print_label("Ctrl", "hextest-entropy:" + tst["rnd"])

def parse_ml_dsa_sig_ver(groups):
    for grp in groups:
        externalMu = grp["externalMu"] # Boolean
        signInterfaceExternal = (grp['signatureInterface'] == "External")
        signPure = (grp['preHash'] == "pure")

        if externalMu or not signPure:
            continue

        name = grp['parameterSet'].replace('-', '_')
        for tst in grp['tests']:
            testname = name + "_" + str(tst['tcId'])
            print_label("\nPublicKeyRaw", testname + ":" + grp['parameterSet'] + ":" + tst['pk'] + "\n")
            if "reason" in tst:
                print("# " + tst['reason'])
            print_label("Verify-Message-Public", grp['parameterSet'] + ":" + testname)
            print_label("Input", tst['message'])
            print_label("Output", tst['signature'])
            print_label("Ctrl", "message-encoding:1")
            print_label("Ctrl", "hexcontext-string:" + tst["context"])
            if not tst['testPassed']:
                print_label("Result", "VERIFY_ERROR")

parser = argparse.ArgumentParser(description="")
parser.add_argument('filename', type=str)
args = parser.parse_args()

# Open and read the JSON file
with open(args.filename, 'r') as file:
    data = json.load(file)

year = datetime.date.today().year
version = data['vsId']
algorithm = data['algorithm']
mode = data['mode']

print("# Copyright " + str(year) + " The OpenSSL Project Authors. All Rights Reserved.")
print("#")
print("# Licensed under the Apache License 2.0 (the \"License\").  You may not use")
print("# this file except in compliance with the License.  You can obtain a copy")
print("# in the file LICENSE in the source distribution or at")
print("# https://www.openssl.org/source/license.html\n")
print("# ACVP test data for " + algorithm + " " + mode + " generated from")
print("# https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/"
      "ML-DSA-" + mode + "-FIPS204/internalProjection.json")
print("# [version " + str(version) + "]")

if algorithm == "ML-DSA":
    if mode == 'sigVer':
        parse_ml_dsa_sig_ver(data['testGroups'])
    elif mode == 'sigGen':
        parse_ml_dsa_sig_gen(data['testGroups'])
    elif mode == 'keyGen':
        parse_ml_dsa_key_gen(data['testGroups'])
    else:
        print("Unsupported mode " + mode)
else:
    print("Unsupported algorithm " + algorithm)
