#!/usr/bin/env python3

import argparse
import sys
from tabulate import tabulate
import yaml
import os

config = {}
with open('generate.yml', mode='r', encoding='utf-8') as f:
    config = yaml.safe_load(f.read())

parser = argparse.ArgumentParser()
parser.add_argument('--liboqs-docs-dir', dest="liboqs_docs_dir", required=True)
args = parser.parse_args()

######################################
# Generate Signature Information Table
######################################

liboqs_sig_docs_dir = os.path.join(args.liboqs_docs_dir, 'algorithms', 'sig')
sig_to_impl_version = {}
for root, _, files in os.walk(liboqs_sig_docs_dir):
    for fil in files:
        with open(os.path.join(root, fil), mode='r', encoding='utf-8') as f:
            alg_pretty_name = next(f).rstrip()
            for line in f:
                if line.startswith("- **Version**:"):
                    sig_to_impl_version[alg_pretty_name] = line.split(":")[1].rstrip()
                    break

table = [['Algorithm', 'Implementation Version',
          'Claimed NIST Level', 'Code Point', 'OID']]
claimed_nist_level = 0
for sig in sorted(config['sigs'][1:], key=lambda s: s['family']):
    for variant in sig['variants']:
        if variant['security'] == 128:
            claimed_nist_level = 1
        elif variant['security'] == 192:
            claimed_nist_level = 3
        elif variant['security'] == 256:
            claimed_nist_level = 5
        else:
            sys.exit("variant['security'] value malformed.")

        if sig['family'].startswith('SPHINCS'):
            sig['family'] = 'SPHINCS+'

        table.append([variant['name'], sig_to_impl_version[sig['family']],
                      claimed_nist_level, variant['code_point'],
                      variant['oid']])

        for hybrid in variant['mix_with']:
            table.append([variant['name'] + ' **hybrid with** ' + hybrid['name'],
                          sig_to_impl_version[sig['family']],
                          claimed_nist_level,
                          hybrid['code_point'],
                          hybrid['oid']])

with open('oqs-sig-info.md', mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))

##################################
# Generate KEM Information Table
##################################

liboqs_kem_docs_dir = os.path.join(args.liboqs_docs_dir, 'algorithms', 'kem')
kem_to_impl_version = {}
for root, _, files in os.walk(liboqs_kem_docs_dir):
    for fil in files:
        with open(os.path.join(root, fil), mode='r', encoding='utf-8') as f:
            alg_pretty_name = next(f).rstrip()
            for line in f:
                if line.startswith("- **Version**:"):
                    kem_to_impl_version[alg_pretty_name] = line.split(":")[1].rstrip()
                    break
kem_to_impl_version['SIDH'] = kem_to_impl_version['SIKE']

table = [['Family', 'Implementation Version', 'Variant', 'Claimed NIST Level',
           'PQ-only Code Point', 'Hybrid Elliptic Curve', 'Hybrid Code Point']]
hybrid_elliptic_curve = ''
for kem in sorted(config['kems'], key=lambda k: k['family']):
    if kem['bit_security'] == 128:
        claimed_nist_level = 1
        hybrid_elliptic_curve = 'secp256_r1'
    elif kem['bit_security'] == 192:
        claimed_nist_level = 3
        hybrid_elliptic_curve = 'secp384_r1'
    elif kem['bit_security'] == 256:
        claimed_nist_level = 5
        hybrid_elliptic_curve = 'secp521_r1'
    else:
        sys.exit("kem['bit_security'] value malformed.")

    if kem['name_group'] == 'kyber512':
        table.append([kem['family'], kem_to_impl_version[kem['family']],
                      kem['name_group'], claimed_nist_level, kem['nid'],
                      'x25519', '0x2F26'])
    elif kem['name_group'] == 'sikep434':
        table.append([kem['family'], kem_to_impl_version[kem['family']],
                      kem['name_group'], claimed_nist_level, kem['nid'],
                      'x25519', '0x2F27'])
    elif kem['name_group'] == 'bike1l1fo':
        table.append([kem['family'], kem_to_impl_version[kem['family']],
                      kem['name_group'], claimed_nist_level, kem['nid'],
                      'x25519', '0x2F28'])

    table.append([kem['family'], kem_to_impl_version[kem['family']],
                  kem['name_group'], claimed_nist_level, kem['nid'],
                  hybrid_elliptic_curve, kem['nid_hybrid']])

with open('oqs-kem-info.md', mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))
