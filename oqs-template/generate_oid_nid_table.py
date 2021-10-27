#!/usr/bin/env python3

import argparse
import sys
from tabulate import tabulate
import yaml
import os

import generatehelpers

config = {}

def gen_sig_table(oqslibdocdir):
  liboqs_sig_docs_dir = os.path.join(oqslibdocdir, 'algorithms', 'sig')
  liboqs_sigs = {}
  for root, _, files in os.walk(liboqs_sig_docs_dir):
    for fil in files:
      if fil.endswith(".yml"):
        with open(os.path.join(root, fil), mode='r', encoding='utf-8') as f:
           algyml = yaml.safe_load(f.read())
        liboqs_sigs[algyml['name']]=algyml

  table = [['Algorithm', 'Implementation Version',
          'NIST round', 'Claimed NIST Level', 'Code Point', 'OID']]
  claimed_nist_level = 0
  for sig in sorted(config['sigs'], key=lambda s: s['family']):
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

        table.append([variant['name'], liboqs_sigs[sig['family']]['spec-version'],
                      liboqs_sigs[sig['family']]['nist-round'], claimed_nist_level, variant['code_point'],
                      variant['oid']])

        for hybrid in variant['mix_with']:
            table.append([variant['name'] + ' **hybrid with** ' + hybrid['name'],
                          liboqs_sigs[sig['family']]['spec-version'],
                          liboqs_sigs[sig['family']]['nist-round'],
                          claimed_nist_level,
                          hybrid['code_point'],
                          hybrid['oid']])

  with open(os.path.join('oqs-template', 'oqs-sig-info.md'), mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))
  print("Written oqs-sig-info.md")

def gen_kem_table(oqslibdocdir):
  liboqs_kem_docs_dir = os.path.join(oqslibdocdir, 'algorithms', 'kem')
  liboqs_kems = {}
  for root, _, files in os.walk(liboqs_kem_docs_dir):
    for fil in files:
      if fil.endswith(".yml"):
        with open(os.path.join(root, fil), mode='r', encoding='utf-8') as f:
           algyml = yaml.safe_load(f.read())
        liboqs_kems[algyml['name']]=algyml
  liboqs_kems['SIDH']=liboqs_kems['SIKE']
  # TODO: Workaround for wrong upstream name for Kyber:
  liboqs_kems['CRYSTALS-Kyber']=liboqs_kems['Kyber']

  table_header = ['Family', 'Implementation Version', 'Variant', 'NIST round', 'Claimed NIST Level',
           'Code Point', 'Hybrid Elliptic Curve (if any)']
  table = []
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
        
    if 'implementation_version' in kem:
        implementation_version = kem['implementation_version']
    else:
        implementation_version = liboqs_kems[kem['family']]['spec-version']

    try: 
       table.append([kem['family'], implementation_version,
                     kem['name_group'], liboqs_kems[kem['family']]['nist-round'], claimed_nist_level,
                     kem['nid'], ""])
       table.append([kem['family'], implementation_version,
                     kem['name_group'], liboqs_kems[kem['family']]['nist-round'], claimed_nist_level,
                     kem['nid_hybrid'], hybrid_elliptic_curve])
    except KeyError as ke:
       # Non-existant NIDs mean this alg is not supported any more
       pass

    if 'extra_nids' in kem:
        if 'current' in kem['extra_nids']: # assume "current" NIDs to mean liboqs-driven NIST round information:
            for entry in kem['extra_nids']['current']:
                table.append([kem['family'], implementation_version,
                              kem['name_group'], liboqs_kems[kem['family']]['nist-round'], claimed_nist_level,
                              entry['nid'], 
                              entry['hybrid_group'] if 'hybrid_group' in entry else ""])
        if 'old' in kem['extra_nids']: # assume "old" submissions to mean NIST round 2:
            for entry in kem['extra_nids']['old']:
                table.append([kem['family'], entry['implementation_version'],
                              kem['name_group'], 2, claimed_nist_level,
                              entry['nid'],
                              entry['hybrid_group'] if 'hybrid_group' in entry else ""])

  # sort by:  family, version, security level, variant, hybrid
  table.sort(key = lambda row: "{:s}|{:s}|{:d}|{:s}|{:s}".format(row[0], row[1], row[3], row[2], row[5]))

  table = [table_header] + table

  with open(os.path.join('oqs-template', 'oqs-kem-info.md'), mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))
    f.write("\n")
  print("Written oqs-kem-info.md")

# main:
with open(os.path.join('oqs-template', 'generate.yml'), mode='r', encoding='utf-8') as f:
    config = yaml.safe_load(f.read())

if 'LIBOQS_DOCS_DIR' not in os.environ:
   parser = argparse.ArgumentParser()
   parser.add_argument('--liboqs-docs-dir', dest="liboqs_docs_dir", required=True)
   args = parser.parse_args()
   oqsdocsdir = args.liboqs_docs_dir
else:
   oqsdocsdir = os.environ["LIBOQS_DOCS_DIR"]

config = generatehelpers.complete_config(config, oqsdocsdir)

gen_kem_table(oqsdocsdir)
gen_sig_table(oqsdocsdir)
