#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import yaml
import json
import sys

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def get_kem_nistlevel(alg, docsdir):
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if alg['family'] == 'CRYSTALS-Kyber': datasheetname = 'kyber'
    elif alg['family'] == 'SIDH': datasheetname = 'sike'
    elif alg['family'] == 'NTRU-Prime': datasheetname = 'ntruprime'
    else: datasheetname = alg['family'].lower()
    # load datasheet
    algymlfilename = os.path.join(docsdir, 'algorithms', 'kem', '{:s}.yml'.format(datasheetname))
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding='utf-8'))
    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace('_', '').replace('-', '')
        if 'FrodoKEM' in name: name = name.replace('FrodoKEM', 'Frodo')
        if 'Saber-KEM' in name: name = name.replace('-KEM', '')
        if '-90s' in name: name = name.replace('-90s', '').replace('Kyber', 'Kyber90s')
        if simplify(name) == simplify(alg['name_group']): return True
        return False
    # find the variant that matches
    for variant in algyml['parameter-sets']:
        if matches(variant['name'], alg):
            return variant['claimed-nist-level']
    return None

def get_sig_nistlevel(family, alg, docsdir):
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if family['family'] == 'CRYSTALS-Dilithium': datasheetname = 'dilithium'
    elif family['family'] == 'SPHINCS-Haraka': datasheetname = 'sphincs'
    elif family['family'] == 'SPHINCS-SHA256': datasheetname = 'sphincs'
    elif family['family'] == 'SPHINCS-SHAKE256': datasheetname = 'sphincs'
    else: datasheetname = family['family'].lower()
    # load datasheet
    algymlfilename = os.path.join(docsdir, 'algorithms', 'sig', '{:s}.yml'.format(datasheetname))
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding='utf-8'))
    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace('_', '').replace('-', '').replace('+', '')
        if simplify(name) == simplify(alg['name']): return True
        return False
    # find the variant that matches
    for variant in algyml['parameter-sets']:
        if matches(variant['name'], alg):
            return variant['claimed-nist-level']
    return None

def nist_to_bits(nistlevel):
   if nistlevel==1 or nistlevel==2:
      return 128
   elif nistlevel==3 or nistlevel==4:
      return 192
   elif nistlevel==5:
      return 256
   else: 
      return None

def complete_config(config, oqsdocsdir = None):
   if oqsdocsdir == None:
      if 'LIBOQS_DOCS_DIR' not in os.environ:
        print("Must include LIBOQS_DOCS_DIR in environment")
        exit(1)
      oqsdocsdir = os.environ["LIBOQS_DOCS_DIR"]
   for kem in config['kems']:
      if not "bit_security" in kem.keys():
         bits_level = nist_to_bits(get_kem_nistlevel(kem, oqsdocsdir))
         if bits_level == None: 
             print("Cannot find security level for {:s} {:s}".format(kem['family'], kem['name_group']))
             exit(1)
         kem['bit_security'] = bits_level
   for famsig in config['sigs']:
      for sig in famsig['variants']:
         if not "security" in sig.keys():
            bits_level = nist_to_bits(get_sig_nistlevel(famsig, sig, oqsdocsdir))
            if bits_level == None: 
                print("Cannot find security level for {:s} {:s}".format(famsig['family'], sig['name']))
                exit(1)
            sig['security'] = bits_level
   return config

