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

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter, overwrite=False):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    if overwrite == True:
        source_file = os.path.join('oqs-template', filename, os.path.basename(filename)+ '.base')
        contents = file_get_contents(source_file)
    else:
        contents = file_get_contents(filename)

    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]

        if filename == 'README.md':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())
        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        if overwrite == True:
            contents = preamble + Jinja2.get_template(fragment).render({'config': config}) + postamble.replace(identifier_end + '\n', '')
        else:
            contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble

    file_put_contents(filename, contents)

def load_config(include_disabled_sigs=False):
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)

    # remove KEMs without NID (old stuff)
    newkems = []
    for kem in config['kems']:
        if 'nid' in kem:
           newkems.append(kem)
    config['kems']=newkems

    if include_disabled_sigs:
        return config
    for sig in config['sigs']:
        sig['variants'] = [variant for variant in sig['variants'] if variant['enable']]

    return config

config = load_config()

if len(sys.argv)>2: 
   # short term approach: iterate KEMs looking for OQS alg names: Argument needs to be v040 KEM KATS list
   # long term solution: Embed KEM KATs as arguments to generate.yml and compare against current liboqs KEM KATs
   kems={}
   v040kats=[]
   kats=[]
   for kem in config['kems']:
      with open(os.path.join('oqs', 'include', 'oqs', 'kem.h')) as fh:
        for line in fh:
            if line.startswith("#define "+kem['oqs_alg'] + " "):
                kem_name = line.split(' ')[2]
                kem_name = kem_name[1:-2]
                #print("SSL %s -> OQS: %s -> KAT name %s" % (kem['name_group'], kem['oqs_alg'], kem_name))
                kems[kem['name_group']] = kem_name
   with open(sys.argv[1], 'r') as fp:
      kats = json.load(fp)
   # temporary solution until generate.yml contains all KATs:
   with open(sys.argv[2], 'r') as fp:
      v040kats = json.load(fp)
   for k in kems.keys():
      try: 
         if v040kats[kems[k]] != kats[kems[k]]:
            print("Different KATs for %s: Code point update needed" % k)
      except KeyError as ke:
         print("No KAT for KEM %s: New code point needed" % (k))

# sigs
populate('crypto/asn1/standard_methods.h', config, '/////')
populate('crypto/ec/oqs_meth.c', config, '/////')
populate('crypto/evp/pmeth_lib.c', config, '/////')
populate('include/crypto/asn1.h', config, '/////')
populate('include/crypto/evp.h', config, '/////')
# We remove the delimiter comments from obj_mac.num
populate('crypto/objects/obj_mac.num', config, '#####', True)
populate('crypto/objects/obj_xref.txt', config, '#####')
populate('crypto/objects/objects.txt', config, '#####')
populate('crypto/x509/x509type.c', config, '/////')
populate('include/openssl/evp.h', config, '/////')
populate('ssl/ssl_cert_table.h', config, '/////')

# both
populate('apps/s_cb.c', config, '/////')
populate('ssl/ssl_local.h', config, '/////')
populate('ssl/t1_lib.c', config, '/////')
populate('ssl/t1_trce.c', config, '/////')
populate('oqs-test/common.py', config, '#####')
populate('oqs-interop-test/common.py', config, '#####')

config = load_config(include_disabled_sigs=True)
populate('README.md', config, '<!---')
