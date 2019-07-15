#!/usr/bin/env python3

import copy
import glob
import jinja2
import os
import shutil
import subprocess
import yaml

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def replacer(filename, instructions, delimiter):
    fragments = glob.glob(os.path.join('oqs_template', filename, '*.fragment'))
    contents = file_get_contents(filename)
    for fragment in fragments:
        template = file_get_contents(fragment)
        identifier = os.path.splitext(os.path.basename(fragment))[0]
        identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())
        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())
        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]
        contents = preamble + identifier_start + jinja2.Template(template).render({'config': config}) + postamble
    file_put_contents(filename, contents)

def load_config():
    config = file_get_contents(os.path.join('oqs_template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    return config

config = load_config()

replacer('apps/s_cb.c', config, '/////')
replacer('ssl/ssl_locl.h', config, '/////')
replacer('ssl/ssl_oqs_extra.h', config, '/////')
replacer('ssl/t1_lib.c', config, '/////')
replacer('ssl/t1_trce.c', config, '/////')
