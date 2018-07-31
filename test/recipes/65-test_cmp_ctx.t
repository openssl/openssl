#! /usr/bin/env perl
# Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
# Copyright Nokia 2007-2018
# Copyright Siemens AG 2015-2018
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_cmp_ctx");

simple_test("test_cmp_ctx", "cmp_ctx_test", "cmp_ctx");
