#! /usr/bin/env perl
# Copyright OpenSSL 2007-2018
# Copyright Nokia 2007-2018
# Copyright Siemens AG 2015-2018
#
# Contents licensed under the terms of the OpenSSL license
# See https://www.openssl.org/source/license.html for details
#
# SPDX-License-Identifier: OpenSSL
#
# CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_cmp_ctx");

simple_test("test_cmp_ctx", "cmp_ctx_test", "cmp_ctx");
