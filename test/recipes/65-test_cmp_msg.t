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
use OpenSSL::Test qw/:DEFAULT data_file/;

setup("test_cmp_msg");

plan tests => 1;

ok(run(test(["cmp_msg_test",
             data_file("server.crt"),
             data_file("pkcs10.der")])));
