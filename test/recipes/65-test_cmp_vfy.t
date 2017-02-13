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

setup("test_cmp_vfy");

plan tests => 1;

ok(run(test(["cmp_vfy_test",
             data_file("server.crt"),     data_file("client.crt"),
             data_file("EndEntity1.crt"), data_file("EndEntity2.crt"),
             data_file("Root_CA.crt"),    data_file("Intermediate_CA.crt"),
             data_file("IR_protected.der"),
             data_file("IR_unprotected.der"),
             data_file("IP_waitingStatus_PBM.der")])));
