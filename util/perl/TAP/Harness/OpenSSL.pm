# Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package TAP::Harness::OpenSSL;

# A TAP::Harness subclass that simply ensures that the OpenSSL TAP
# parser (TAP::Parser::OpenSSL) is used.  See that module for what it
# provides.
#
# This used to live inline in test/run_tests.pl; it now stands alone so
# it can be used with a plain 'prove' invocation.

use strict;
use warnings;

use parent -norequire, 'TAP::Harness';
require TAP::Harness;

use TAP::Parser::OpenSSL;

sub new {
    my $class = shift;
    my $args = shift;

    $args->{parser_class} = 'TAP::Parser::OpenSSL';
    return $class->SUPER::new($args);
}

1;
