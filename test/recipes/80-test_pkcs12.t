#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

use Encode;

setup("test_pkcs12");

plan skip_all => "The PKCS12 command line utility is not supported by this OpenSSL build"
    if disabled("des");

plan tests => 1;

my $pass = "σύνθημα γνώρισμα";

my $savedcp;
if (eval { require Win32::Console; 1; }) {
    # Trouble is that Win32 perl uses CreateProcessA, which
    # makes it problematic to pass non-ASCII arguments. The only
    # feasible option is to pick one language, set corresponding
    # code page and reencode the problematic string...

    $savedcp = Win32::Console::OutputCP();
    Win32::Console::OutputCP(1253);
    $pass = Encode::encode("cp1253",Encode::decode("utf-8",$pass));
} else {
    # Running MinGW tests transparenly under Wine apparently requires
    # UTF-8 locale...

    foreach(`locale -a`) {
        s/\R$//;
        if ($_ =~ m/^C\.UTF\-?8/i) {
            $ENV{LC_ALL} = $_;
            last;
        }
    }
}

# just see that we can read shibboleth.pfx protected with $pass
ok(run(app(["openssl", "pkcs12", "-noout",
            "-password", "pass:$pass",
            "-in", srctop_file("test", "shibboleth.pfx")])),
   "test_pkcs12");

Win32::Console::OutputCP($savedcp) if (defined($savedcp));
