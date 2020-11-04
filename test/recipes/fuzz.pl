# Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;

sub fuzz_test {
	die "No arguments?" if scalar @_ == 0;
	die "Too many arguments" if scalar @_ > 1;

	my $f = $_[0];
	my @dir = glob(srctop_dir('fuzz', 'corpora', $f));

	subtest "Fuzzing $f" => sub {
		plan skip_all => "No directory fuzz/corpora/$f" unless @dir;
		plan tests => scalar @dir; # likely 1

		foreach (@dir) {
			ok(run(fuzz(["$f-test", $_])));
		}
	};
}

1;
