#! /usr/bin/env perl
# Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# modify the '#!/usr/local/bin/perl'
# line in all scripts that rely on perl.

require "find.pl";

$#ARGV == 0 || print STDERR "usage: perlpath newpath  (eg /usr/bin)\n";
&find(".");

sub wanted
	{
	return unless /\.pl$/ || /^[Cc]onfigur/;

	open(IN,"<$_") || die "unable to open $dir/$_:$!\n";
	@a=<IN>;
	close(IN);

	if (-d $ARGV[0]) {
		$a[0]="#!$ARGV[0]/perl\n";
	}
	else {
		$a[0]="#!$ARGV[0]\n";
	}

	# Playing it safe...
	$new="$_.new";
	open(OUT,">$new") || die "unable to open $dir/$new:$!\n";
	print OUT @a;
	close(OUT);

	rename($new,$_) || die "unable to rename $dir/$new:$!\n";
	chmod(0755,$_) || die "unable to chmod $dir/$new:$!\n";
	}
