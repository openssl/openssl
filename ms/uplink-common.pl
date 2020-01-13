#! /usr/bin/env perl
# Copyright 2008-2016 The Opentls Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.opentls.org/source/license.html

# pull APPLINK_MAX value from applink.c...
$applink_c=$0;
$applink_c=~s|[^/\\]+$||g;
$applink_c.="applink.c";
open(INPUT,$applink_c) || die "can't open $applink_c: $!";
@max=grep {/APPLINK_MAX\s+(\d+)/} <INPUT>;
close(INPUT);
($#max==0) or die "can't find APPLINK_MAX in $applink_c";

$max[0]=~/APPLINK_MAX\s+(\d+)/;
$N=$1;	# number of entries in OPENtls_UplinkTable not including
	# OPENtls_UplinkTable[0], which contains this value...

1;

# Idea is to fill the OPENtls_UplinkTable with pointers to stubs
# which invoke 'void OPENtls_Uplink (ULONG_PTR *table,int index)';
# and then dereference themselves. Latter shall result in endless
# loop *unless* OPENtls_Uplink does not replace 'table[index]' with
# something else, e.g. as 'table[index]=unimplemented;'...
