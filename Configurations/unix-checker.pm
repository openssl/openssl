#! /usr/bin/perl

use Config;

# Check that the perl implementation file modules generate paths that
# we expect for the platform
use File::Spec::Functions qw(:DEFAULT rel2abs);

if (rel2abs('.') !~ m|/|) {
    die <<EOF;

******************************************************************************
This perl version doesn't produce Unix like paths (with forward slash
directory separators).  Please use an implementation that does.

This Perl version: $Config{version} for $Config{archname}
******************************************************************************
EOF
}

1;
