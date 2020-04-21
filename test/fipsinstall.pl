#! /usr/bin/env perl

use strict;
use warnings;

use File::Spec;

use if $^O eq "VMS", "VMS::Filespec";

my $bldtop_dir;

# First script argument MUST be the build top directory
BEGIN {
    $bldtop_dir = $ARGV[0];
    # 'use lib' needs Unix-ish paths
    $bldtop_dir = VMS::Filespec::unixpath($bldtop_dir) if $^O eq "VMS";
}

use lib $bldtop_dir;
use FindBin;
use lib "$FindBin::Bin/../Configurations";
use platform;

print STDERR "DEBUG[fipsinstall.pl]: Environment dump:\n";
print STDERR "DEBUG[fipsinstall.pl]: > $_ = $ENV{$_}\n" foreach (sort keys %ENV);
print STDERR "DEBUG[fipsinstall.pl]: \@ARGV dump:\n";
print STDERR "DEBUG[fipsinstall.pl]: > $_\n" foreach (@ARGV);

my @providers = ($bldtop_dir, 'providers');
my $fips_cnf = File::Spec->catfile(@providers, 'fipsinstall.cnf');
my $fips_module = File::Spec->catfile(@providers, platform->dso('fips'));
my $openssl = File::Spec->catfile($bldtop_dir, 'apps',
                                  platform->bin('openssl'));

# We create the command like this to make it readable, then massage it with
# a space replacement regexp to make it usable with system()
my $cmd = <<_____;
$openssl fipsinstall \
    -out "{fips_cnf}" \
    -module "{fips_module}" \
    -provider_name "fips" \
    -mac_name "HMAC" -macopt "digest:SHA256" -macopt "hexkey:00" \
    -section_name "fips_sect"
_____
$cmd =~ s|\s+| |gm;
$cmd =~ s|{fips_cnf}|$fips_cnf|;
$cmd =~ s|{fips_module}|$fips_module|;

print STDERR "DEBUG[fipsinstall.pl]: \$cmd = $cmd\n";

my $exit = 0;
system($cmd);
die "Failed to run '$cmd'\n" if $? == -1;
# If there was a signal, use it as exit code with high bit set.
$exit = (($? & 255) | 128) if ($? & 255) != 0;
# Otherwise, just return fipsinstall's exit code
$exit = ($? >> 8);

print STDERR "DEBUG[fipsinstall.pl]: \$exit = $exit\n";

print STDERR "# fipsinstall.pl: $cmd => $exit\n"
    if $ENV{HARNESS_ACTIVE} && $ENV{HARNESS_VERBOSE};

exit($exit);

