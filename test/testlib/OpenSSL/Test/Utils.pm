package OpenSSL::Test::Utils;

use strict;
use warnings;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.1";
@ISA = qw(Exporter);
@EXPORT = qw(disabled config);

=head1 NAME

OpenSSL::Test::Utils - test utility functions

=head1 SYNOPSIS

  use OpenSSL::Test::Utils;

  disabled("dh");

  config("no_shared");

=head1 DESCRIPTION

This module provides utility functions for the testing framework.

=cut

use OpenSSL::Test qw/:DEFAULT top_file/;

=over 4

=item B<disabled ARRAY>

In a scalar context returns 1 if any of the features in ARRAY is disabled.

In an array context returns an array with each element set to 1 if the
corresponding feature is disabled and 0 otherwise.

=item B<config STRING>

Returns an item from the %config hash in \$TOP/configdata.pm.

=back

=cut

our %disabled;
my $disabled_set = 0;

sub check_disabled {
#print STDERR "Running check_disabled\n";
    foreach (run(app(["openssl", "list", "-disabled"]), capture => 1)) {
        s/\R//;         # chomp;
        next if /:/;    # skip header
        $disabled{lc $_} = 1;
    }
    $disabled_set = 1;
}

# args:
#  list of features to check
sub disabled {
    check_disabled() unless $disabled_set;
    if (wantarray) {
        my @ret;
        foreach (@_) {
            push @ret, exists $disabled{lc $_} ? 1 : 0;
        }
        return @ret;
    }
    foreach (@_) {
        return 1 if exists $disabled{lc $_};
    }
    return 0;
}

our %config;
sub config {
    if (!%config) {
	# We eval it so it doesn't run at compile time of this file.
	# The latter would have top_dir() complain that setup() hasn't
	# been run yet.
	my $configdata = top_file("configdata.pm");
	eval { require $configdata; %config = %configdata::config };
    }
    return $config{$_[0]};
}

=head1 SEE ALSO

L<OpenSSL::Test>

=head1 AUTHORS

Stephen Henson E<lt>steve@openssl.orgE<gt> with inspiration
from Richard Levitte E<lt>levitte@openssl.orgE<gt>

=cut

1;
