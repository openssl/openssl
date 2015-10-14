package OpenSSL::Test::Utils;

use strict;
use warnings;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.1";
@ISA = qw(Exporter);
@EXPORT = qw(disabled);

=head1 NAME

OpenSSL::Test::Utils - test utility functions

=head1 SYNOPSIS

  use OpenSSL::Test::Utils;

  disabled("dh");

=head1 DESCRIPTION

This module provides utility functions for the testing framework.

=cut

use OpenSSL::Test;

=over 4

=item B<disabled ARRAY>

In a scalar context returns 1 if any of the features in ARRAY is disabled.

In an array context returns an array with each element set to 1 if the
corresponding feature is disabled and 0 otherwise.

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

=head1 SEE ALSO

L<OpenSSL::Test>

=head1 AUTHORS

Stephen Henson E<lt>steve@openssl.orgE<gt> with inspiration
from Richard Levitte E<lt>levitte@openssl.orgE<gt>

=cut

1;
