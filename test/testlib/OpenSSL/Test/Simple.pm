package OpenSSL::Test::Simple;

use strict;
use warnings;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.2";
@ISA = qw(Exporter);
@EXPORT = qw(simple_test);

=head1 NAME

OpenSSL::Test::Simple - a few very simple test functions

=head1 SYNOPSIS

  use OpenSSL::Test::Simple;

  simple_test("my_test_name", "des", "destest");

=head1 DESCRIPTION

Sometimes, the functions in L<OpenSSL::Test> are quite tedious for some
repetitive tasks.  This module provides functions to make life easier.
You could call them hacks if you wish.

=cut

use OpenSSL::Test;
use OpenSSL::Test::Utils;

=over 4

=item B<simple_test NAME, PROGRAM, ALGORITHM>

Runs a test named NAME, running the program PROGRAM with no arguments,
to test the algorithm ALGORITHM.

A complete recipe looks like this:

  use OpenSSL::Test::Simple;

  simple_test("test_bf", "bftest", "bf");

=back

=cut

# args:
#  name			(used with setup())
#  algorithm		(used to check if it's at all supported)
#  name of binary	(the program that does the actual test)
sub simple_test {
    my ($name, $prgr, $algo, @rest) = @_;

    setup($name);

    plan skip_all => "$algo is not supported by this OpenSSL build"
        if $algo && disabled($algo);

    plan tests => 1;

    ok(run(test([$prgr])), "running $prgr");
}

=head1 SEE ALSO

L<OpenSSL::Test>

=head1 AUTHORS

Richard Levitte E<lt>levitte@openssl.orgE<gt> with inspiration
from Rich Salz E<lt>rsalz@openssl.orgE<gt>.

=cut

1;
