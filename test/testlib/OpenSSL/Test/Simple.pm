package OpenSSL::Test::Simple;

use strict;
use warnings;

use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
$VERSION = "0.1";
@ISA = qw(Exporter);
@EXPORT = qw(simple_test);


use Test::More 0.96;
use OpenSSL::Test;

# args:
#  name			(used with setup())
#  algorithm		(used to check if it's at all supported)
#  name of binary	(the program that does the actual test)
sub simple_test {
    my ($name, $prgr, $algo, @rest) = @_;

    setup($name);

    plan tests => 1;
  SKIP: {
      skip "$algo is not supported by this OpenSSL build, skipping this test...", 1
	  if $algo && run(app(["openssl", "no-$algo"]));

      ok(run(test([$prgr])), "running $prgr");
    }
}
