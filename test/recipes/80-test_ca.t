#! /usr/bin/perl

use strict;
use warnings;

use POSIX;
use File::Path 2.00 qw/remove_tree/;
use OpenSSL::Test qw/:DEFAULT cmdstr top_file/;

setup("test_ca");

$ENV{OPENSSL} = cmdstr(app(["openssl"]));
my $std_openssl_cnf = $^O eq "VMS"
    ? top_file("apps", "openssl-vms.cnf") : top_file("apps", "openssl.cnf");

remove_tree("demoCA", { safe => 0 });

plan tests => 4;
 SKIP: {
     $ENV{OPENSSL_CONFIG} = "-config ".top_file("test", "CAss.cnf");
     skip "failed creating CA structure", 3
	 if !ok(run(perlapp(["CA.pl","-newca"], stdin => undef, stderr => undef)),
		'creating CA structure');

     $ENV{OPENSSL_CONFIG} = "-config ".top_file("test", "Uss.cnf");
     skip "failed creating new certificate request", 2
	 if !ok(run(perlapp(["CA.pl","-newreq"], stderr => undef)),
		'creating CA structure');

     $ENV{OPENSSL_CONFIG} = "-config ".$std_openssl_cnf;
     skip "failed to sign certificate request", 1
	 if !is(yes(cmdstr(perlapp(["CA.pl", "-sign"], stderr => undef))), 0,
		'signing certificate request');

     ok(run(perlapp(["CA.pl", "-verify", "newcert.pem"], stderr => undef)),
	'verifying new certificate');
}


remove_tree("demoCA", { safe => 0 });
unlink "newcert.pem", "newreq.pem";


sub yes {
    my $cntr = 10;
    open(PIPE, "|-", join(" ",@_));
    local $SIG{PIPE} = "IGNORE";
    1 while $cntr-- > 0 && print PIPE "y\n";
    close PIPE;
    return 0;
}
