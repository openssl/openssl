#! /usr/bin/perl

use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/splitdir curdir catfile devnull/;
use File::Path 2.00 qw/remove_tree/;
use OpenSSL::Test qw/:DEFAULT cmdstr top_file quotify/;

setup("test_ca");

my $perl = $^X;
$ENV{OPENSSL} = cmdstr(app(["openssl"]));
my $CA_pl = top_file("apps", "CA.pl");
my $std_openssl_cnf = top_file("apps", "openssl.cnf");

($perl) = quotify($perl) unless $^O eq "VMS"; # never quotify a command on VMS. Ever!

remove_tree("demoCA", { safe => 0 });

plan tests => 4;
 SKIP: {
     $ENV{OPENSSL_CONFIG} = "-config ".top_file("test", "CAss.cnf");
     skip "failed creating CA structure", 3
	 if !is(system("$perl ".$CA_pl." -newca < ".devnull()." 2>&1"), 0,
		'creating CA structure');

     $ENV{OPENSSL_CONFIG} = "-config ".top_file("test", "Uss.cnf");
     skip "failed creating new certificate request", 2
	 if !is(system("$perl ".$CA_pl." -newreq 2>&1"), 0,
		'creating new certificate request');

     $ENV{OPENSSL_CONFIG} = "-config ".$std_openssl_cnf;
     skip "failed to sign certificate request", 1
	 if !is(yes("$perl ".$CA_pl." -sign 2>&1"), 0,
		'signing certificate request');

     is(system("$perl ".$CA_pl." -verify newcert.pem 2>&1"), 0,
	'verifying new certificate');
}


remove_tree("demoCA", { safe => 0 });
unlink "newcert.pem", "newreq.pem";


sub yes {
    open(PIPE, "|-", join(" ",@_));
    local $SIG{PIPE} = "IGNORE";
    1 while print PIPE "y\n";
    close PIPE;
    return 0;
}
