
BEGIN { 
    $| = 1; 
    print "1..1\n";
}
END {
	print "not ok 1\n" unless $ok;
}

use OpenSSL;
my $bio = OpenSSL::BIO::new("mem") || die;
undef $bio;

$ok = 1;
print "ok 1\n";

