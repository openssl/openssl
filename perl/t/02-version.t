
print "1..1\n";
use OpenSSL;
if ($OpenSSL::VERSION ne '') {
    print "ok 1\n";
}
else {
    print "not ok 1\n";
}

