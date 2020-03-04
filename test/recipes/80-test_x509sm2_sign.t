use strict;
use warnings;

use POSIX;
use File::Spec::Functions qw/splitdir curdir catfile/;
use File::Compare;
use OpenSSL::Test qw/:DEFAULT cmdstr srctop_file/;
use OpenSSL::Test::Utils;

setup("x509sm2_sign");

plan skip_all => "x509sm2_sign is not supported by this OpenSSL build"
    if disabled("sm2");

plan tests => 1;  
ok(run(app(["openssl", "x509", "-req",
                "-in", srctop_file("test", "certs", "sm2-csr.pem"),
                "-signkey", srctop_file("test", "certs", "sm2-root.key"),
                "-noout", "-sm3",
                "-sm2-id", "1234567812345678",
                "-sigopt", "sm2_id:1234567812345678"])));
                