##
##  Makefile.PL -- Perl MakeMaker specification
##

open(IN,"<../Makefile.ssl") || die "unable to open Makefile.ssl!\n";
while(<IN>) {
    $V=$1 if (/^VERSION=(.*)$/);
}
close(IN);
print "Configuring companion Perl module for OpenSSL $V\n";

use ExtUtils::MakeMaker;

WriteMakefile(
    'OPTIMIZE'      => '',
    'DISTNAME'      => "openssl-$V",
    'NAME'          => 'OpenSSL',
    'VERSION_FROM'  => 'OpenSSL.pm',
    'LIBS'          => ( $^O eq 'MSWin32'
                         ? [ '-L../out32dll -lssleay32 -llibeay32' ]
                         : [ '-L.. -lssl -lcrypto' ]                 ),
    'DEFINE'        => '',
    'INC'           => '-I../include',
    'H'             => ['openssl.h'],
    'OBJECT' =>
        'OpenSSL.o ' .
        'openssl_bio.o ' .
        'openssl_bn.o ' .
        'openssl_cipher.o ' .
        'openssl_digest.o ' .
        'openssl_err.o ' .
        'openssl_ssl.o ' .
        'openssl_x509.o ',
    'XS' => { 
        'OpenSSL.xs'        =>  'OpenSSL.c',
        'openssl_bio.xs'    =>  'openssl_bio.c',
        'openssl_bn.xs'     =>  'openssl_bn.c',
        'openssl_cipher.xs' =>  'openssl_cipher.c',
        'openssl_digest.xs' =>  'openssl_digest.c',
        'openssl_err.xs'    =>  'openssl_err.c',
        'openssl_ssl.xs'    =>  'openssl_ssl.c',
        'openssl_x509.xs'   =>  'openssl_x509.c',
    },
);

