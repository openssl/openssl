##
##  Makefile.PL -- Perl MakeMaker specification
##

use ExtUtils::MakeMaker;

WriteMakefile(
    'OPTIMIZE'      => '',
    'DISTNAME'      => 'OpenSSL-0.9.2',
    'NAME'          => 'OpenSSL',
    'VERSION_FROM'  => 'OpenSSL.pm',
    'LIBS'          => ['-L.. -lssl -lcrypto'],
    'DEFINE'        => '',
    'INC'           => '-I../include',
    'H'             => ['openssl.h'],
    'C'             => ['openssl_cb.c'],
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

