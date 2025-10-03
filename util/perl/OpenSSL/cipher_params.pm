package OpenSSL::cipher_params;

use strict;
use warnings;

require Exporter;
our @ISA= qw(Exporter);
our @EXPORT = qw(cipher_generic_gettable_params
                 cipher_generic_gettable_ctx_params
                 cipher_generic_settable_ctx_params
                 cipher_var_keylen_settable_ctx_params
                );

sub cipher_generic_gettable_params {
    return (['struct ossl_cipher_get_param_list_st', 'com'],
                ['OSSL_CIPHER_PARAM_MODE',             'mode',   'uint'],
                ['OSSL_CIPHER_PARAM_KEYLEN',           'keylen', 'size_t'],
                ['OSSL_CIPHER_PARAM_IVLEN',            'ivlen',  'size_t'],
                ['OSSL_CIPHER_PARAM_BLOCK_SIZE',       'bsize',  'size_t'],
                ['OSSL_CIPHER_PARAM_AEAD',             'aead',   'int' ],
                ['OSSL_CIPHER_PARAM_CUSTOM_IV',        'custiv', 'int' ],
                ['OSSL_CIPHER_PARAM_CTS',              'cts',    'int' ],
                ['OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK',  'mb',     'int' ],
                ['OSSL_CIPHER_PARAM_HAS_RAND_KEY',     'rand',   'int' ],
                ['OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC', 'etm',    'int' ],
            ['end struct'],
           );
}

sub cipher_generic_gettable_ctx_params {
    return (['struct ossl_cipher_get_ctx_param_list_st', 'com'],
                ['OSSL_CIPHER_PARAM_KEYLEN',     'keylen', 'size_t'],
                ['OSSL_CIPHER_PARAM_IVLEN',      'ivlen',  'size_t'],
                ['OSSL_CIPHER_PARAM_PADDING',    'pad',    'uint'],
                ['OSSL_CIPHER_PARAM_NUM',        'num',    'uint' ],
                ['OSSL_CIPHER_PARAM_IV',         'iv',     'octet_string' ],
                ['OSSL_CIPHER_PARAM_UPDATED_IV', 'updiv',  'octet_string' ],
                ['OSSL_CIPHER_PARAM_TLS_MAC',    'tlsmac', 'octet_string' ],
            ['end struct'],
           );
}

sub cipher_generic_settable_ctx_params {
    return (['struct ossl_cipher_set_ctx_param_list_st', 'com'],
                ['OSSL_CIPHER_PARAM_PADDING',      'pad',        'uint'],
                ['OSSL_CIPHER_PARAM_NUM',          'num',        'uint'],
                ['OSSL_CIPHER_PARAM_USE_BITS',     'bits',       'uint'],
                ['OSSL_CIPHER_PARAM_TLS_VERSION',  'tlsvers',    'uint'],
                ['OSSL_CIPHER_PARAM_TLS_MAC_SIZE', 'tlsmacsize', 'size_t'],
            ['end struct'],
           );
}

sub cipher_var_keylen_settable_ctx_params {
    return (cipher_generic_settable_ctx_params(),
            ['OSSL_CIPHER_PARAM_KEYLEN', 'com.keylen', 'size_t'],
           );
}

1;
