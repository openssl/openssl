package OpenSSL::cipher_params;

use strict;
use warnings;

require Exporter;
our @ISA= qw(Exporter);
our @EXPORT = qw(cipher_generic_gettable_params
                 cipher_generic_gettable_ctx_params
                 cipher_generic_settable_ctx_params);

sub cipher_generic_gettable_params {
    return (['struct ossl_cipher_get_param_list_st', 'com'],

            ['OSSL_CIPHER_PARAM_MODE',             'com.mode',   'uint'],
            ['OSSL_CIPHER_PARAM_KEYLEN',           'com.keylen', 'size_t'],
            ['OSSL_CIPHER_PARAM_IVLEN',            'com.ivlen',  'size_t'],
            ['OSSL_CIPHER_PARAM_BLOCK_SIZE',       'com.bsize',  'size_t'],
            ['OSSL_CIPHER_PARAM_AEAD',             'com.aead',   'int' ],
            ['OSSL_CIPHER_PARAM_CUSTOM_IV',        'com.custiv', 'int' ],
            ['OSSL_CIPHER_PARAM_CTS',              'com.cts',    'int' ],
            ['OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK',  'com.mb',     'int' ],
            ['OSSL_CIPHER_PARAM_HAS_RAND_KEY',     'com.rand',   'int' ],
            ['OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC', 'com.etm',    'int' ],
           );
}

sub cipher_generic_gettable_ctx_params {
    return (['struct ossl_cipher_get_ctx_param_list_st', 'com'],

            ['OSSL_CIPHER_PARAM_KEYLEN',       'com.keylen',     'size_t'],
            ['OSSL_CIPHER_PARAM_IVLEN',        'com.ivlen',      'size_t'],
            ['OSSL_CIPHER_PARAM_PADDING',      'com.pad',        'uint'],
            ['OSSL_CIPHER_PARAM_NUM',          'com.num',        'uint' ],
            ['OSSL_CIPHER_PARAM_IV',           'com.iv',         'octet_string' ],
            ['OSSL_CIPHER_PARAM_UPDATED_IV',   'com.updiv',      'octet_string' ],
            ['OSSL_CIPHER_PARAM_TLS_MAC',      'com.tlsmac',     'octet_string' ],
           );
}

sub cipher_generic_settable_ctx_params {
    return (['struct ossl_cipher_set_ctx_param_list_st', 'com'],

            ['OSSL_CIPHER_PARAM_PADDING',      'com.pad',        'uint'],
            ['OSSL_CIPHER_PARAM_NUM',          'com.num',        'uint'],
            ['OSSL_CIPHER_PARAM_USE_BITS',     'com.bits',       'uint'],
            ['OSSL_CIPHER_PARAM_TLS_VERSION',  'com.tlsvers',    'uint'],
            ['OSSL_CIPHER_PARAM_TLS_MAC_SIZE', 'com.tlsmacsize', 'size_t'],
           );
}

1;
