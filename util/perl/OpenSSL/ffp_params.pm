package OpenSSL::ffp_params;

use strict;
use warnings;

require Exporter;
our @ISA= qw(Exporter);
our @EXPORT = qw(ffp_get_params);

sub ffp_get_params {
    return (['struct ffc_ossl_params_st', 'ffp'],
                ['OSSL_PKEY_PARAM_FFC_P',        'p',         'BN'],
                ['OSSL_PKEY_PARAM_FFC_Q',        'q',         'BN'],
                ['OSSL_PKEY_PARAM_FFC_G',        'g',         'BN'],
                ['OSSL_PKEY_PARAM_FFC_COFACTOR', 'cofactor',  'BN'],
                ['OSSL_PKEY_PARAM_FFC_GINDEX',   'g_index',   'int'],
                ['OSSL_PKEY_PARAM_FFC_PCOUNTER', 'p_counter', 'int'],
                ['OSSL_PKEY_PARAM_FFC_H',        'h',         'int'],
                ['OSSL_PKEY_PARAM_FFC_SEED',     'seed',      'octet_string'],
            ['end struct'],
           );
}
