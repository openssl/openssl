/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef DECODER
# error Macro DECODER undefined
#endif

#ifndef OPENSSL_NO_DH
    DECODER("DH", "yes", "der", ossl_der_to_dh_decoder_functions),
    DECODER("DHX", "yes", "der", ossl_der_to_dhx_decoder_functions),
#endif
#ifndef OPENSSL_NO_DSA
    DECODER("DSA", "yes", "der", ossl_der_to_dsa_decoder_functions),
    DECODER("DSA", "yes", "mblob", ossl_msblob_to_dsa_decoder_functions),
# ifndef OPENSSL_NO_RC4
    DECODER("DSA", "yes", "pvk", ossl_pvk_to_dsa_decoder_functions),
# endif
#endif
#ifndef OPENSSL_NO_EC
    DECODER("EC", "yes", "der", ossl_der_to_ec_decoder_functions),
    DECODER("ED25519", "yes", "der", ossl_der_to_ed25519_decoder_functions),
    DECODER("ED448", "yes", "der", ossl_der_to_ed448_decoder_functions),
    DECODER("X25519", "yes", "der", ossl_der_to_x25519_decoder_functions),
    DECODER("X448", "yes", "der", ossl_der_to_x448_decoder_functions),
#endif
    DECODER("RSA", "yes", "der", ossl_der_to_rsa_decoder_functions),
    DECODER("RSA-PSS", "yes", "der", ossl_der_to_rsapss_decoder_functions),
#ifndef OPENSSL_NO_DSA
    DECODER("RSA", "yes", "mblob", ossl_msblob_to_rsa_decoder_functions),
# ifndef OPENSSL_NO_RC4
    DECODER("RSA", "yes", "pvk", ossl_pvk_to_rsa_decoder_functions),
# endif
#endif

    DECODER("DER", "yes", "pem", ossl_pem_to_der_decoder_functions),

