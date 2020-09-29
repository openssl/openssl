/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ENCODER
# error Macro ENCODER undefined
#endif

    ENCODER("RSA", "yes", "text", ossl_rsa_to_text_encoder_functions),
    ENCODER("RSA", "yes", "der", ossl_rsa_to_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", ossl_rsa_to_pem_encoder_functions),
    ENCODER("RSA-PSS", "yes", "text", ossl_rsapss_to_text_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", ossl_rsapss_to_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", ossl_rsapss_to_pem_encoder_functions),

#ifndef OPENSSL_NO_DH
    ENCODER("DH", "yes", "text", ossl_dh_to_text_encoder_functions),
    ENCODER("DH", "yes", "der", ossl_dh_to_der_encoder_functions),
    ENCODER("DH", "yes", "pem", ossl_dh_to_pem_encoder_functions),

    ENCODER("DHX", "yes", "text", ossl_dhx_to_text_encoder_functions),
    ENCODER("DHX", "yes", "der", ossl_dhx_to_der_encoder_functions),
    ENCODER("DHX", "yes", "pem", ossl_dhx_to_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_DSA
    ENCODER("DSA", "yes", "text", ossl_dsa_to_text_encoder_functions),
    ENCODER("DSA", "yes", "der", ossl_dsa_to_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", ossl_dsa_to_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_EC
    ENCODER("X25519", "yes", "text", ossl_x25519_to_text_encoder_functions),
    ENCODER("X25519", "yes", "der", ossl_x25519_to_der_encoder_functions),
    ENCODER("X25519", "yes", "pem", ossl_x25519_to_pem_encoder_functions),

    ENCODER("X448", "yes", "text", ossl_x448_to_text_encoder_functions),
    ENCODER("X448", "yes", "der", ossl_x448_to_der_encoder_functions),
    ENCODER("X448", "yes", "pem", ossl_x448_to_pem_encoder_functions),

    ENCODER("ED25519", "yes", "text", ossl_ed25519_to_text_encoder_functions),
    ENCODER("ED25519", "yes", "der", ossl_ed25519_to_der_encoder_functions),
    ENCODER("ED25519", "yes", "pem", ossl_ed25519_to_pem_encoder_functions),

    ENCODER("ED448", "yes", "text", ossl_ed448_to_text_encoder_functions),
    ENCODER("ED448", "yes", "der", ossl_ed448_to_der_encoder_functions),
    ENCODER("ED448", "yes", "pem", ossl_ed448_to_pem_encoder_functions),

    ENCODER("EC", "yes", "text", ossl_ec_to_text_encoder_functions),
    ENCODER("EC", "yes", "der", ossl_ec_to_der_encoder_functions),
    ENCODER("EC", "yes", "pem", ossl_ec_to_pem_encoder_functions),
#endif
