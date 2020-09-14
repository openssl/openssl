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

    ENCODER("RSA", "yes", "text", rsa_to_text_encoder_functions),
    ENCODER("RSA", "yes", "der", rsa_to_der_encoder_functions),
    ENCODER("RSA", "yes", "pem", rsa_to_pem_encoder_functions),
    ENCODER("RSA-PSS", "yes", "text", rsapss_to_text_encoder_functions),
    ENCODER("RSA-PSS", "yes", "der", rsapss_to_der_encoder_functions),
    ENCODER("RSA-PSS", "yes", "pem", rsapss_to_pem_encoder_functions),

#ifndef OPENSSL_NO_DH
    ENCODER("DH", "yes", "text", dh_to_text_encoder_functions),
    ENCODER("DH", "yes", "der", dh_to_der_encoder_functions),
    ENCODER("DH", "yes", "pem", dh_to_pem_encoder_functions),

    ENCODER("DHX", "yes", "text", dhx_to_text_encoder_functions),
    ENCODER("DHX", "yes", "der", dhx_to_der_encoder_functions),
    ENCODER("DHX", "yes", "pem", dhx_to_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_DSA
    ENCODER("DSA", "yes", "text", dsa_to_text_encoder_functions),
    ENCODER("DSA", "yes", "der", dsa_to_der_encoder_functions),
    ENCODER("DSA", "yes", "pem", dsa_to_pem_encoder_functions),
#endif

#ifndef OPENSSL_NO_EC
    ENCODER("X25519", "yes", "text", x25519_to_text_encoder_functions),
    ENCODER("X25519", "yes", "der", x25519_to_der_encoder_functions),
    ENCODER("X25519", "yes", "pem", x25519_to_pem_encoder_functions),

    ENCODER("X448", "yes", "text", x448_to_text_encoder_functions),
    ENCODER("X448", "yes", "der", x448_to_der_encoder_functions),
    ENCODER("X448", "yes", "pem", x448_to_pem_encoder_functions),

    ENCODER("ED25519", "yes", "text", ed25519_to_text_encoder_functions),
    ENCODER("ED25519", "yes", "der", ed25519_to_der_encoder_functions),
    ENCODER("ED25519", "yes", "pem", ed25519_to_pem_encoder_functions),

    ENCODER("ED448", "yes", "text", ed448_to_text_encoder_functions),
    ENCODER("ED448", "yes", "der", ed448_to_der_encoder_functions),
    ENCODER("ED448", "yes", "pem", ed448_to_pem_encoder_functions),

    ENCODER("EC", "yes", "text", ec_to_text_encoder_functions),
    ENCODER("EC", "yes", "der", ec_to_der_encoder_functions),
    ENCODER("EC", "yes", "pem", ec_to_pem_encoder_functions),
#endif
