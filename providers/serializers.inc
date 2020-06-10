/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef SER
# error Macro SER undefined
#endif

    SER("RSA", "yes", "text", "private", rsa_priv_text_serializer_functions),
    SER("RSA", "yes", "text", "public", rsa_pub_text_serializer_functions),
    SER("RSA", "yes", "der", "private", rsa_priv_der_serializer_functions),
    SER("RSA", "yes", "der", "public", rsa_pub_der_serializer_functions),
    SER("RSA", "yes", "pem", "private", rsa_priv_pem_serializer_functions),
    SER("RSA", "yes", "pem", "public", rsa_pub_pem_serializer_functions),
    SER("RSA-PSS", "yes", "text", "private",
        rsa_priv_text_serializer_functions),
    SER("RSA-PSS", "yes", "text", "public", rsa_pub_text_serializer_functions),
    SER("RSA-PSS", "yes", "der", "private", rsa_priv_der_serializer_functions),
    SER("RSA-PSS", "yes", "der", "public", rsa_pub_der_serializer_functions),
    SER("RSA-PSS", "yes", "pem", "private", rsa_priv_pem_serializer_functions),
    SER("RSA-PSS", "yes", "pem", "public", rsa_pub_pem_serializer_functions),

#ifndef OPENSSL_NO_DH
    SER("DH", "yes", "text", "private", dh_priv_text_serializer_functions),
    SER("DH", "yes", "text", "public", dh_pub_text_serializer_functions),
    SER("DH", "yes", "text", "parameters", dh_param_text_serializer_functions),
    SER("DH", "yes", "der", "private", dh_priv_der_serializer_functions),
    SER("DH", "yes", "der", "public", dh_pub_der_serializer_functions),
    SER("DH", "yes", "der", "parameters", dh_param_der_serializer_functions),
    SER("DH", "yes", "pem", "private", dh_priv_pem_serializer_functions),
    SER("DH", "yes", "pem", "public", dh_pub_pem_serializer_functions),
    SER("DH", "yes", "pem", "parameters", dh_param_pem_serializer_functions),
#endif

#ifndef OPENSSL_NO_DSA
    SER("DSA", "yes", "text", "private", dsa_priv_text_serializer_functions),
    SER("DSA", "yes", "text", "public", dsa_pub_text_serializer_functions),
    SER("DSA", "yes", "text", "parameters",
        dsa_param_text_serializer_functions),
    SER("DSA", "yes", "der", "private", dsa_priv_der_serializer_functions),
    SER("DSA", "yes", "der", "public", dsa_pub_der_serializer_functions),
    SER("DSA", "yes", "der", "parameters", dsa_param_der_serializer_functions),
    SER("DSA", "yes", "pem", "private", dsa_priv_pem_serializer_functions),
    SER("DSA", "yes", "pem", "public", dsa_pub_pem_serializer_functions),
    SER("DSA", "yes", "pem", "parameters", dsa_param_pem_serializer_functions),
#endif

#ifndef OPENSSL_NO_EC
    SER("X25519", "yes", "text", "private",
        x25519_priv_print_serializer_functions),
    SER("X25519", "yes", "text", "public",
        x25519_pub_print_serializer_functions),
    SER("X25519", "yes", "der", "private",
        x25519_priv_der_serializer_functions),
    SER("X25519", "yes", "der", "public", x25519_pub_der_serializer_functions),
    SER("X25519", "yes", "pem", "private",
        x25519_priv_pem_serializer_functions),
    SER("X25519", "yes", "pem", "public", x25519_pub_pem_serializer_functions),

    SER("X448", "no", "text", "private", x448_priv_print_serializer_functions),
    SER("X448", "no", "text", "public", x448_pub_print_serializer_functions),
    SER("X448", "no", "der", "private", x448_priv_der_serializer_functions),
    SER("X448", "no", "der", "public", x448_pub_der_serializer_functions),
    SER("X448", "no", "pem", "private", x448_priv_pem_serializer_functions),
    SER("X448", "no", "pem", "public", x448_pub_pem_serializer_functions),

    SER("ED25519", "yes", "text", "private",
        ed25519_priv_print_serializer_functions),
    SER("ED25519", "yes", "text", "public",
        ed25519_pub_print_serializer_functions),
    SER("ED25519", "yes", "der", "private",
        ed25519_priv_der_serializer_functions),
    SER("ED25519", "yes", "der", "public",
        ed25519_pub_der_serializer_functions),
    SER("ED25519", "yes", "pem", "private",
        ed25519_priv_pem_serializer_functions),
    SER("ED25519", "yes", "pem", "public",
        ed25519_pub_pem_serializer_functions),

    SER("ED448", "no", "text", "private",
        ed448_priv_print_serializer_functions),
    SER("ED448", "no", "text", "public", ed448_pub_print_serializer_functions),
    SER("ED448", "no", "der", "private", ed448_priv_der_serializer_functions),
    SER("ED448", "no", "der", "public", ed448_pub_der_serializer_functions),
    SER("ED448", "no", "pem", "private", ed448_priv_pem_serializer_functions),
    SER("ED448", "no", "pem", "public", ed448_pub_pem_serializer_functions),

    SER("EC", "yes", "text", "private", ec_priv_text_serializer_functions),
    SER("EC", "yes", "text", "public", ec_pub_text_serializer_functions),
    SER("EC", "yes", "text", "parameters", ec_param_text_serializer_functions),
    SER("EC", "yes", "der", "private", ec_priv_der_serializer_functions),
    SER("EC", "yes", "der", "public", ec_pub_der_serializer_functions),
    SER("EC", "yes", "der", "parameters", ec_param_der_serializer_functions),
    SER("EC", "yes", "pem", "private", ec_priv_pem_serializer_functions),
    SER("EC", "yes", "pem", "public", ec_pub_pem_serializer_functions),
    SER("EC", "yes", "pem", "parameters", ec_param_pem_serializer_functions),
#endif
