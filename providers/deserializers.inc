/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef DESER
# error Macro DESER undefined
#endif

#ifndef OPENSSL_NO_DH
    DESER("DH", "yes", "der", der_to_dh_deserializer_functions),
#endif
#ifndef OPENSSL_NO_DSA
    DESER("DSA", "yes", "der", der_to_dsa_deserializer_functions),
#endif
#ifndef OPENSSL_NO_EC
    DESER("EC", "yes", "der", der_to_ec_deserializer_functions),
    DESER("ED25519", "yes", "der", der_to_ed25519_deserializer_functions),
    DESER("ED448", "yes", "der", der_to_ed448_deserializer_functions),
    DESER("X25519", "yes", "der", der_to_x25519_deserializer_functions),
    DESER("X448", "yes", "der", der_to_x448_deserializer_functions),
#endif
    DESER("RSA", "yes", "der", der_to_rsa_deserializer_functions),
    DESER("RSA-PSS", "yes", "der", der_to_rsapss_deserializer_functions),

    DESER("DER", "yes", "pem", pem_to_der_deserializer_functions),
