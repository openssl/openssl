/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

#define XTS_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV             \
                   | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT            \
                   | EVP_CIPH_CUSTOM_COPY)

#define WRAP_FLAGS (EVP_CIPH_WRAP_MODE                                         \
                    | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER         \
                    | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_DEFAULT_ASN1)

/*
 * EVP_aes_128_cbc()
 * EVP_aes_128_ecb(
 * EVP_aes_128_ofb()
 * EVP_aes_128_cfb128()
 * EVP_aes_128_cfb1()
 * EVP_aes_128_cfb8()
 * EVP_aes_128_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aes, NID_aes, 128, 0)
/*
 * EVP_aes_192_cbc()
 * EVP_aes_192_ecb(
 * EVP_aes_192_ofb()
 * EVP_aes_192_cfb128()
 * EVP_aes_192_cfb1()
 * EVP_aes_192_cfb8()
 * EVP_aes_192_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aes, NID_aes, 192, 0)
/*
 * EVP_aes_256_cbc()
 * EVP_aes_256_ecb(
 * EVP_aes_256_ofb()
 * EVP_aes_256_cfb128()
 * EVP_aes_256_cfb1()
 * EVP_aes_256_cfb8()
 * EVP_aes_256_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aes, NID_aes, 256, 0)

/* EVP_aes_128_xts() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_128_xts, 128, 1, 16, xts, XTS, XTS_FLAGS)
/* EVP_aes_256_xts() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_256_xts, 256, 1, 16, xts, XTS, XTS_FLAGS)

/* EVP_aes_128_wrap() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes128_wrap, 128, 8, 8, wrap,
                           WRAP, WRAP_FLAGS)
/* EVP_aes_192_wrap() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes192_wrap, 192, 8, 8, wrap,
                           WRAP, WRAP_FLAGS)
/* EVP_aes_256_wrap() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes256_wrap, 256, 8, 8, wrap,
                           WRAP, WRAP_FLAGS)

/* EVP_aes_128_wrap_pad() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes128_wrap_pad, 128, 8, 4, wrap_pad,
                           WRAP, WRAP_FLAGS)
/* EVP_aes_192_wrap_pad() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes192_wrap_pad, 192, 8, 4, wrap_pad,
                           WRAP, WRAP_FLAGS)
/* EVP_aes_256_wrap_pad() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_id_aes256_wrap_pad, 256, 8, 4, wrap_pad,
                           WRAP, WRAP_FLAGS)

/* EVP_aes_128_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_128_gcm, 128, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_192_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_192_gcm, 192, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_256_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_256_gcm, 256, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)

/* EVP_aes_128_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_128_ccm, 128, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_192_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_192_ccm, 192, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_256_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_256_ccm, 256, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)

#ifndef OPENSSL_NO_OCB
/* EVP_aes_128_ocb() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_128_ocb, 128, 16, 12, ocb, OCB, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_192_ocb() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_192_ocb, 192, 16, 12, ocb, OCB, EVP_CIPH_AEAD_FLAGS)
/* EVP_aes_256_ocb() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_256_ocb, 256, 16, 12, ocb, OCB, EVP_CIPH_AEAD_FLAGS)
#endif /* OPENSSL_NO_OCB */

#ifndef OPENSSL_NO_SIV
# define SIV_FLAGS    (EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1  \
                      | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER       \
                      | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_COPY       \
                      | EVP_CIPH_CTRL_INIT)
/* EVP_aes_128_siv() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_128_siv, 128, 1, 0, siv, SIV, SIV_FLAGS)
/* EVP_aes_192_siv() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_192_siv, 192, 1, 0, siv, SIV, SIV_FLAGS)
/* EVP_aes_256_siv() */
IMPLEMENT_EVP_CIPHER_CONST(aes, NID_aes_256_siv, 256, 1, 0, siv, SIV, SIV_FLAGS)
#endif /* OPENSSL_NO_SIV */

