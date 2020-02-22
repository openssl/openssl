/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * TODO(v3.0): the IMPLEMENT macros in include/openssl/pem.h should be
 * moved here.
 */

#include <openssl/pem.h>
#include <openssl/serializer.h>

/* Alternative IMPLEMENT macros for provided serializers */

# define IMPLEMENT_PEM_provided_write_body_vars(type, asn1)             \
    int ret = 0;                                                        \
    const char *pq = OSSL_SERIALIZER_##asn1##_TO_PEM_PQ;                \
    OSSL_SERIALIZER_CTX *ctx = OSSL_SERIALIZER_CTX_new_by_##type(x, pq); \
                                                                        \
    if (ctx != NULL && OSSL_SERIALIZER_CTX_get_serializer(ctx) == NULL) { \
        OSSL_SERIALIZER_CTX_free(ctx);                                  \
        goto legacy;                                                    \
    }
# define IMPLEMENT_PEM_provided_write_body_pass()                       \
    ret = 1;                                                            \
    if (kstr == NULL && cb == NULL) {                                   \
        if (u != NULL) {                                                \
            kstr = u;                                                   \
            klen = strlen(u);                                           \
        } else {                                                        \
            cb = PEM_def_callback;                                      \
        }                                                               \
    }                                                                   \
    if (enc != NULL) {                                                  \
        ret = 0;                                                        \
        if (OSSL_SERIALIZER_CTX_set_cipher(ctx, EVP_CIPHER_name(enc),   \
                                           NULL)) {                     \
            ret = 1;                                                    \
            if (kstr != NULL                                            \
                && !OSSL_SERIALIZER_CTX_set_passphrase(ctx, kstr, klen)) \
                ret = 0;                                                \
            else if (cb != NULL                                         \
                     && !OSSL_SERIALIZER_CTX_set_passphrase_cb(ctx, 1,  \
                                                               cb, u))  \
                ret = 0;                                                \
        }                                                               \
    }                                                                   \
    if (!ret) {                                                         \
        OSSL_SERIALIZER_CTX_free(ctx);                                  \
        return 0;                                                       \
    }
# define IMPLEMENT_PEM_provided_write_body_main(type, outtype)          \
    ret = OSSL_SERIALIZER_to_##outtype(ctx, out);                       \
    OSSL_SERIALIZER_CTX_free(ctx);                                      \
    return ret
# define IMPLEMENT_PEM_provided_write_body_fallback(str, asn1,          \
                                                    writename)          \
    legacy:                                                             \
    return PEM_ASN1_##writename((i2d_of_void *)i2d_##asn1, str, out,    \
                                  x, NULL, NULL, 0, NULL, NULL)
# define IMPLEMENT_PEM_provided_write_body_fallback_cb(str, asn1,       \
                                                       writename)       \
    legacy:                                                             \
    return PEM_ASN1_##writename((i2d_of_void *)i2d_##asn1, str, out,    \
                                x, enc, kstr, klen, cb, u)

# define IMPLEMENT_PEM_provided_write_to(name, type, str, asn1,         \
                                         OUTTYPE, outtype, writename)   \
    PEM_write_fnsig(name, type, OUTTYPE, writename)                     \
    {                                                                   \
        IMPLEMENT_PEM_provided_write_body_vars(type, asn1);             \
        IMPLEMENT_PEM_provided_write_body_main(type, outtype);          \
        IMPLEMENT_PEM_provided_write_body_fallback(str, asn1,           \
                                                   writename);          \
    }


# define IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1,      \
                                            OUTTYPE, outtype, writename) \
    PEM_write_cb_fnsig(name, type, OUTTYPE, writename)                  \
    {                                                                   \
        IMPLEMENT_PEM_provided_write_body_vars(type, asn1);             \
        IMPLEMENT_PEM_provided_write_body_pass();                       \
        IMPLEMENT_PEM_provided_write_body_main(type, outtype);          \
        IMPLEMENT_PEM_provided_write_body_fallback_cb(str, asn1,        \
                                                      writename);       \
    }

# ifdef OPENSSL_NO_STDIO

#  define IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1)
#  define IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1)

# else

#  define IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1)        \
    IMPLEMENT_PEM_provided_write_to(name, type, str, asn1, FILE, fp, write)
#  define IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1, FILE, fp, write)

# endif

# define IMPLEMENT_PEM_provided_write_bio(name, type, str, asn1)        \
    IMPLEMENT_PEM_provided_write_to(name, type, str, asn1, BIO, bio, write_bio)
# define IMPLEMENT_PEM_provided_write_cb_bio(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_cb_to(name, type, str, asn1, BIO, bio, write_bio)

# define IMPLEMENT_PEM_provided_write(name, type, str, asn1)    \
    IMPLEMENT_PEM_provided_write_bio(name, type, str, asn1)     \
    IMPLEMENT_PEM_provided_write_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_write_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_provided_write_cb_bio(name, type, str, asn1)  \
    IMPLEMENT_PEM_provided_write_cb_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_rw(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)                   \
    IMPLEMENT_PEM_provided_write(name, type, str, asn1)

# define IMPLEMENT_PEM_provided_rw_cb(name, type, str, asn1) \
    IMPLEMENT_PEM_read(name, type, str, asn1)                   \
    IMPLEMENT_PEM_provided_write_cb(name, type, str, asn1)

