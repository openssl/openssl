/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"
#include "rsa_locl.h"

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36

/*
 * encode_pkcs1 encodes a DigestInfo prefix of hash |type| and digest |m|, as
 * described in EMSA-PKCS1-v1_5-ENCODE, RFC 3447 section 9.2 step 2. This
 * encodes the DigestInfo (T and tLen) but does not add the padding.
 *
 * On success, it returns one and sets |*out| to a newly allocated buffer
 * containing the result and |*out_len| to its length. The caller must free
 * |*out| with |OPENSSL_free|. Otherwise, it returns zero.
 */
static int encode_pkcs1(unsigned char **out, int *out_len, int type,
                        const unsigned char *m, unsigned int m_len)
{
    X509_SIG sig;
    X509_ALGOR algor;
    ASN1_TYPE parameter;
    ASN1_OCTET_STRING digest;
    uint8_t *der = NULL;
    int len;

    sig.algor = &algor;
    sig.algor->algorithm = OBJ_nid2obj(type);
    if (sig.algor->algorithm == NULL) {
        RSAerr(RSA_F_ENCODE_PKCS1, RSA_R_UNKNOWN_ALGORITHM_TYPE);
        return 0;
    }
    if (OBJ_length(sig.algor->algorithm) == 0) {
        RSAerr(RSA_F_ENCODE_PKCS1,
               RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
        return 0;
    }
    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    sig.algor->parameter = &parameter;

    sig.digest = &digest;
    sig.digest->data = (unsigned char *)m;
    sig.digest->length = m_len;

    len = i2d_X509_SIG(&sig, &der);
    if (len < 0)
        return 0;

    *out = der;
    *out_len = len;
    return 1;
}

int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    int i, encoded_len = 0, ret = 0;
    unsigned char *tmps = NULL;
    const unsigned char *encoded = NULL;

    if (rsa->meth->rsa_sign) {
        return rsa->meth->rsa_sign(type, m, m_len, sigret, siglen, rsa);
    }

    /* Compute the encoded digest. */
    if (type == NID_md5_sha1) {
	/* NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
	 * earlier. It has no DigestInfo wrapper but otherwise is
	 * RSASSA-PKCS1-v1_5. */
        if (m_len != SSL_SIG_LENGTH) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_INVALID_MESSAGE_LENGTH);
            return 0;
        }
        encoded_len = SSL_SIG_LENGTH;
        encoded = m;
    } else {
        if (!encode_pkcs1(&tmps, &encoded_len, type, m, m_len))
            goto err;
        encoded = tmps;
    }

    if (encoded_len > RSA_size(rsa) - RSA_PKCS1_PADDING_SIZE) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        goto err;
    }
    i = RSA_private_encrypt(encoded_len, encoded, sigret, rsa,
                            RSA_PKCS1_PADDING);
    if (i <= 0)
        goto err;

    *siglen = i;
    ret = 1;

err:
    OPENSSL_clear_free(tmps, (size_t)encoded_len);
    return ret;
}

int int_rsa_verify(int dtype, const unsigned char *m,
                   unsigned int m_len,
                   unsigned char *rm, size_t *prm_len,
                   const unsigned char *sigbuf, size_t siglen, RSA *rsa)
{
    int i, ret = 0, encoded_len = 0;
    unsigned char *s = NULL, *encoded = NULL;

    if (siglen != (size_t)RSA_size(rsa)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_WRONG_SIGNATURE_LENGTH);
        return 0;
    }

    /* Recover the encoded digest. */
    s = OPENSSL_malloc(siglen);
    if (s == NULL) {
        RSAerr(RSA_F_INT_RSA_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    i = RSA_public_decrypt((int)siglen, sigbuf, s, rsa, RSA_PKCS1_PADDING);
    if (i <= 0)
        goto err;

    if (dtype == NID_md5_sha1) {
	/* NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
	 * earlier. It has no DigestInfo wrapper but otherwise is
	 * RSASSA-PKCS1-v1_5. */
        if (i != SSL_SIG_LENGTH) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        if (rm != NULL) {
            memcpy(rm, s, SSL_SIG_LENGTH);
            *prm_len = SSL_SIG_LENGTH;
        } else if (memcmp(s, m, SSL_SIG_LENGTH) != 0) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
    } else if (dtype == NID_mdc2 && i == 18 && s[0] == 0x04 && s[1] == 0x10) {
        /*
         * Oddball MDC2 case: signature can be OCTET STRING. check for correct
         * tag and length octets.
         */
        if (rm != NULL) {
            memcpy(rm, s + 2, 16);
            *prm_len = 16;
        } else if (memcmp(m, s + 2, 16) != 0) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
    } else {
        /*
         * In verifyrecover mode, construct the encoded form using the end of
         * the structure. If the DigestInfo prefix is invalid, the signature
         * check will cover it.
         */
        if (rm != NULL) {
            const EVP_MD *md = EVP_get_digestbynid(dtype);
            m_len = EVP_MD_size(md);
            if (md != NULL && m_len > (size_t)i) {
                RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_DIGEST_LENGTH);
                goto err;
            }
            m = s + i - m_len;
        }

        /* Construct the encoded digest and ensure it matches. */
        if (!encode_pkcs1(&encoded, &encoded_len, dtype, m, m_len))
            goto err;

        if (encoded_len != i
            || memcmp(encoded, s, encoded_len) != 0) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        if (rm != NULL) {
            memcpy(rm, m, m_len);
            *prm_len = m_len;
        }
    }

    ret = 1;

err:
    OPENSSL_clear_free(encoded, (size_t)encoded_len);
    OPENSSL_clear_free(s, siglen);
    return ret;
}

int RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
               const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
{

    if (rsa->meth->rsa_verify) {
        return rsa->meth->rsa_verify(dtype, m, m_len, sigbuf, siglen, rsa);
    }

    return int_rsa_verify(dtype, m, m_len, NULL, NULL, sigbuf, siglen, rsa);
}
