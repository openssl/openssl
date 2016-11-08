/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define TLS13_MAX_LABEL_LEN     246

/* Always filled with zeros */
static const unsigned char default_zeros[EVP_MAX_MD_SIZE];

static const unsigned char keylabel[] = "key";
static const unsigned char ivlabel[] = "iv";

/*
 * Given a |secret|; a |label| of length |labellen|; and a |hash| of the
 * handshake messages, derive a new secret |outlen| bytes long and store it in
 * the location pointed to be |out|. The |hash| value may be NULL.
 *
 * Returns 1 on success  0 on failure.
 */
static int tls13_hkdf_expand(SSL *s, const unsigned char *secret,
                             const unsigned char *label, size_t labellen,
                             const unsigned char *hash,
                             unsigned char *out, size_t outlen)
{
    const unsigned char label_prefix[] = "TLS 1.3, ";
    const EVP_MD *md = ssl_handshake_md(s);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ret;
    size_t hkdflabellen;
    size_t hashlen;
    /*
     * 2 bytes for length of whole HkdfLabel + 1 byte for length of combined
     * prefix and label + bytes for the label itself + bytes for the hash
     */
    unsigned char hkdflabel[sizeof(uint16_t) + sizeof(uint8_t) +
                            + sizeof(label_prefix) + TLS13_MAX_LABEL_LEN
                            + EVP_MAX_MD_SIZE];
    WPACKET pkt;

    if (pctx == NULL)
        return 0;

    hashlen = EVP_MD_size(md);

    if (!WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
            || !WPACKET_put_bytes_u16(&pkt, outlen)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_memcpy(&pkt, label_prefix, sizeof(label_prefix) - 1)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_close(&pkt)
            || !WPACKET_sub_memcpy_u8(&pkt, hash, (hash == NULL) ? 0 : hashlen)
            || !WPACKET_get_total_written(&pkt, &hkdflabellen)
            || !WPACKET_finish(&pkt)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
               <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, hashlen) <= 0
            || EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdflabel, hkdflabellen) <= 0
            || EVP_PKEY_derive(pctx, out, &outlen) <= 0;

    EVP_PKEY_CTX_free(pctx);

    return ret == 0;
}

/*
 * Given a input secret |insecret| and a |label| of length |labellen|, derive a
 * new |secret|. This will be the length of the current hash output size and
 * will be based on the current state of the handshake hashes.
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_derive_secret(SSL *s, const unsigned char *insecret,
                        const unsigned char *label, size_t labellen,
                        unsigned char *secret)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hashlen;

    if (!ssl3_digest_cached_records(s, 1))
        return 0;

    if (!ssl_handshake_hash(s, hash, sizeof(hash), &hashlen))
        return 0;

    return tls13_hkdf_expand(s, insecret, label, labellen, hash, secret,
                             hashlen);
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes.
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_derive_key(SSL *s, const unsigned char *secret, unsigned char *key,
                     size_t keylen)
{
    return tls13_hkdf_expand(s, secret, keylabel, sizeof(keylabel) - 1, NULL,
                             key, keylen);
}

/*
 * Given a |secret| generate an |iv| of length |ivlen| bytes.
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_derive_iv(SSL *s, const unsigned char *secret, unsigned char *iv,
                    size_t ivlen)
{
    return tls13_hkdf_expand(s, secret, ivlabel, sizeof(ivlabel) - 1, NULL,
                             iv, ivlen);
}

/*
 * Given the previous secret |prevsecret| and a new input secret |insecret| of
 * length |insecretlen|, generate a new secret and store it in the location
 * pointed to by |outsecret|.
 *
 * Returns 1 on success  0 on failure.
 */
static int tls13_generate_secret(SSL *s, const unsigned char *prevsecret,
                                 const unsigned char *insecret,
                                 size_t insecretlen,
                                 unsigned char *outsecret)
{
    const EVP_MD *md = ssl_handshake_md(s);
    size_t mdlen, prevsecretlen;
    int ret;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (pctx == NULL)
        return 0;

    mdlen = EVP_MD_size(md);

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        prevsecretlen = mdlen;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
               <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0
            || EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen)
               <= 0
            || EVP_PKEY_derive(pctx, outsecret, &mdlen)
               <= 0;

    EVP_PKEY_CTX_free(pctx);
    return ret == 0;
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the early
 * secret.
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_generate_early_secret(SSL *s, const unsigned char *insecret,
                                size_t insecretlen)
{
    return tls13_generate_secret(s, NULL, insecret, insecretlen,
                                 (unsigned char *)&s->early_secret);
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the
 * handshake secret. This requires the early secret to already have been
 * generated.
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_generate_handshake_secret(SSL *s, const unsigned char *insecret,
                                size_t insecretlen)
{
    return tls13_generate_secret(s, s->early_secret, insecret, insecretlen,
                                 (unsigned char *)&s->handshake_secret);
}

/*
 * Given the handshake secret |prev| of length |prevlen| generate the master
 * secret and store its length in |*secret_size|
 *
 * Returns 1 on success  0 on failure.
 */
int tls13_generate_master_secret(SSL *s, unsigned char *out,
                                 unsigned char *prev, size_t prevlen,
                                 size_t *secret_size)
{
    *secret_size = EVP_MD_size(ssl_handshake_md(s));
    return tls13_generate_secret(s, prev, NULL, 0, out);
}


