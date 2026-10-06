/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "internal/pool.h"
#include "internal/refcount.h"

#include "ssl_local.h"

SSL_CREDENTIAL *ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE type)
{
    SSL_CREDENTIAL *cred;

    if ((cred = OPENSSL_zalloc(sizeof(*cred))) == NULL)
        return NULL;
    cred->type = type;
    if (!CRYPTO_NEW_REF(&cred->references, 1)) {
        OPENSSL_free(cred);
        return NULL;
    }
    return cred;
}

int ossl_ssl_credential_set1_cert_chain(SSL_CREDENTIAL *cred,
    STACK_OF(CRYPTO_BUFFER) *chain)
{
    STACK_OF(CRYPTO_BUFFER) *copy = NULL;
    int i;

    if (chain != NULL) {
        if ((copy = sk_CRYPTO_BUFFER_dup(chain)) == NULL)
            return 0;
        for (i = 0; i < sk_CRYPTO_BUFFER_num(copy); i++) {
            if (!CRYPTO_BUFFER_up_ref(sk_CRYPTO_BUFFER_value(copy, i))) {
                while (--i >= 0)
                    CRYPTO_BUFFER_free(sk_CRYPTO_BUFFER_value(copy, i));
                sk_CRYPTO_BUFFER_free(copy);
                return 0;
            }
        }
    }
    sk_CRYPTO_BUFFER_pop_free(cred->chain, CRYPTO_BUFFER_free);
    cred->chain = copy;
    return 1;
}

int ossl_ssl_credential_set1_private_key(SSL_CREDENTIAL *cred, EVP_PKEY *pkey)
{
    if (pkey != NULL && !EVP_PKEY_up_ref(pkey))
        return 0;
    EVP_PKEY_free(cred->pkey);
    cred->pkey = pkey;
    return 1;
}

int ossl_ssl_credential_set1_trust_anchor_id(SSL_CREDENTIAL *cred,
    const uint8_t *id, size_t id_len)
{
    uint8_t *copy = NULL;

    if (id_len != 0 && (copy = OPENSSL_memdup(id, id_len)) == NULL)
        return 0;
    OPENSSL_free(cred->trust_anchor_id);
    cred->trust_anchor_id = copy;
    cred->trust_anchor_id_len = id_len;
    return 1;
}

int ossl_ssl_credential_add1_trust_anchor_group(SSL_CREDENTIAL *cred,
    const uint8_t *pattern, size_t pattern_len)
{
    SSL_TRUST_ANCHOR_PATTERN *groups;
    uint8_t *copy = NULL;

    if (pattern_len != 0
        && (copy = OPENSSL_memdup(pattern, pattern_len)) == NULL)
        return 0;
    groups = OPENSSL_realloc_array(cred->groups, cred->group_count + 1,
        sizeof(*groups));
    if (groups == NULL) {
        OPENSSL_free(copy);
        return 0;
    }
    cred->groups = groups;
    groups[cred->group_count].pattern = copy;
    groups[cred->group_count].pattern_len = pattern_len;
    cred->group_count++;
    return 1;
}

int ossl_ssl_credential_set1_certificate_properties(SSL_CREDENTIAL *cred,
    const uint8_t *props, size_t props_len)
{
    PACKET pkt, list, data;
    int have_last_type = 0;
    unsigned int last_type = 0;

    if (!PACKET_buf_init(&pkt, props, props_len)
        || !PACKET_get_length_prefixed_2(&pkt, &list)
        || PACKET_remaining(&pkt) != 0)
        goto malformed;

    while (PACKET_remaining(&list) > 0) {
        unsigned int type;

        if (!PACKET_get_net_2(&list, &type)
            || !PACKET_get_length_prefixed_2(&list, &data)
            /* Properties must be sorted by type with no duplicates. */
            || (have_last_type && type <= last_type))
            goto malformed;
        have_last_type = 1;
        last_type = type;

        switch (type) {
        case 0: /* trust_anchor_id */
            if (PACKET_remaining(&data) == 0
                || PACKET_remaining(&data) > TLSEXT_TRUST_ANCHOR_ID_MAX_LEN)
                goto malformed;
            if (!ossl_ssl_credential_set1_trust_anchor_id(cred,
                    PACKET_data(&data), PACKET_remaining(&data)))
                return 0;
            break;
        case 1: { /* trust_anchor_groups */
            PACKET patterns, pattern;

            if (!PACKET_get_length_prefixed_2(&data, &patterns)
                || PACKET_remaining(&data) != 0
                || PACKET_remaining(&patterns) == 0)
                goto malformed;
            while (PACKET_remaining(&patterns) > 0) {
                if (!PACKET_get_length_prefixed_1(&patterns, &pattern))
                    goto malformed;
                if (!ossl_ssl_credential_add1_trust_anchor_group(cred,
                        PACKET_data(&pattern), PACKET_remaining(&pattern)))
                    return 0;
            }
            break;
        }
        case 2: /* trust_anchor_negotiation */
            if (PACKET_remaining(&data) != 0)
                goto malformed;
            break;
        default:
            /* Unknown property types are ignored but must be well formed. */
            break;
        }
    }

    return 1;

malformed:
    ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_CERTIFICATE_PROPERTY_LIST);
    return 0;
}

/*
 * Remove an encoded base-128 integer from the front of in, leaving its
 * encoding in out (section 5.3.1 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
 * Fails if in is empty, or the integer is not minimally encoded or is
 * truncated.
 */
static int pattern_get_int(PACKET *in, PACKET *out)
{
    const unsigned char *data = PACKET_data(in);
    size_t len = PACKET_remaining(in), i;

    if (len == 0 || data[0] == 0x80)
        return 0;
    for (i = 0; i < len && (data[i] & 0x80) != 0; i++)
        continue;
    if (i == len)
        return 0;
    return PACKET_get_sub_packet(in, out, i + 1);
}

/*
 * Compare two encoded base-128 integers, returning a negative, zero or
 * positive value as a is less than, equal to or greater than b.  A minimal
 * encoding orders by length, then by bytes.
 */
static int pattern_int_cmp(const PACKET *a, const PACKET *b)
{
    if (PACKET_remaining(a) != PACKET_remaining(b))
        return PACKET_remaining(a) < PACKET_remaining(b) ? -1 : 1;
    return memcmp(PACKET_data(a), PACKET_data(b), PACKET_remaining(a));
}

int ossl_ssl_trust_anchor_pattern_contains(const uint8_t *pattern,
    size_t pattern_len, const uint8_t *id, size_t id_len)
{
    PACKET pat, in, v, min, max;
    unsigned int b;

    if (!PACKET_buf_init(&pat, pattern, pattern_len)
        || !PACKET_buf_init(&in, id, id_len))
        return 0;
    while (PACKET_remaining(&in) > 0) {
        if (!pattern_get_int(&in, &v)
            || !pattern_get_int(&pat, &min)
            || pattern_int_cmp(&v, &min) < 0)
            return 0;
        /* A max of infinity is the single byte 0x80. */
        if (PACKET_peek_1(&pat, &b) && b == 0x80 && PACKET_forward(&pat, 1))
            continue;
        if (!pattern_get_int(&pat, &max) || pattern_int_cmp(&max, &v) < 0)
            return 0;
    }
    return PACKET_remaining(&pat) == 0;
}

int ossl_ssl_credential_matches_request(const SSL_CREDENTIAL *cred,
    const uint8_t *ids, size_t ids_len)
{
    PACKET list, id;
    size_t i;

    if (!PACKET_buf_init(&list, ids, ids_len))
        return 0;
    while (PACKET_remaining(&list) > 0) {
        /* The list was validated when it was parsed. */
        if (!PACKET_get_length_prefixed_1(&list, &id))
            return 0;
        if (cred->trust_anchor_id != NULL
            && PACKET_remaining(&id) == cred->trust_anchor_id_len
            && memcmp(PACKET_data(&id), cred->trust_anchor_id,
                   cred->trust_anchor_id_len)
                == 0)
            return 1;
        for (i = 0; i < cred->group_count; i++)
            if (ossl_ssl_trust_anchor_pattern_contains(cred->groups[i].pattern,
                    cred->groups[i].pattern_len, PACKET_data(&id),
                    PACKET_remaining(&id)))
                return 1;
    }

    return 0;
}

int SSL_CREDENTIAL_up_ref(SSL_CREDENTIAL *cred)
{
    int i;

    if (cred == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return CRYPTO_UP_REF(&cred->references, &i);
}

void SSL_CREDENTIAL_free(SSL_CREDENTIAL *cred)
{
    int i;
    size_t j;

    if (cred == NULL)
        return;
    CRYPTO_DOWN_REF(&cred->references, &i);
    REF_PRINT_COUNT("SSL_CREDENTIAL", i, cred);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    sk_CRYPTO_BUFFER_pop_free(cred->chain, CRYPTO_BUFFER_free);
    EVP_PKEY_free(cred->pkey);
    OPENSSL_free(cred->trust_anchor_id);
    for (j = 0; j < cred->group_count; j++)
        OPENSSL_free(cred->groups[j].pattern);
    OPENSSL_free(cred->groups);
    CRYPTO_FREE_REF(&cred->references);
    OPENSSL_free(cred);
}

int SSL_CTX_add1_credential(SSL_CTX *ctx, SSL_CREDENTIAL *cred)
{
    if (ctx == NULL || cred == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ctx->cert->credentials == NULL
        && (ctx->cert->credentials = sk_SSL_CREDENTIAL_new_null()) == NULL)
        return 0;
    if (!SSL_CREDENTIAL_up_ref(cred))
        return 0;
    if (sk_SSL_CREDENTIAL_push(ctx->cert->credentials, cred) <= 0) {
        SSL_CREDENTIAL_free(cred);
        ERR_raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB);
        return 0;
    }
    return 1;
}

static size_t credential_size(const SSL_CREDENTIAL *cred)
{
    size_t total = 0;
    int i;

    for (i = 0; i < sk_CRYPTO_BUFFER_num(cred->chain); i++)
        total += CRYPTO_BUFFER_len(sk_CRYPTO_BUFFER_value(cred->chain, i));
    return total;
}

int SSL_CREDENTIAL_size_cmp(const SSL_CREDENTIAL *const *a,
    const SSL_CREDENTIAL *const *b)
{
    size_t sa = credential_size(*a);
    size_t sb = credential_size(*b);

    return sa < sb ? -1 : (sa > sb ? 1 : 0);
}

static int is_private_key_pem_name(const char *name)
{
    return strcmp(name, "PRIVATE KEY") == 0
        || strcmp(name, "ENCRYPTED PRIVATE KEY") == 0
        || strcmp(name, "EC PRIVATE KEY") == 0
        || strcmp(name, "RSA PRIVATE KEY") == 0;
}

/*
 * Read the next PEM block from in, counting it in *block.  Returns 1 with the
 * block in *name, *header, *data and *len, 0 at the end of the input, or -1
 * on error.
 */
static int read_pem_block(BIO *in, int *block, char **name, char **header,
    unsigned char **data, long *len)
{
    if (!PEM_read_bio(in, name, header, data, len)) {
        /* A missing start line at this point simply means end of input. */
        if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
            ERR_clear_error();
            return 0;
        }
        return -1;
    }
    (*block)++;
    return 1;
}

/*
 * Decode the private key in PEM block number block and append it to keys.  An
 * encrypted key is rejected, naming the block in the error data.
 */
static int push_private_key(STACK_OF(EVP_PKEY) *keys, int block,
    const char *name, const char *header, const unsigned char *data, long len)
{
    EVP_PKEY *key;

    /*
     * A PKCS#8 encrypted key, or a traditional key whose headers carry the
     * encryption parameters.
     */
    if (strcmp(name, "ENCRYPTED PRIVATE KEY") == 0 || header[0] != '\0') {
        ERR_raise_data(ERR_LIB_SSL, SSL_R_UNEXPECTED_PEM_BLOCK,
            "PEM block %d", block);
        return 0;
    }
    if ((key = d2i_AutoPrivateKey(NULL, &data, len)) == NULL)
        return 0;
    if (sk_EVP_PKEY_push(keys, key) <= 0) {
        EVP_PKEY_free(key);
        return 0;
    }
    return 1;
}

/* Return the key in keys whose public half is pubkey, or NULL if none. */
static EVP_PKEY *find_key(STACK_OF(EVP_PKEY) *keys, EVP_PKEY *pubkey)
{
    int i;

    for (i = 0; i < sk_EVP_PKEY_num(keys); i++) {
        EVP_PKEY *key = sk_EVP_PKEY_value(keys, i);

        if (EVP_PKEY_eq(pubkey, key) == 1)
            return key;
    }
    return NULL;
}

/*
 * Set the private key of cred to the key, from file_keys or keys, whose public
 * half matches the SubjectPublicKeyInfo of its leaf certificate.  The key is
 * up-referenced.  Returns 0 if the leaf does not parse or no key matches.
 */
static int set_key_for_leaf(SSL_CREDENTIAL *cred,
    STACK_OF(EVP_PKEY) *file_keys, STACK_OF(EVP_PKEY) *keys)
{
    const CRYPTO_BUFFER *leaf = sk_CRYPTO_BUFFER_value(cred->chain, 0);
    const unsigned char *der = CRYPTO_BUFFER_data(leaf);
    X509 *x = d2i_X509(NULL, &der, (long)CRYPTO_BUFFER_len(leaf));
    EVP_PKEY *pubkey, *match = NULL;

    /* If the leaf did not parse, d2i_X509() has queued the reason. */
    if (x == NULL)
        return 0;
    if ((pubkey = X509_get0_pubkey(x)) != NULL
        && (match = find_key(file_keys, pubkey)) == NULL)
        match = find_key(keys, pubkey);
    X509_free(x);
    if (match == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_NO_MATCHING_PRIVATE_KEY);
        return 0;
    }
    return ossl_ssl_credential_set1_private_key(cred, match);
}

/*
 * Assemble one certification path into a credential, without its key, and
 * append it to out.  certs is the leaf-first chain and properties its
 * CERTIFICATE PROPERTIES block.  Returns 0, leaving out unchanged, if the
 * chain is empty or has no property list.
 */
static int append_parsed_credential(STACK_OF(CRYPTO_BUFFER) *certs,
    CRYPTO_BUFFER *properties, STACK_OF(SSL_CREDENTIAL) *out)
{
    SSL_CREDENTIAL *cred;

    /* A path needs both a chain and its property list. */
    if (sk_CRYPTO_BUFFER_num(certs) <= 0 || properties == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_PEM_BLOCK);
        return 0;
    }

    if ((cred = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509)) == NULL)
        return 0;

    if (!ossl_ssl_credential_set1_cert_chain(cred, certs)
        || !ossl_ssl_credential_set1_certificate_properties(cred,
            CRYPTO_BUFFER_data(properties), CRYPTO_BUFFER_len(properties))
        || sk_SSL_CREDENTIAL_push(out, cred) <= 0) {
        SSL_CREDENTIAL_free(cred);
        return 0;
    }
    return 1;
}

int SSL_parse_certificates_with_properties(BIO *in, STACK_OF(EVP_PKEY) *keys,
    STACK_OF(SSL_CREDENTIAL) *out_credentials)
{
    STACK_OF(CRYPTO_BUFFER) *certs = NULL;
    STACK_OF(EVP_PKEY) *file_keys = NULL;
    CRYPTO_BUFFER *properties = NULL;
    int have_path = 0, ret = 0, start, i, block = 0, r;

    if (in == NULL || out_credentials == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Remember the starting size so a failure leaves out_credentials as is. */
    start = sk_SSL_CREDENTIAL_num(out_credentials);

    if ((certs = sk_CRYPTO_BUFFER_new_null()) == NULL
        || (file_keys = sk_EVP_PKEY_new_null()) == NULL)
        goto err;

    for (;;) {
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int ok = 1;

        if ((r = read_pem_block(in, &block, &name, &header, &data, &len)) == 0)
            break;
        if (r < 0)
            goto err;

        if (strcmp(name, "CERTIFICATE PROPERTIES") == 0) {
            /* A property list begins a new path; append the previous one. */
            if (have_path
                && !append_parsed_credential(certs, properties,
                    out_credentials))
                ok = 0;
            sk_CRYPTO_BUFFER_pop_free(certs, CRYPTO_BUFFER_free);
            CRYPTO_BUFFER_free(properties);
            certs = sk_CRYPTO_BUFFER_new_null();
            properties = CRYPTO_BUFFER_new(data, (size_t)len, NULL);
            have_path = 1;
            if (certs == NULL || properties == NULL)
                ok = 0;
        } else if (strcmp(name, "CERTIFICATE") == 0) {
            CRYPTO_BUFFER *buf = CRYPTO_BUFFER_new(data, (size_t)len, NULL);

            if (buf == NULL || sk_CRYPTO_BUFFER_push(certs, buf) <= 0) {
                CRYPTO_BUFFER_free(buf);
                ok = 0;
            }
            have_path = 1;
        } else if (is_private_key_pem_name(name)) {
            ok = push_private_key(file_keys, block, name, header, data, len);
        }
        /* Any other block is skipped. */

        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        if (!ok)
            goto err;
    }

    if (have_path
        && !append_parsed_credential(certs, properties, out_credentials))
        goto err;

    /* Every key in the input is read, so a path's key may be anywhere. */
    for (i = start; i < sk_SSL_CREDENTIAL_num(out_credentials); i++)
        if (!set_key_for_leaf(sk_SSL_CREDENTIAL_value(out_credentials, i),
                file_keys, keys))
            goto err;

    ret = 1;
err:
    sk_CRYPTO_BUFFER_pop_free(certs, CRYPTO_BUFFER_free);
    CRYPTO_BUFFER_free(properties);
    sk_EVP_PKEY_pop_free(file_keys, EVP_PKEY_free);
    /* On failure, drop anything this call added to out_credentials. */
    if (!ret) {
        while (sk_SSL_CREDENTIAL_num(out_credentials) > start)
            SSL_CREDENTIAL_free(sk_SSL_CREDENTIAL_pop(out_credentials));
    }
    return ret;
}

int SSL_parse_private_keys(BIO *in, STACK_OF(EVP_PKEY) *out_keys)
{
    int start, ret = 0, block = 0, r;

    if (in == NULL || out_keys == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Remember the starting size so a failure leaves out_keys unchanged. */
    start = sk_EVP_PKEY_num(out_keys);

    for (;;) {
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int ok = 1;

        if ((r = read_pem_block(in, &block, &name, &header, &data, &len)) == 0)
            break;
        if (r < 0)
            goto err;

        /* Blocks other than private keys are skipped. */
        if (is_private_key_pem_name(name))
            ok = push_private_key(out_keys, block, name, header, data, len);

        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        if (!ok)
            goto err;
    }

    ret = 1;
err:
    if (!ret) {
        while (sk_EVP_PKEY_num(out_keys) > start)
            EVP_PKEY_free(sk_EVP_PKEY_pop(out_keys));
    }
    return ret;
}
