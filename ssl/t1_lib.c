/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ocsp.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include "ssl_locl.h"
#include <openssl/ct.h>

static int tls_decrypt_ticket(SSL *s, const unsigned char *tick, size_t ticklen,
                              const unsigned char *sess_id, size_t sesslen,
                              SSL_SESSION **psess);

SSL3_ENC_METHOD const TLSv1_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    0,
    ssl3_set_handshake_header,
    tls_close_construct_packet,
    ssl3_handshake_write
};

SSL3_ENC_METHOD const TLSv1_1_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_EXPLICIT_IV,
    ssl3_set_handshake_header,
    tls_close_construct_packet,
    ssl3_handshake_write
};

SSL3_ENC_METHOD const TLSv1_2_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF
        | SSL_ENC_FLAG_TLS1_2_CIPHERS,
    ssl3_set_handshake_header,
    tls_close_construct_packet,
    ssl3_handshake_write
};

SSL3_ENC_METHOD const TLSv1_3_enc_data = {
    tls13_enc,
    tls1_mac,
    tls13_setup_key_block,
    tls13_generate_master_secret,
    tls13_change_cipher_state,
    tls13_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls13_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF,
    ssl3_set_handshake_header,
    tls_close_construct_packet,
    ssl3_handshake_write
};

long tls1_default_timeout(void)
{
    /*
     * 2 hours, the 24 hours mentioned in the TLSv1 spec is way too long for
     * http, the cache would over fill
     */
    return (60 * 60 * 2);
}

int tls1_new(SSL *s)
{
    if (!ssl3_new(s))
        return (0);
    s->method->ssl_clear(s);
    return (1);
}

void tls1_free(SSL *s)
{
    OPENSSL_free(s->ext.session_ticket);
    ssl3_free(s);
}

void tls1_clear(SSL *s)
{
    ssl3_clear(s);
    if (s->method->version == TLS_ANY_VERSION)
        s->version = TLS_MAX_VERSION;
    else
        s->version = s->method->version;
}

#ifndef OPENSSL_NO_EC

typedef struct {
    int nid;                    /* Curve NID */
    int secbits;                /* Bits of security (from SP800-57) */
    unsigned int flags;         /* Flags: currently just field type */
} tls_curve_info;

/*
 * Table of curve information.
 * Do not delete entries or reorder this array! It is used as a lookup
 * table: the index of each entry is one less than the TLS curve id.
 */
static const tls_curve_info nid_list[] = {
    {NID_sect163k1, 80, TLS_CURVE_CHAR2}, /* sect163k1 (1) */
    {NID_sect163r1, 80, TLS_CURVE_CHAR2}, /* sect163r1 (2) */
    {NID_sect163r2, 80, TLS_CURVE_CHAR2}, /* sect163r2 (3) */
    {NID_sect193r1, 80, TLS_CURVE_CHAR2}, /* sect193r1 (4) */
    {NID_sect193r2, 80, TLS_CURVE_CHAR2}, /* sect193r2 (5) */
    {NID_sect233k1, 112, TLS_CURVE_CHAR2}, /* sect233k1 (6) */
    {NID_sect233r1, 112, TLS_CURVE_CHAR2}, /* sect233r1 (7) */
    {NID_sect239k1, 112, TLS_CURVE_CHAR2}, /* sect239k1 (8) */
    {NID_sect283k1, 128, TLS_CURVE_CHAR2}, /* sect283k1 (9) */
    {NID_sect283r1, 128, TLS_CURVE_CHAR2}, /* sect283r1 (10) */
    {NID_sect409k1, 192, TLS_CURVE_CHAR2}, /* sect409k1 (11) */
    {NID_sect409r1, 192, TLS_CURVE_CHAR2}, /* sect409r1 (12) */
    {NID_sect571k1, 256, TLS_CURVE_CHAR2}, /* sect571k1 (13) */
    {NID_sect571r1, 256, TLS_CURVE_CHAR2}, /* sect571r1 (14) */
    {NID_secp160k1, 80, TLS_CURVE_PRIME}, /* secp160k1 (15) */
    {NID_secp160r1, 80, TLS_CURVE_PRIME}, /* secp160r1 (16) */
    {NID_secp160r2, 80, TLS_CURVE_PRIME}, /* secp160r2 (17) */
    {NID_secp192k1, 80, TLS_CURVE_PRIME}, /* secp192k1 (18) */
    {NID_X9_62_prime192v1, 80, TLS_CURVE_PRIME}, /* secp192r1 (19) */
    {NID_secp224k1, 112, TLS_CURVE_PRIME}, /* secp224k1 (20) */
    {NID_secp224r1, 112, TLS_CURVE_PRIME}, /* secp224r1 (21) */
    {NID_secp256k1, 128, TLS_CURVE_PRIME}, /* secp256k1 (22) */
    {NID_X9_62_prime256v1, 128, TLS_CURVE_PRIME}, /* secp256r1 (23) */
    {NID_secp384r1, 192, TLS_CURVE_PRIME}, /* secp384r1 (24) */
    {NID_secp521r1, 256, TLS_CURVE_PRIME}, /* secp521r1 (25) */
    {NID_brainpoolP256r1, 128, TLS_CURVE_PRIME}, /* brainpoolP256r1 (26) */
    {NID_brainpoolP384r1, 192, TLS_CURVE_PRIME}, /* brainpoolP384r1 (27) */
    {NID_brainpoolP512r1, 256, TLS_CURVE_PRIME}, /* brainpool512r1 (28) */
    {NID_X25519, 128, TLS_CURVE_CUSTOM}, /* X25519 (29) */
};

static const unsigned char ecformats_default[] = {
    TLSEXT_ECPOINTFORMAT_uncompressed,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2
};

/* The default curves */
static const unsigned char eccurves_default[] = {
    0, 29,                      /* X25519 (29) */
    0, 23,                      /* secp256r1 (23) */
    0, 25,                      /* secp521r1 (25) */
    0, 24,                      /* secp384r1 (24) */
};

static const unsigned char suiteb_curves[] = {
    0, TLSEXT_curve_P_256,
    0, TLSEXT_curve_P_384
};

int tls1_ec_curve_id2nid(int curve_id, unsigned int *pflags)
{
    const tls_curve_info *cinfo;
    /* ECC curves from RFC 4492 and RFC 7027 */
    if ((curve_id < 1) || ((unsigned int)curve_id > OSSL_NELEM(nid_list)))
        return 0;
    cinfo = nid_list + curve_id - 1;
    if (pflags)
        *pflags = cinfo->flags;
    return cinfo->nid;
}

int tls1_ec_nid2curve_id(int nid)
{
    size_t i;
    for (i = 0; i < OSSL_NELEM(nid_list); i++) {
        if (nid_list[i].nid == nid)
            return (int)(i + 1);
    }
    return 0;
}

/*
 * Get curves list, if "sess" is set return client curves otherwise
 * preferred list.
 * Sets |num_curves| to the number of curves in the list, i.e.,
 * the length of |pcurves| is 2 * num_curves.
 * Returns 1 on success and 0 if the client curves list has invalid format.
 * The latter indicates an internal error: we should not be accepting such
 * lists in the first place.
 * TODO(emilia): we should really be storing the curves list in explicitly
 * parsed form instead. (However, this would affect binary compatibility
 * so cannot happen in the 1.0.x series.)
 */
int tls1_get_curvelist(SSL *s, int sess, const unsigned char **pcurves,
                       size_t *num_curves)
{
    size_t pcurveslen = 0;

    if (sess) {
        *pcurves = s->session->ext.supportedgroups;
        pcurveslen = s->session->ext.supportedgroups_len;
    } else {
        /* For Suite B mode only include P-256, P-384 */
        switch (tls1_suiteb(s)) {
        case SSL_CERT_FLAG_SUITEB_128_LOS:
            *pcurves = suiteb_curves;
            pcurveslen = sizeof(suiteb_curves);
            break;

        case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
            *pcurves = suiteb_curves;
            pcurveslen = 2;
            break;

        case SSL_CERT_FLAG_SUITEB_192_LOS:
            *pcurves = suiteb_curves + 2;
            pcurveslen = 2;
            break;
        default:
            *pcurves = s->ext.supportedgroups;
            pcurveslen = s->ext.supportedgroups_len;
        }
        if (!*pcurves) {
            *pcurves = eccurves_default;
            pcurveslen = sizeof(eccurves_default);
        }
    }

    /* We do not allow odd length arrays to enter the system. */
    if (pcurveslen & 1) {
        SSLerr(SSL_F_TLS1_GET_CURVELIST, ERR_R_INTERNAL_ERROR);
        *num_curves = 0;
        return 0;
    }
    *num_curves = pcurveslen / 2;
    return 1;
}

/* See if curve is allowed by security callback */
int tls_curve_allowed(SSL *s, const unsigned char *curve, int op)
{
    const tls_curve_info *cinfo;
    if (curve[0])
        return 1;
    if ((curve[1] < 1) || ((size_t)curve[1] > OSSL_NELEM(nid_list)))
        return 0;
    cinfo = &nid_list[curve[1] - 1];
# ifdef OPENSSL_NO_EC2M
    if (cinfo->flags & TLS_CURVE_CHAR2)
        return 0;
# endif
    return ssl_security(s, op, cinfo->secbits, cinfo->nid, (void *)curve);
}

/* Check a curve is one of our preferences */
int tls1_check_curve(SSL *s, const unsigned char *p, size_t len)
{
    const unsigned char *curves;
    size_t num_curves, i;
    unsigned int suiteb_flags = tls1_suiteb(s);
    if (len != 3 || p[0] != NAMED_CURVE_TYPE)
        return 0;
    /* Check curve matches Suite B preferences */
    if (suiteb_flags) {
        unsigned long cid = s->s3->tmp.new_cipher->id;
        if (p[1])
            return 0;
        if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
            if (p[2] != TLSEXT_curve_P_256)
                return 0;
        } else if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
            if (p[2] != TLSEXT_curve_P_384)
                return 0;
        } else                  /* Should never happen */
            return 0;
    }
    if (!tls1_get_curvelist(s, 0, &curves, &num_curves))
        return 0;
    for (i = 0; i < num_curves; i++, curves += 2) {
        if (p[1] == curves[0] && p[2] == curves[1])
            return tls_curve_allowed(s, p + 1, SSL_SECOP_CURVE_CHECK);
    }
    return 0;
}

/*-
 * For nmatch >= 0, return the NID of the |nmatch|th shared group or NID_undef
 * if there is no match.
 * For nmatch == -1, return number of matches
 * For nmatch == -2, return the NID of the group to use for
 * an EC tmp key, or NID_undef if there is no match.
 */
int tls1_shared_group(SSL *s, int nmatch)
{
    const unsigned char *pref, *supp;
    size_t num_pref, num_supp, i, j;
    int k;

    /* Can't do anything on client side */
    if (s->server == 0)
        return -1;
    if (nmatch == -2) {
        if (tls1_suiteb(s)) {
            /*
             * For Suite B ciphersuite determines curve: we already know
             * these are acceptable due to previous checks.
             */
            unsigned long cid = s->s3->tmp.new_cipher->id;

            if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                return NID_X9_62_prime256v1; /* P-256 */
            if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
                return NID_secp384r1; /* P-384 */
            /* Should never happen */
            return NID_undef;
        }
        /* If not Suite B just return first preference shared curve */
        nmatch = 0;
    }
    /*
     * Avoid truncation. tls1_get_curvelist takes an int
     * but s->options is a long...
     */
    if (!tls1_get_curvelist(s,
            (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0,
            &supp, &num_supp))
        /* In practice, NID_undef == 0 but let's be precise. */
        return nmatch == -1 ? 0 : NID_undef;
    if (!tls1_get_curvelist(s,
            (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) == 0,
            &pref, &num_pref))
        return nmatch == -1 ? 0 : NID_undef;

    for (k = 0, i = 0; i < num_pref; i++, pref += 2) {
        const unsigned char *tsupp = supp;

        for (j = 0; j < num_supp; j++, tsupp += 2) {
            if (pref[0] == tsupp[0] && pref[1] == tsupp[1]) {
                if (!tls_curve_allowed(s, pref, SSL_SECOP_CURVE_SHARED))
                    continue;
                if (nmatch == k) {
                    int id = (pref[0] << 8) | pref[1];

                    return tls1_ec_curve_id2nid(id, NULL);
                }
                k++;
            }
        }
    }
    if (nmatch == -1)
        return k;
    /* Out of range (nmatch > k). */
    return NID_undef;
}

int tls1_set_groups(unsigned char **pext, size_t *pextlen,
                    int *groups, size_t ngroups)
{
    unsigned char *glist, *p;
    size_t i;
    /*
     * Bitmap of groups included to detect duplicates: only works while group
     * ids < 32
     */
    unsigned long dup_list = 0;
    glist = OPENSSL_malloc(ngroups * 2);
    if (glist == NULL)
        return 0;
    for (i = 0, p = glist; i < ngroups; i++) {
        unsigned long idmask;
        int id;
        /* TODO(TLS1.3): Convert for DH groups */
        id = tls1_ec_nid2curve_id(groups[i]);
        idmask = 1L << id;
        if (!id || (dup_list & idmask)) {
            OPENSSL_free(glist);
            return 0;
        }
        dup_list |= idmask;
        s2n(id, p);
    }
    OPENSSL_free(*pext);
    *pext = glist;
    *pextlen = ngroups * 2;
    return 1;
}

# define MAX_CURVELIST   28

typedef struct {
    size_t nidcnt;
    int nid_arr[MAX_CURVELIST];
} nid_cb_st;

static int nid_cb(const char *elem, int len, void *arg)
{
    nid_cb_st *narg = arg;
    size_t i;
    int nid;
    char etmp[20];
    if (elem == NULL)
        return 0;
    if (narg->nidcnt == MAX_CURVELIST)
        return 0;
    if (len > (int)(sizeof(etmp) - 1))
        return 0;
    memcpy(etmp, elem, len);
    etmp[len] = 0;
    nid = EC_curve_nist2nid(etmp);
    if (nid == NID_undef)
        nid = OBJ_sn2nid(etmp);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(etmp);
    if (nid == NID_undef)
        return 0;
    for (i = 0; i < narg->nidcnt; i++)
        if (narg->nid_arr[i] == nid)
            return 0;
    narg->nid_arr[narg->nidcnt++] = nid;
    return 1;
}

/* Set groups based on a colon separate list */
int tls1_set_groups_list(unsigned char **pext, size_t *pextlen, const char *str)
{
    nid_cb_st ncb;
    ncb.nidcnt = 0;
    if (!CONF_parse_list(str, ':', 1, nid_cb, &ncb))
        return 0;
    if (pext == NULL)
        return 1;
    return tls1_set_groups(pext, pextlen, ncb.nid_arr, ncb.nidcnt);
}

/* For an EC key set TLS id and required compression based on parameters */
static int tls1_set_ec_id(unsigned char *curve_id, unsigned char *comp_id,
                          EC_KEY *ec)
{
    int id;
    const EC_GROUP *grp;
    if (!ec)
        return 0;
    /* Determine if it is a prime field */
    grp = EC_KEY_get0_group(ec);
    if (!grp)
        return 0;
    /* Determine curve ID */
    id = EC_GROUP_get_curve_name(grp);
    id = tls1_ec_nid2curve_id(id);
    /* If no id return error: we don't support arbitrary explicit curves */
    if (id == 0)
        return 0;
    curve_id[0] = 0;
    curve_id[1] = (unsigned char)id;
    if (comp_id) {
        if (EC_KEY_get0_public_key(ec) == NULL)
            return 0;
        if (EC_KEY_get_conv_form(ec) == POINT_CONVERSION_UNCOMPRESSED) {
            *comp_id = TLSEXT_ECPOINTFORMAT_uncompressed;
        } else {
            if ((nid_list[id - 1].flags & TLS_CURVE_TYPE) == TLS_CURVE_PRIME)
                *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime;
            else
                *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;
        }
    }
    return 1;
}

/* Check an EC key is compatible with extensions */
static int tls1_check_ec_key(SSL *s,
                             unsigned char *curve_id, unsigned char *comp_id)
{
    const unsigned char *pformats, *pcurves;
    size_t num_formats, num_curves, i;
    int j;
    /*
     * If point formats extension present check it, otherwise everything is
     * supported (see RFC4492).
     */
    if (comp_id && s->session->ext.ecpointformats) {
        pformats = s->session->ext.ecpointformats;
        num_formats = s->session->ext.ecpointformats_len;
        for (i = 0; i < num_formats; i++, pformats++) {
            if (*comp_id == *pformats)
                break;
        }
        if (i == num_formats)
            return 0;
    }
    if (!curve_id)
        return 1;
    /* Check curve is consistent with client and server preferences */
    for (j = 0; j <= 1; j++) {
        if (!tls1_get_curvelist(s, j, &pcurves, &num_curves))
            return 0;
        if (j == 1 && num_curves == 0) {
            /*
             * If we've not received any curves then skip this check.
             * RFC 4492 does not require the supported elliptic curves extension
             * so if it is not sent we can just choose any curve.
             * It is invalid to send an empty list in the elliptic curves
             * extension, so num_curves == 0 always means no extension.
             */
            break;
        }
        for (i = 0; i < num_curves; i++, pcurves += 2) {
            if (pcurves[0] == curve_id[0] && pcurves[1] == curve_id[1])
                break;
        }
        if (i == num_curves)
            return 0;
        /* For clients can only check sent curve list */
        if (!s->server)
            break;
    }
    return 1;
}

void tls1_get_formatlist(SSL *s, const unsigned char **pformats,
                         size_t *num_formats)
{
    /*
     * If we have a custom point format list use it otherwise use default
     */
    if (s->ext.ecpointformats) {
        *pformats = s->ext.ecpointformats;
        *num_formats = s->ext.ecpointformats_len;
    } else {
        *pformats = ecformats_default;
        /* For Suite B we don't support char2 fields */
        if (tls1_suiteb(s))
            *num_formats = sizeof(ecformats_default) - 1;
        else
            *num_formats = sizeof(ecformats_default);
    }
}

/*
 * Check cert parameters compatible with extensions: currently just checks EC
 * certificates have compatible curves and compression.
 */
static int tls1_check_cert_param(SSL *s, X509 *x, int set_ee_md)
{
    unsigned char comp_id, curve_id[2];
    EVP_PKEY *pkey;
    int rv;
    pkey = X509_get0_pubkey(x);
    if (!pkey)
        return 0;
    /* If not EC nothing to do */
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC)
        return 1;
    rv = tls1_set_ec_id(curve_id, &comp_id, EVP_PKEY_get0_EC_KEY(pkey));
    if (!rv)
        return 0;
    /*
     * Can't check curve_id for client certs as we don't have a supported
     * curves extension.
     */
    rv = tls1_check_ec_key(s, s->server ? curve_id : NULL, &comp_id);
    if (!rv)
        return 0;
    /*
     * Special case for suite B. We *MUST* sign using SHA256+P-256 or
     * SHA384+P-384, adjust digest if necessary.
     */
    if (set_ee_md && tls1_suiteb(s)) {
        int check_md;
        size_t i;
        CERT *c = s->cert;
        if (curve_id[0])
            return 0;
        /* Check to see we have necessary signing algorithm */
        if (curve_id[1] == TLSEXT_curve_P_256)
            check_md = NID_ecdsa_with_SHA256;
        else if (curve_id[1] == TLSEXT_curve_P_384)
            check_md = NID_ecdsa_with_SHA384;
        else
            return 0;           /* Should never happen */
        for (i = 0; i < c->shared_sigalgslen; i++)
            if (check_md == c->shared_sigalgs[i].signandhash_nid)
                break;
        if (i == c->shared_sigalgslen)
            return 0;
        if (set_ee_md == 2) {
            if (check_md == NID_ecdsa_with_SHA256)
                s->s3->tmp.md[SSL_PKEY_ECC] = EVP_sha256();
            else
                s->s3->tmp.md[SSL_PKEY_ECC] = EVP_sha384();
        }
    }
    return rv;
}

# ifndef OPENSSL_NO_EC
/*
 * tls1_check_ec_tmp_key - Check EC temporary key compatibility
 * @s: SSL connection
 * @cid: Cipher ID we're considering using
 *
 * Checks that the kECDHE cipher suite we're considering using
 * is compatible with the client extensions.
 *
 * Returns 0 when the cipher can't be used or 1 when it can.
 */
int tls1_check_ec_tmp_key(SSL *s, unsigned long cid)
{
    /*
     * If Suite B, AES128 MUST use P-256 and AES256 MUST use P-384, no other
     * curves permitted.
     */
    if (tls1_suiteb(s)) {
        unsigned char curve_id[2];
        /* Curve to check determined by ciphersuite */
        if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            curve_id[1] = TLSEXT_curve_P_256;
        else if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            curve_id[1] = TLSEXT_curve_P_384;
        else
            return 0;
        curve_id[0] = 0;
        /* Check this curve is acceptable */
        if (!tls1_check_ec_key(s, curve_id, NULL))
            return 0;
        return 1;
    }
    /* Need a shared curve */
    if (tls1_shared_group(s, 0))
        return 1;
    return 0;
}
# endif                         /* OPENSSL_NO_EC */

#else

static int tls1_check_cert_param(SSL *s, X509 *x, int set_ee_md)
{
    return 1;
}

#endif                          /* OPENSSL_NO_EC */

/* Default sigalg schemes */
static const unsigned int tls12_sigalgs[] = {
#ifndef OPENSSL_NO_EC
    TLSEXT_SIGALG_ecdsa_secp256r1_sha256,
    TLSEXT_SIGALG_ecdsa_secp384r1_sha384,
    TLSEXT_SIGALG_ecdsa_secp521r1_sha512,
#endif

    TLSEXT_SIGALG_rsa_pss_sha256,
    TLSEXT_SIGALG_rsa_pss_sha384,
    TLSEXT_SIGALG_rsa_pss_sha512,

    TLSEXT_SIGALG_rsa_pkcs1_sha256,
    TLSEXT_SIGALG_rsa_pkcs1_sha384,
    TLSEXT_SIGALG_rsa_pkcs1_sha512,

#ifndef OPENSSL_NO_EC
    TLSEXT_SIGALG_ecdsa_sha1,
#endif
    TLSEXT_SIGALG_rsa_pkcs1_sha1,
#ifndef OPENSSL_NO_DSA
    TLSEXT_SIGALG_dsa_sha1,

    TLSEXT_SIGALG_dsa_sha256,
    TLSEXT_SIGALG_dsa_sha384,
    TLSEXT_SIGALG_dsa_sha512
#endif
};

#ifndef OPENSSL_NO_EC
static const unsigned int suiteb_sigalgs[] = {
    TLSEXT_SIGALG_ecdsa_secp256r1_sha256,
    TLSEXT_SIGALG_ecdsa_secp384r1_sha384
};
#endif

typedef struct sigalg_lookup_st {
    unsigned int sigalg;
    int hash;
    int sig;
} SIGALG_LOOKUP;

static const SIGALG_LOOKUP sigalg_lookup_tbl[] = {
#ifndef OPENSSL_NO_EC
    {TLSEXT_SIGALG_ecdsa_secp256r1_sha256, NID_sha256, EVP_PKEY_EC},
    {TLSEXT_SIGALG_ecdsa_secp384r1_sha384, NID_sha384, EVP_PKEY_EC},
    {TLSEXT_SIGALG_ecdsa_secp521r1_sha512, NID_sha512, EVP_PKEY_EC},
    {TLSEXT_SIGALG_ecdsa_sha1, NID_sha1, EVP_PKEY_EC},
#endif
    /*
     * PSS must appear before PKCS1 so that we prefer that when signing where
     * possible
     */
    {TLSEXT_SIGALG_rsa_pss_sha256, NID_sha256, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pss_sha384, NID_sha384, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pss_sha512, NID_sha512, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pkcs1_sha256, NID_sha256, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pkcs1_sha384, NID_sha384, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pkcs1_sha512, NID_sha512, EVP_PKEY_RSA},
    {TLSEXT_SIGALG_rsa_pkcs1_sha1, NID_sha1, EVP_PKEY_RSA},
#ifndef OPENSSL_NO_DSA
    {TLSEXT_SIGALG_dsa_sha256, NID_sha256, EVP_PKEY_DSA},
    {TLSEXT_SIGALG_dsa_sha384, NID_sha384, EVP_PKEY_DSA},
    {TLSEXT_SIGALG_dsa_sha512, NID_sha512, EVP_PKEY_DSA},
    {TLSEXT_SIGALG_dsa_sha1, NID_sha1, EVP_PKEY_DSA},
#endif
#ifndef OPENSSL_NO_GOST
    {TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256, NID_id_GostR3411_2012_256, NID_id_GostR3410_2012_256},
    {TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512, NID_id_GostR3411_2012_512, NID_id_GostR3410_2012_512},
    {TLSEXT_SIGALG_gostr34102001_gostr3411, NID_id_GostR3411_94, NID_id_GostR3410_2001}
#endif
};

static int tls_sigalg_get_hash(unsigned int sigalg)
{
    size_t i;
    const SIGALG_LOOKUP *curr;

    for (i = 0, curr = sigalg_lookup_tbl; i < OSSL_NELEM(sigalg_lookup_tbl);
         i++, curr++) {
        if (curr->sigalg == sigalg)
            return curr->hash;
    }

    return 0;
}

static int tls_sigalg_get_sig(unsigned int sigalg)
{
    size_t i;
    const SIGALG_LOOKUP *curr;

    for (i = 0, curr = sigalg_lookup_tbl; i < OSSL_NELEM(sigalg_lookup_tbl);
         i++, curr++) {
        if (curr->sigalg == sigalg)
            return curr->sig;
    }

    return 0;
}
size_t tls12_get_psigalgs(SSL *s, int sent, const unsigned int **psigs)
{
    /*
     * If Suite B mode use Suite B sigalgs only, ignore any other
     * preferences.
     */
#ifndef OPENSSL_NO_EC
    switch (tls1_suiteb(s)) {
    case SSL_CERT_FLAG_SUITEB_128_LOS:
        *psigs = suiteb_sigalgs;
        return OSSL_NELEM(suiteb_sigalgs);

    case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *psigs = suiteb_sigalgs;
        return 1;

    case SSL_CERT_FLAG_SUITEB_192_LOS:
        *psigs = suiteb_sigalgs + 1;
        return 1;
    }
#endif
    /*
     *  We use client_sigalgs (if not NULL) if we're a server
     *  and sending a certificate request or if we're a client and
     *  determining which shared algorithm to use.
     */
    if ((s->server == sent) && s->cert->client_sigalgs != NULL) {
        *psigs = s->cert->client_sigalgs;
        return s->cert->client_sigalgslen;
    } else if (s->cert->conf_sigalgs) {
        *psigs = s->cert->conf_sigalgs;
        return s->cert->conf_sigalgslen;
    } else {
        *psigs = tls12_sigalgs;
        return OSSL_NELEM(tls12_sigalgs);
    }
}

/*
 * Check signature algorithm is consistent with sent supported signature
 * algorithms and if so return relevant digest.
 */
int tls12_check_peer_sigalg(const EVP_MD **pmd, SSL *s, unsigned int sig,
                            EVP_PKEY *pkey)
{
    const unsigned int *sent_sigs;
    char sigalgstr[2];
    size_t sent_sigslen, i;
    int pkeyid = EVP_PKEY_id(pkey);
    /* Should never happen */
    if (pkeyid == -1)
        return -1;
    /* Check key type is consistent with signature */
    if (pkeyid != tls_sigalg_get_sig(sig)) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
#ifndef OPENSSL_NO_EC
    if (pkeyid == EVP_PKEY_EC) {
        unsigned char curve_id[2], comp_id;
        /* Check compression and curve matches extensions */
        if (!tls1_set_ec_id(curve_id, &comp_id, EVP_PKEY_get0_EC_KEY(pkey)))
            return 0;
        if (!s->server && !tls1_check_ec_key(s, curve_id, &comp_id)) {
            SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_CURVE);
            return 0;
        }
        /* If Suite B only P-384+SHA384 or P-256+SHA-256 allowed */
        if (tls1_suiteb(s)) {
            if (curve_id[0])
                return 0;
            if (curve_id[1] == TLSEXT_curve_P_256) {
                if (tls_sigalg_get_hash(sig) != NID_sha256) {
                    SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG,
                           SSL_R_ILLEGAL_SUITEB_DIGEST);
                    return 0;
                }
            } else if (curve_id[1] == TLSEXT_curve_P_384) {
                if (tls_sigalg_get_hash(sig) != NID_sha384) {
                    SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG,
                           SSL_R_ILLEGAL_SUITEB_DIGEST);
                    return 0;
                }
            } else
                return 0;
        }
    } else if (tls1_suiteb(s))
        return 0;
#endif

    /* Check signature matches a type we sent */
    sent_sigslen = tls12_get_psigalgs(s, 1, &sent_sigs);
    for (i = 0; i < sent_sigslen; i++, sent_sigs++) {
        if (sig == *sent_sigs)
            break;
    }
    /* Allow fallback to SHA1 if not strict mode */
    if (i == sent_sigslen
        && (tls_sigalg_get_hash(sig) != NID_sha1
            || s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
    *pmd = tls12_get_hash(tls_sigalg_get_hash(sig));
    if (*pmd == NULL) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_UNKNOWN_DIGEST);
        return 0;
    }
    /*
     * Make sure security callback allows algorithm. For historical reasons we
     * have to pass the sigalg as a two byte char array.
     */
    sigalgstr[0] = (sig >> 8) & 0xff;
    sigalgstr[1] = sig & 0xff;
    if (!ssl_security(s, SSL_SECOP_SIGALG_CHECK,
                      EVP_MD_size(*pmd) * 4, EVP_MD_type(*pmd),
                      (void *)sigalgstr)) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
    /*
     * Store the digest used so applications can retrieve it if they wish.
     */
    s->s3->tmp.peer_md = *pmd;
    return 1;
}

/*
 * Set a mask of disabled algorithms: an algorithm is disabled if it isn't
 * supported, doesn't appear in supported signature algorithms, isn't supported
 * by the enabled protocol versions or by the security level.
 *
 * This function should only be used for checking which ciphers are supported
 * by the client.
 *
 * Call ssl_cipher_disabled() to check that it's enabled or not.
 */
void ssl_set_client_disabled(SSL *s)
{
    s->s3->tmp.mask_a = 0;
    s->s3->tmp.mask_k = 0;
    ssl_set_sig_mask(&s->s3->tmp.mask_a, s, SSL_SECOP_SIGALG_MASK);
    ssl_get_client_min_max_version(s, &s->s3->tmp.min_ver, &s->s3->tmp.max_ver);
#ifndef OPENSSL_NO_PSK
    /* with PSK there must be client callback set */
    if (!s->psk_client_callback) {
        s->s3->tmp.mask_a |= SSL_aPSK;
        s->s3->tmp.mask_k |= SSL_PSK;
    }
#endif                          /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (!(s->srp_ctx.srp_Mask & SSL_kSRP)) {
        s->s3->tmp.mask_a |= SSL_aSRP;
        s->s3->tmp.mask_k |= SSL_kSRP;
    }
#endif
}

/*
 * ssl_cipher_disabled - check that a cipher is disabled or not
 * @s: SSL connection that you want to use the cipher on
 * @c: cipher to check
 * @op: Security check that you want to do
 *
 * Returns 1 when it's disabled, 0 when enabled.
 */
int ssl_cipher_disabled(SSL *s, const SSL_CIPHER *c, int op)
{
    if (c->algorithm_mkey & s->s3->tmp.mask_k
        || c->algorithm_auth & s->s3->tmp.mask_a)
        return 1;
    if (s->s3->tmp.max_ver == 0)
        return 1;
    if (!SSL_IS_DTLS(s) && ((c->min_tls > s->s3->tmp.max_ver)
                            || (c->max_tls < s->s3->tmp.min_ver)))
        return 1;
    if (SSL_IS_DTLS(s) && (DTLS_VERSION_GT(c->min_dtls, s->s3->tmp.max_ver)
                           || DTLS_VERSION_LT(c->max_dtls, s->s3->tmp.min_ver)))
        return 1;

    return !ssl_security(s, op, c->strength_bits, 0, (void *)c);
}

int tls_use_ticket(SSL *s)
{
    if ((s->options & SSL_OP_NO_TICKET) || SSL_IS_TLS13(s))
        return 0;
    return ssl_security(s, SSL_SECOP_TICKET, 0, 0, NULL);
}

/* Initialise digests to default values */
void ssl_set_default_md(SSL *s)
{
    const EVP_MD **pmd = s->s3->tmp.md;
#ifndef OPENSSL_NO_DSA
    pmd[SSL_PKEY_DSA_SIGN] = ssl_md(SSL_MD_SHA1_IDX);
#endif
#ifndef OPENSSL_NO_RSA
    if (SSL_USE_SIGALGS(s))
        pmd[SSL_PKEY_RSA_SIGN] = ssl_md(SSL_MD_SHA1_IDX);
    else
        pmd[SSL_PKEY_RSA_SIGN] = ssl_md(SSL_MD_MD5_SHA1_IDX);
    pmd[SSL_PKEY_RSA_ENC] = pmd[SSL_PKEY_RSA_SIGN];
#endif
#ifndef OPENSSL_NO_EC
    pmd[SSL_PKEY_ECC] = ssl_md(SSL_MD_SHA1_IDX);
#endif
#ifndef OPENSSL_NO_GOST
    pmd[SSL_PKEY_GOST01] = ssl_md(SSL_MD_GOST94_IDX);
    pmd[SSL_PKEY_GOST12_256] = ssl_md(SSL_MD_GOST12_256_IDX);
    pmd[SSL_PKEY_GOST12_512] = ssl_md(SSL_MD_GOST12_512_IDX);
#endif
}

int tls1_set_server_sigalgs(SSL *s)
{
    int al;
    size_t i;

    /* Clear any shared signature algorithms */
    OPENSSL_free(s->cert->shared_sigalgs);
    s->cert->shared_sigalgs = NULL;
    s->cert->shared_sigalgslen = 0;
    /* Clear certificate digests and validity flags */
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        s->s3->tmp.md[i] = NULL;
        s->s3->tmp.valid_flags[i] = 0;
    }

    /* If sigalgs received process it. */
    if (s->s3->tmp.peer_sigalgs) {
        if (!tls1_process_sigalgs(s)) {
            SSLerr(SSL_F_TLS1_SET_SERVER_SIGALGS, ERR_R_MALLOC_FAILURE);
            al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
        /* Fatal error is no shared signature algorithms */
        if (!s->cert->shared_sigalgs) {
            SSLerr(SSL_F_TLS1_SET_SERVER_SIGALGS,
                   SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS);
            al = SSL_AD_ILLEGAL_PARAMETER;
            goto err;
        }
    } else {
        ssl_set_default_md(s);
    }
    return 1;
 err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return 0;
}

/*-
 * Gets the ticket information supplied by the client if any.
 *
 *   hello: The parsed ClientHello data
 *   ret: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * If s->tls_session_secret_cb is set then we are expecting a pre-shared key
 * ciphersuite, in which case we have no use for session tickets and one will
 * never be decrypted, nor will s->ext.ticket_expected be set to 1.
 *
 * Returns:
 *   -1: fatal error, either from parsing or decrypting the ticket.
 *    0: no ticket was found (or was ignored, based on settings).
 *    1: a zero length extension was found, indicating that the client supports
 *       session tickets but doesn't currently have one to offer.
 *    2: either s->tls_session_secret_cb was set, or a ticket was offered but
 *       couldn't be decrypted because of a non-fatal error.
 *    3: a ticket was successfully decrypted and *ret was set.
 *
 * Side effects:
 *   Sets s->ext.ticket_expected to 1 if the server will have to issue
 *   a new session ticket to the client because the client indicated support
 *   (and s->tls_session_secret_cb is NULL) but the client either doesn't have
 *   a session ticket or we couldn't use the one it gave us, or if
 *   s->ctx->ext.ticket_key_cb asked to renew the client's ticket.
 *   Otherwise, s->ext.ticket_expected is set to 0.
 */
int tls_get_ticket_from_client(SSL *s, CLIENTHELLO_MSG *hello,
                               SSL_SESSION **ret)
{
    int retv;
    size_t size;
    RAW_EXTENSION *ticketext;

    *ret = NULL;
    s->ext.ticket_expected = 0;

    /*
     * If tickets disabled or not supported by the protocol version
     * (e.g. TLSv1.3) behave as if no ticket present to permit stateful
     * resumption.
     */
    if (s->version <= SSL3_VERSION || !tls_use_ticket(s))
        return 0;

    ticketext = &hello->pre_proc_exts[TLSEXT_IDX_session_ticket];
    if (!ticketext->present)
        return 0;

    size = PACKET_remaining(&ticketext->data);
    if (size == 0) {
        /*
         * The client will accept a ticket but doesn't currently have
         * one.
         */
        s->ext.ticket_expected = 1;
        return 1;
    }
    if (s->ext.session_secret_cb) {
        /*
         * Indicate that the ticket couldn't be decrypted rather than
         * generating the session from ticket now, trigger
         * abbreviated handshake based on external mechanism to
         * calculate the master secret later.
         */
        return 2;
    }

    retv = tls_decrypt_ticket(s, PACKET_data(&ticketext->data), size,
                              hello->session_id, hello->session_id_len, ret);
    switch (retv) {
    case 2:            /* ticket couldn't be decrypted */
        s->ext.ticket_expected = 1;
        return 2;

    case 3:            /* ticket was decrypted */
        return 3;

    case 4:            /* ticket decrypted but need to renew */
        s->ext.ticket_expected = 1;
        return 3;

    default:           /* fatal error */
        return -1;
    }
}

/*-
 * tls_decrypt_ticket attempts to decrypt a session ticket.
 *
 *   etick: points to the body of the session ticket extension.
 *   eticklen: the length of the session tickets extension.
 *   sess_id: points at the session ID.
 *   sesslen: the length of the session ID.
 *   psess: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * Returns:
 *   -2: fatal error, malloc failure.
 *   -1: fatal error, either from parsing or decrypting the ticket.
 *    2: the ticket couldn't be decrypted.
 *    3: a ticket was successfully decrypted and *psess was set.
 *    4: same as 3, but the ticket needs to be renewed.
 */
static int tls_decrypt_ticket(SSL *s, const unsigned char *etick,
                              size_t eticklen, const unsigned char *sess_id,
                              size_t sesslen, SSL_SESSION **psess)
{
    SSL_SESSION *sess;
    unsigned char *sdec;
    const unsigned char *p;
    int slen, renew_ticket = 0, ret = -1, declen;
    size_t mlen;
    unsigned char tick_hmac[EVP_MAX_MD_SIZE];
    HMAC_CTX *hctx = NULL;
    EVP_CIPHER_CTX *ctx;
    SSL_CTX *tctx = s->initial_ctx;

    /* Initialize session ticket encryption and HMAC contexts */
    hctx = HMAC_CTX_new();
    if (hctx == NULL)
        return -2;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ret = -2;
        goto err;
    }
    if (tctx->ext.ticket_key_cb) {
        unsigned char *nctick = (unsigned char *)etick;
        int rv = tctx->ext.ticket_key_cb(s, nctick, nctick + 16,
                                            ctx, hctx, 0);
        if (rv < 0)
            goto err;
        if (rv == 0) {
            ret = 2;
            goto err;
        }
        if (rv == 2)
            renew_ticket = 1;
    } else {
        /* Check key name matches */
        if (memcmp(etick, tctx->ext.tick_key_name,
                   sizeof(tctx->ext.tick_key_name)) != 0) {
            ret = 2;
            goto err;
        }
        if (HMAC_Init_ex(hctx, tctx->ext.tick_hmac_key,
                         sizeof(tctx->ext.tick_hmac_key),
                         EVP_sha256(), NULL) <= 0
            || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                  tctx->ext.tick_aes_key,
                                  etick + sizeof(tctx->ext.tick_key_name)) <=
            0) {
            goto err;
        }
    }
    /*
     * Attempt to process session ticket, first conduct sanity and integrity
     * checks on ticket.
     */
    mlen = HMAC_size(hctx);
    if (mlen == 0) {
        goto err;
    }
    /* Sanity check ticket length: must exceed keyname + IV + HMAC */
    if (eticklen <=
        TLSEXT_KEYNAME_LENGTH + EVP_CIPHER_CTX_iv_length(ctx) + mlen) {
        ret = 2;
        goto err;
    }
    eticklen -= mlen;
    /* Check HMAC of encrypted ticket */
    if (HMAC_Update(hctx, etick, eticklen) <= 0
        || HMAC_Final(hctx, tick_hmac, NULL) <= 0) {
        goto err;
    }
    HMAC_CTX_free(hctx);
    if (CRYPTO_memcmp(tick_hmac, etick + eticklen, mlen)) {
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }
    /* Attempt to decrypt session data */
    /* Move p after IV to start of encrypted ticket, update length */
    p = etick + 16 + EVP_CIPHER_CTX_iv_length(ctx);
    eticklen -= 16 + EVP_CIPHER_CTX_iv_length(ctx);
    sdec = OPENSSL_malloc(eticklen);
    if (sdec == NULL || EVP_DecryptUpdate(ctx, sdec, &slen, p,
                                          (int)eticklen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(sdec);
        return -1;
    }
    if (EVP_DecryptFinal(ctx, sdec + slen, &declen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(sdec);
        return 2;
    }
    slen += declen;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    p = sdec;

    sess = d2i_SSL_SESSION(NULL, &p, slen);
    OPENSSL_free(sdec);
    if (sess) {
        /*
         * The session ID, if non-empty, is used by some clients to detect
         * that the ticket has been accepted. So we copy it to the session
         * structure. If it is empty set length to zero as required by
         * standard.
         */
        if (sesslen)
            memcpy(sess->session_id, sess_id, sesslen);
        sess->session_id_length = sesslen;
        *psess = sess;
        if (renew_ticket)
            return 4;
        else
            return 3;
    }
    ERR_clear_error();
    /*
     * For session parse failure, indicate that we need to send a new ticket.
     */
    return 2;
 err:
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_free(hctx);
    return ret;
}

int tls12_get_sigandhash(SSL *s, WPACKET *pkt, const EVP_PKEY *pk,
                         const EVP_MD *md, int *ispss)
{
    int md_id, sig_id, tmpispss = 0;
    size_t i;
    const SIGALG_LOOKUP *curr;

    if (md == NULL)
        return 0;
    md_id = EVP_MD_type(md);
    sig_id = EVP_PKEY_id(pk);
    if (md_id == NID_undef)
        return 0;

    for (i = 0, curr = sigalg_lookup_tbl; i < OSSL_NELEM(sigalg_lookup_tbl);
         i++, curr++) {
        if (curr->hash == md_id && curr->sig == sig_id) {
            if (sig_id == EVP_PKEY_RSA) {
                tmpispss = SIGID_IS_PSS(curr->sigalg);
                if (!SSL_IS_TLS13(s) && tmpispss) {
                    size_t j;

                    /*
                     * Check peer actually sent a PSS sig id - it could have
                     * been a PKCS1 sig id instead.
                     */
                    for (j = 0; j < s->cert->shared_sigalgslen; j++)
                        if (s->cert->shared_sigalgs[j].rsigalg == curr->sigalg)
                            break;

                    if (j == s->cert->shared_sigalgslen)
                        continue;
                }
            }
            if (!WPACKET_put_bytes_u16(pkt, curr->sigalg))
                return 0;
            *ispss = tmpispss;
            return 1;
        }
    }

    return 0;
}

typedef struct {
    int nid;
    int secbits;
    int md_idx;
} tls12_hash_info;

static const tls12_hash_info tls12_md_info[] = {
    {NID_md5, 64, SSL_MD_MD5_IDX},
    {NID_sha1, 80, SSL_MD_SHA1_IDX},
    {NID_sha224, 112, SSL_MD_SHA224_IDX},
    {NID_sha256, 128, SSL_MD_SHA256_IDX},
    {NID_sha384, 192, SSL_MD_SHA384_IDX},
    {NID_sha512, 256, SSL_MD_SHA512_IDX},
    {NID_id_GostR3411_94, 128, SSL_MD_GOST94_IDX},
    {NID_id_GostR3411_2012_256, 128, SSL_MD_GOST12_256_IDX},
    {NID_id_GostR3411_2012_512, 256, SSL_MD_GOST12_512_IDX},
};

static const tls12_hash_info *tls12_get_hash_info(int hash_nid)
{
    unsigned int i;
    if (hash_nid == NID_undef)
        return NULL;

    for (i = 0; i < OSSL_NELEM(tls12_md_info); i++) {
        if (tls12_md_info[i].nid == hash_nid)
            return tls12_md_info + i;
    }

    return NULL;
}

const EVP_MD *tls12_get_hash(int hash_nid)
{
    const tls12_hash_info *inf;
    if (hash_nid == NID_md5 && FIPS_mode())
        return NULL;
    inf = tls12_get_hash_info(hash_nid);
    if (!inf)
        return NULL;
    return ssl_md(inf->md_idx);
}

static int tls12_get_pkey_idx(int sig_nid)
{
    switch (sig_nid) {
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
        return SSL_PKEY_RSA_SIGN;
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        return SSL_PKEY_DSA_SIGN;
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        return SSL_PKEY_ECC;
#endif
#ifndef OPENSSL_NO_GOST
    case NID_id_GostR3410_2001:
        return SSL_PKEY_GOST01;

    case NID_id_GostR3410_2012_256:
        return SSL_PKEY_GOST12_256;

    case NID_id_GostR3410_2012_512:
        return SSL_PKEY_GOST12_512;
#endif
    }
    return -1;
}

/* Convert TLS 1.2 signature algorithm extension values into NIDs */
static void tls1_lookup_sigalg(int *phash_nid, int *psign_nid,
                               int *psignhash_nid, unsigned int data)
{
    int sign_nid = NID_undef, hash_nid = NID_undef;
    if (!phash_nid && !psign_nid && !psignhash_nid)
        return;
    if (phash_nid || psignhash_nid) {
        hash_nid = tls_sigalg_get_hash(data);
        if (phash_nid)
            *phash_nid = hash_nid;
    }
    if (psign_nid || psignhash_nid) {
        sign_nid = tls_sigalg_get_sig(data);
        if (psign_nid)
            *psign_nid = sign_nid;
    }
    if (psignhash_nid) {
        if (sign_nid == NID_undef || hash_nid == NID_undef
            || OBJ_find_sigid_by_algs(psignhash_nid, hash_nid, sign_nid) <= 0)
            *psignhash_nid = NID_undef;
    }
}

/* Check to see if a signature algorithm is allowed */
static int tls12_sigalg_allowed(SSL *s, int op, unsigned int ptmp)
{
    /* See if we have an entry in the hash table and it is enabled */
    const tls12_hash_info *hinf
        = tls12_get_hash_info(tls_sigalg_get_hash(ptmp));
    unsigned char sigalgstr[2];

    if (hinf == NULL || ssl_md(hinf->md_idx) == NULL)
        return 0;
    /* See if public key algorithm allowed */
    if (tls12_get_pkey_idx(tls_sigalg_get_sig(ptmp)) == -1)
        return 0;
    /* Finally see if security callback allows it */
    sigalgstr[0] = (ptmp >> 8) & 0xff;
    sigalgstr[1] = ptmp & 0xff;
    return ssl_security(s, op, hinf->secbits, hinf->nid, (void *)sigalgstr);
}

/*
 * Get a mask of disabled public key algorithms based on supported signature
 * algorithms. For example if no signature algorithm supports RSA then RSA is
 * disabled.
 */

void ssl_set_sig_mask(uint32_t *pmask_a, SSL *s, int op)
{
    const unsigned int *sigalgs;
    size_t i, sigalgslen;
    int have_rsa = 0, have_dsa = 0, have_ecdsa = 0;
    /*
     * Now go through all signature algorithms seeing if we support any for
     * RSA, DSA, ECDSA. Do this for all versions not just TLS 1.2. To keep
     * down calls to security callback only check if we have to.
     */
    sigalgslen = tls12_get_psigalgs(s, 1, &sigalgs);
    for (i = 0; i < sigalgslen; i ++, sigalgs++) {
        switch (tls_sigalg_get_sig(*sigalgs)) {
#ifndef OPENSSL_NO_RSA
        case EVP_PKEY_RSA:
            if (!have_rsa && tls12_sigalg_allowed(s, op, *sigalgs))
                have_rsa = 1;
            break;
#endif
#ifndef OPENSSL_NO_DSA
        case EVP_PKEY_DSA:
            if (!have_dsa && tls12_sigalg_allowed(s, op, *sigalgs))
                have_dsa = 1;
            break;
#endif
#ifndef OPENSSL_NO_EC
        case EVP_PKEY_EC:
            if (!have_ecdsa && tls12_sigalg_allowed(s, op, *sigalgs))
                have_ecdsa = 1;
            break;
#endif
        }
    }
    if (!have_rsa)
        *pmask_a |= SSL_aRSA;
    if (!have_dsa)
        *pmask_a |= SSL_aDSS;
    if (!have_ecdsa)
        *pmask_a |= SSL_aECDSA;
}

int tls12_copy_sigalgs(SSL *s, WPACKET *pkt,
                       const unsigned int *psig, size_t psiglen)
{
    size_t i;

    for (i = 0; i < psiglen; i++, psig++) {
        if (tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SUPPORTED, *psig)) {
            if (!WPACKET_put_bytes_u16(pkt, *psig))
                return 0;
        }
    }
    return 1;
}

/* Given preference and allowed sigalgs set shared sigalgs */
static size_t tls12_shared_sigalgs(SSL *s, TLS_SIGALGS *shsig,
                                   const unsigned int *pref, size_t preflen,
                                   const unsigned int *allow, size_t allowlen)
{
    const unsigned int *ptmp, *atmp;
    size_t i, j, nmatch = 0;
    for (i = 0, ptmp = pref; i < preflen; i++, ptmp++) {
        /* Skip disabled hashes or signature algorithms */
        if (!tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SHARED, *ptmp))
            continue;
        for (j = 0, atmp = allow; j < allowlen; j++, atmp++) {
            if (*ptmp == *atmp) {
                nmatch++;
                if (shsig) {
                    shsig->rsigalg = *ptmp;
                    tls1_lookup_sigalg(&shsig->hash_nid,
                                       &shsig->sign_nid,
                                       &shsig->signandhash_nid, *ptmp);
                    shsig++;
                }
                break;
            }
        }
    }
    return nmatch;
}

/* Set shared signature algorithms for SSL structures */
static int tls1_set_shared_sigalgs(SSL *s)
{
    const unsigned int *pref, *allow, *conf;
    size_t preflen, allowlen, conflen;
    size_t nmatch;
    TLS_SIGALGS *salgs = NULL;
    CERT *c = s->cert;
    unsigned int is_suiteb = tls1_suiteb(s);

    OPENSSL_free(c->shared_sigalgs);
    c->shared_sigalgs = NULL;
    c->shared_sigalgslen = 0;
    /* If client use client signature algorithms if not NULL */
    if (!s->server && c->client_sigalgs && !is_suiteb) {
        conf = c->client_sigalgs;
        conflen = c->client_sigalgslen;
    } else if (c->conf_sigalgs && !is_suiteb) {
        conf = c->conf_sigalgs;
        conflen = c->conf_sigalgslen;
    } else
        conflen = tls12_get_psigalgs(s, 0, &conf);
    if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE || is_suiteb) {
        pref = conf;
        preflen = conflen;
        allow = s->s3->tmp.peer_sigalgs;
        allowlen = s->s3->tmp.peer_sigalgslen;
    } else {
        allow = conf;
        allowlen = conflen;
        pref = s->s3->tmp.peer_sigalgs;
        preflen = s->s3->tmp.peer_sigalgslen;
    }
    nmatch = tls12_shared_sigalgs(s, NULL, pref, preflen, allow, allowlen);
    if (nmatch) {
        salgs = OPENSSL_malloc(nmatch * sizeof(TLS_SIGALGS));
        if (salgs == NULL)
            return 0;
        nmatch = tls12_shared_sigalgs(s, salgs, pref, preflen, allow, allowlen);
    } else {
        salgs = NULL;
    }
    c->shared_sigalgs = salgs;
    c->shared_sigalgslen = nmatch;
    return 1;
}

/* Set preferred digest for each key type */

int tls1_save_sigalgs(SSL *s, PACKET *pkt)
{
    CERT *c = s->cert;
    size_t size, i;

    /* Extension ignored for inappropriate versions */
    if (!SSL_USE_SIGALGS(s))
        return 1;
    /* Should never happen */
    if (!c)
        return 0;

    size = PACKET_remaining(pkt);

    /* Invalid data length */
    if ((size & 1) != 0)
        return 0;

    size >>= 1;

    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = OPENSSL_malloc(size
                                         * sizeof(*s->s3->tmp.peer_sigalgs));
    if (s->s3->tmp.peer_sigalgs == NULL)
        return 0;
    s->s3->tmp.peer_sigalgslen = size;
    for (i = 0; i < size && PACKET_get_net_2(pkt, &s->s3->tmp.peer_sigalgs[i]);
         i++)
        continue;

    if (i != size)
        return 0;

    return 1;
}

int tls1_process_sigalgs(SSL *s)
{
    int idx;
    size_t i;
    const EVP_MD *md;
    const EVP_MD **pmd = s->s3->tmp.md;
    uint32_t *pvalid = s->s3->tmp.valid_flags;
    CERT *c = s->cert;
    TLS_SIGALGS *sigptr;
    if (!tls1_set_shared_sigalgs(s))
        return 0;

    for (i = 0, sigptr = c->shared_sigalgs;
         i < c->shared_sigalgslen; i++, sigptr++) {
        /* Ignore PKCS1 based sig algs in TLSv1.3 */
        if (SSL_IS_TLS13(s)
                && (sigptr->rsigalg == TLSEXT_SIGALG_rsa_pkcs1_sha1
                    || sigptr->rsigalg == TLSEXT_SIGALG_rsa_pkcs1_sha256
                    || sigptr->rsigalg == TLSEXT_SIGALG_rsa_pkcs1_sha384
                    || sigptr->rsigalg == TLSEXT_SIGALG_rsa_pkcs1_sha512))
            continue;
        idx = tls12_get_pkey_idx(sigptr->sign_nid);
        if (idx > 0 && pmd[idx] == NULL) {
            md = tls12_get_hash(sigptr->hash_nid);
            pmd[idx] = md;
            pvalid[idx] = CERT_PKEY_EXPLICIT_SIGN;
            if (idx == SSL_PKEY_RSA_SIGN) {
                pvalid[SSL_PKEY_RSA_ENC] = CERT_PKEY_EXPLICIT_SIGN;
                pmd[SSL_PKEY_RSA_ENC] = md;
            }
        }

    }
    /*
     * In strict mode or TLS1.3 leave unset digests as NULL to indicate we can't
     * use the certificate for signing.
     */
    if (!(s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
            && !SSL_IS_TLS13(s)) {
        /*
         * Set any remaining keys to default values. NOTE: if alg is not
         * supported it stays as NULL.
         */
#ifndef OPENSSL_NO_DSA
        if (pmd[SSL_PKEY_DSA_SIGN] == NULL)
            pmd[SSL_PKEY_DSA_SIGN] = EVP_sha1();
#endif
#ifndef OPENSSL_NO_RSA
        if (pmd[SSL_PKEY_RSA_SIGN] == NULL) {
            pmd[SSL_PKEY_RSA_SIGN] = EVP_sha1();
            pmd[SSL_PKEY_RSA_ENC] = EVP_sha1();
        }
#endif
#ifndef OPENSSL_NO_EC
        if (pmd[SSL_PKEY_ECC] == NULL)
            pmd[SSL_PKEY_ECC] = EVP_sha1();
#endif
#ifndef OPENSSL_NO_GOST
        if (pmd[SSL_PKEY_GOST01] == NULL)
            pmd[SSL_PKEY_GOST01] = EVP_get_digestbynid(NID_id_GostR3411_94);
        if (pmd[SSL_PKEY_GOST12_256] == NULL)
            pmd[SSL_PKEY_GOST12_256] =
                EVP_get_digestbynid(NID_id_GostR3411_2012_256);
        if (pmd[SSL_PKEY_GOST12_512] == NULL)
            pmd[SSL_PKEY_GOST12_512] =
                EVP_get_digestbynid(NID_id_GostR3411_2012_512);
#endif
    }
    return 1;
}

int SSL_get_sigalgs(SSL *s, int idx,
                    int *psign, int *phash, int *psignhash,
                    unsigned char *rsig, unsigned char *rhash)
{
    unsigned int *psig = s->s3->tmp.peer_sigalgs;
    size_t numsigalgs = s->s3->tmp.peer_sigalgslen;
    if (psig == NULL || numsigalgs > INT_MAX)
        return 0;
    if (idx >= 0) {
        if (idx >= (int)numsigalgs)
            return 0;
        psig += idx;
        if (rhash)
            *rhash = (unsigned char)((*psig >> 8) & 0xff);
        if (rsig)
            *rsig = (unsigned char)(*psig & 0xff);
        tls1_lookup_sigalg(phash, psign, psignhash, *psig);
    }
    return (int)numsigalgs;
}

int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignhash,
                           unsigned char *rsig, unsigned char *rhash)
{
    TLS_SIGALGS *shsigalgs = s->cert->shared_sigalgs;
    if (!shsigalgs || idx >= (int)s->cert->shared_sigalgslen
            || s->cert->shared_sigalgslen > INT_MAX)
        return 0;
    shsigalgs += idx;
    if (phash)
        *phash = shsigalgs->hash_nid;
    if (psign)
        *psign = shsigalgs->sign_nid;
    if (psignhash)
        *psignhash = shsigalgs->signandhash_nid;
    if (rsig)
        *rsig = (unsigned char)(shsigalgs->rsigalg & 0xff);
    if (rhash)
        *rhash = (unsigned char)((shsigalgs->rsigalg >> 8) & 0xff);
    return (int)s->cert->shared_sigalgslen;
}

#define MAX_SIGALGLEN   (TLSEXT_hash_num * TLSEXT_signature_num * 2)

typedef struct {
    size_t sigalgcnt;
    int sigalgs[MAX_SIGALGLEN];
} sig_cb_st;

static void get_sigorhash(int *psig, int *phash, const char *str)
{
    if (strcmp(str, "RSA") == 0) {
        *psig = EVP_PKEY_RSA;
    } else if (strcmp(str, "DSA") == 0) {
        *psig = EVP_PKEY_DSA;
    } else if (strcmp(str, "ECDSA") == 0) {
        *psig = EVP_PKEY_EC;
    } else {
        *phash = OBJ_sn2nid(str);
        if (*phash == NID_undef)
            *phash = OBJ_ln2nid(str);
    }
}

static int sig_cb(const char *elem, int len, void *arg)
{
    sig_cb_st *sarg = arg;
    size_t i;
    char etmp[20], *p;
    int sig_alg = NID_undef, hash_alg = NID_undef;
    if (elem == NULL)
        return 0;
    if (sarg->sigalgcnt == MAX_SIGALGLEN)
        return 0;
    if (len > (int)(sizeof(etmp) - 1))
        return 0;
    memcpy(etmp, elem, len);
    etmp[len] = 0;
    p = strchr(etmp, '+');
    if (!p)
        return 0;
    *p = 0;
    p++;
    if (!*p)
        return 0;

    get_sigorhash(&sig_alg, &hash_alg, etmp);
    get_sigorhash(&sig_alg, &hash_alg, p);

    if (sig_alg == NID_undef || hash_alg == NID_undef)
        return 0;

    for (i = 0; i < sarg->sigalgcnt; i += 2) {
        if (sarg->sigalgs[i] == sig_alg && sarg->sigalgs[i + 1] == hash_alg)
            return 0;
    }
    sarg->sigalgs[sarg->sigalgcnt++] = hash_alg;
    sarg->sigalgs[sarg->sigalgcnt++] = sig_alg;
    return 1;
}

/*
 * Set supported signature algorithms based on a colon separated list of the
 * form sig+hash e.g. RSA+SHA512:DSA+SHA512
 */
int tls1_set_sigalgs_list(CERT *c, const char *str, int client)
{
    sig_cb_st sig;
    sig.sigalgcnt = 0;
    if (!CONF_parse_list(str, ':', 1, sig_cb, &sig))
        return 0;
    if (c == NULL)
        return 1;
    return tls1_set_sigalgs(c, sig.sigalgs, sig.sigalgcnt, client);
}

/* TODO(TLS1.3): Needs updating to allow setting of TLS1.3 sig algs */
int tls1_set_sigalgs(CERT *c, const int *psig_nids, size_t salglen, int client)
{
    unsigned int *sigalgs, *sptr;
    size_t i;

    if (salglen & 1)
        return 0;
    sigalgs = OPENSSL_malloc((salglen / 2) * sizeof(*sigalgs));
    if (sigalgs == NULL)
        return 0;
    /*
     * TODO(TLS1.3): Somehow we need to be able to set RSA-PSS as well as
     * RSA-PKCS1. For now we only allow setting of RSA-PKCS1
     */
    for (i = 0, sptr = sigalgs; i < salglen; i += 2) {
        size_t j;
        const SIGALG_LOOKUP *curr;
        int md_id = *psig_nids++;
        int sig_id = *psig_nids++;

        for (j = 0, curr = sigalg_lookup_tbl; j < OSSL_NELEM(sigalg_lookup_tbl);
             j++, curr++) {
            /* Skip setting PSS so we get PKCS1 by default */
            if (SIGID_IS_PSS(curr->sigalg))
                continue;
            if (curr->hash == md_id && curr->sig == sig_id) {
                *sptr++ = curr->sigalg;
                break;
            }
        }

        if (j == OSSL_NELEM(sigalg_lookup_tbl))
            goto err;
    }

    if (client) {
        OPENSSL_free(c->client_sigalgs);
        c->client_sigalgs = sigalgs;
        c->client_sigalgslen = salglen / 2;
    } else {
        OPENSSL_free(c->conf_sigalgs);
        c->conf_sigalgs = sigalgs;
        c->conf_sigalgslen = salglen / 2;
    }

    return 1;

 err:
    OPENSSL_free(sigalgs);
    return 0;
}

static int tls1_check_sig_alg(CERT *c, X509 *x, int default_nid)
{
    int sig_nid;
    size_t i;
    if (default_nid == -1)
        return 1;
    sig_nid = X509_get_signature_nid(x);
    if (default_nid)
        return sig_nid == default_nid ? 1 : 0;
    for (i = 0; i < c->shared_sigalgslen; i++)
        if (sig_nid == c->shared_sigalgs[i].signandhash_nid)
            return 1;
    return 0;
}

/* Check to see if a certificate issuer name matches list of CA names */
static int ssl_check_ca_name(STACK_OF(X509_NAME) *names, X509 *x)
{
    X509_NAME *nm;
    int i;
    nm = X509_get_issuer_name(x);
    for (i = 0; i < sk_X509_NAME_num(names); i++) {
        if (!X509_NAME_cmp(nm, sk_X509_NAME_value(names, i)))
            return 1;
    }
    return 0;
}

/*
 * Check certificate chain is consistent with TLS extensions and is usable by
 * server. This servers two purposes: it allows users to check chains before
 * passing them to the server and it allows the server to check chains before
 * attempting to use them.
 */

/* Flags which need to be set for a certificate when stict mode not set */

#define CERT_PKEY_VALID_FLAGS \
        (CERT_PKEY_EE_SIGNATURE|CERT_PKEY_EE_PARAM)
/* Strict mode flags */
#define CERT_PKEY_STRICT_FLAGS \
         (CERT_PKEY_VALID_FLAGS|CERT_PKEY_CA_SIGNATURE|CERT_PKEY_CA_PARAM \
         | CERT_PKEY_ISSUER_NAME|CERT_PKEY_CERT_TYPE)

int tls1_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain,
                     int idx)
{
    int i;
    int rv = 0;
    int check_flags = 0, strict_mode;
    CERT_PKEY *cpk = NULL;
    CERT *c = s->cert;
    uint32_t *pvalid;
    unsigned int suiteb_flags = tls1_suiteb(s);
    /* idx == -1 means checking server chains */
    if (idx != -1) {
        /* idx == -2 means checking client certificate chains */
        if (idx == -2) {
            cpk = c->key;
            idx = (int)(cpk - c->pkeys);
        } else
            cpk = c->pkeys + idx;
        pvalid = s->s3->tmp.valid_flags + idx;
        x = cpk->x509;
        pk = cpk->privatekey;
        chain = cpk->chain;
        strict_mode = c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT;
        /* If no cert or key, forget it */
        if (!x || !pk)
            goto end;
    } else {
        if (!x || !pk)
            return 0;
        idx = ssl_cert_type(x, pk);
        if (idx == -1)
            return 0;
        pvalid = s->s3->tmp.valid_flags + idx;

        if (c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
            check_flags = CERT_PKEY_STRICT_FLAGS;
        else
            check_flags = CERT_PKEY_VALID_FLAGS;
        strict_mode = 1;
    }

    if (suiteb_flags) {
        int ok;
        if (check_flags)
            check_flags |= CERT_PKEY_SUITEB;
        ok = X509_chain_check_suiteb(NULL, x, chain, suiteb_flags);
        if (ok == X509_V_OK)
            rv |= CERT_PKEY_SUITEB;
        else if (!check_flags)
            goto end;
    }

    /*
     * Check all signature algorithms are consistent with signature
     * algorithms extension if TLS 1.2 or later and strict mode.
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION && strict_mode) {
        int default_nid;
        int rsign = 0;
        if (s->s3->tmp.peer_sigalgs)
            default_nid = 0;
        /* If no sigalgs extension use defaults from RFC5246 */
        else {
            switch (idx) {
            case SSL_PKEY_RSA_ENC:
            case SSL_PKEY_RSA_SIGN:
                rsign = EVP_PKEY_RSA;
                default_nid = NID_sha1WithRSAEncryption;
                break;

            case SSL_PKEY_DSA_SIGN:
                rsign = EVP_PKEY_DSA;
                default_nid = NID_dsaWithSHA1;
                break;

            case SSL_PKEY_ECC:
                rsign = EVP_PKEY_EC;
                default_nid = NID_ecdsa_with_SHA1;
                break;

            case SSL_PKEY_GOST01:
                rsign = NID_id_GostR3410_2001;
                default_nid = NID_id_GostR3411_94_with_GostR3410_2001;
                break;

            case SSL_PKEY_GOST12_256:
                rsign = NID_id_GostR3410_2012_256;
                default_nid = NID_id_tc26_signwithdigest_gost3410_2012_256;
                break;

            case SSL_PKEY_GOST12_512:
                rsign = NID_id_GostR3410_2012_512;
                default_nid = NID_id_tc26_signwithdigest_gost3410_2012_512;
                break;

            default:
                default_nid = -1;
                break;
            }
        }
        /*
         * If peer sent no signature algorithms extension and we have set
         * preferred signature algorithms check we support sha1.
         */
        if (default_nid > 0 && c->conf_sigalgs) {
            size_t j;
            const unsigned int *p = c->conf_sigalgs;
            for (j = 0; j < c->conf_sigalgslen; j++, p++) {
                if (tls_sigalg_get_hash(*p) == NID_sha1
                        && tls_sigalg_get_sig(*p) == rsign)
                    break;
            }
            if (j == c->conf_sigalgslen) {
                if (check_flags)
                    goto skip_sigs;
                else
                    goto end;
            }
        }
        /* Check signature algorithm of each cert in chain */
        if (!tls1_check_sig_alg(c, x, default_nid)) {
            if (!check_flags)
                goto end;
        } else
            rv |= CERT_PKEY_EE_SIGNATURE;
        rv |= CERT_PKEY_CA_SIGNATURE;
        for (i = 0; i < sk_X509_num(chain); i++) {
            if (!tls1_check_sig_alg(c, sk_X509_value(chain, i), default_nid)) {
                if (check_flags) {
                    rv &= ~CERT_PKEY_CA_SIGNATURE;
                    break;
                } else
                    goto end;
            }
        }
    }
    /* Else not TLS 1.2, so mark EE and CA signing algorithms OK */
    else if (check_flags)
        rv |= CERT_PKEY_EE_SIGNATURE | CERT_PKEY_CA_SIGNATURE;
 skip_sigs:
    /* Check cert parameters are consistent */
    if (tls1_check_cert_param(s, x, check_flags ? 1 : 2))
        rv |= CERT_PKEY_EE_PARAM;
    else if (!check_flags)
        goto end;
    if (!s->server)
        rv |= CERT_PKEY_CA_PARAM;
    /* In strict mode check rest of chain too */
    else if (strict_mode) {
        rv |= CERT_PKEY_CA_PARAM;
        for (i = 0; i < sk_X509_num(chain); i++) {
            X509 *ca = sk_X509_value(chain, i);
            if (!tls1_check_cert_param(s, ca, 0)) {
                if (check_flags) {
                    rv &= ~CERT_PKEY_CA_PARAM;
                    break;
                } else
                    goto end;
            }
        }
    }
    if (!s->server && strict_mode) {
        STACK_OF(X509_NAME) *ca_dn;
        int check_type = 0;
        switch (EVP_PKEY_id(pk)) {
        case EVP_PKEY_RSA:
            check_type = TLS_CT_RSA_SIGN;
            break;
        case EVP_PKEY_DSA:
            check_type = TLS_CT_DSS_SIGN;
            break;
        case EVP_PKEY_EC:
            check_type = TLS_CT_ECDSA_SIGN;
            break;
        }
        if (check_type) {
            const unsigned char *ctypes;
            int ctypelen;
            if (c->ctypes) {
                ctypes = c->ctypes;
                ctypelen = (int)c->ctype_num;
            } else {
                ctypes = (unsigned char *)s->s3->tmp.ctype;
                ctypelen = s->s3->tmp.ctype_num;
            }
            for (i = 0; i < ctypelen; i++) {
                if (ctypes[i] == check_type) {
                    rv |= CERT_PKEY_CERT_TYPE;
                    break;
                }
            }
            if (!(rv & CERT_PKEY_CERT_TYPE) && !check_flags)
                goto end;
        } else
            rv |= CERT_PKEY_CERT_TYPE;

        ca_dn = s->s3->tmp.ca_names;

        if (!sk_X509_NAME_num(ca_dn))
            rv |= CERT_PKEY_ISSUER_NAME;

        if (!(rv & CERT_PKEY_ISSUER_NAME)) {
            if (ssl_check_ca_name(ca_dn, x))
                rv |= CERT_PKEY_ISSUER_NAME;
        }
        if (!(rv & CERT_PKEY_ISSUER_NAME)) {
            for (i = 0; i < sk_X509_num(chain); i++) {
                X509 *xtmp = sk_X509_value(chain, i);
                if (ssl_check_ca_name(ca_dn, xtmp)) {
                    rv |= CERT_PKEY_ISSUER_NAME;
                    break;
                }
            }
        }
        if (!check_flags && !(rv & CERT_PKEY_ISSUER_NAME))
            goto end;
    } else
        rv |= CERT_PKEY_ISSUER_NAME | CERT_PKEY_CERT_TYPE;

    if (!check_flags || (rv & check_flags) == check_flags)
        rv |= CERT_PKEY_VALID;

 end:

    if (TLS1_get_version(s) >= TLS1_2_VERSION) {
        if (*pvalid & CERT_PKEY_EXPLICIT_SIGN)
            rv |= CERT_PKEY_EXPLICIT_SIGN | CERT_PKEY_SIGN;
        else if (s->s3->tmp.md[idx] != NULL)
            rv |= CERT_PKEY_SIGN;
    } else
        rv |= CERT_PKEY_SIGN | CERT_PKEY_EXPLICIT_SIGN;

    /*
     * When checking a CERT_PKEY structure all flags are irrelevant if the
     * chain is invalid.
     */
    if (!check_flags) {
        if (rv & CERT_PKEY_VALID)
            *pvalid = rv;
        else {
            /* Preserve explicit sign flag, clear rest */
            *pvalid &= CERT_PKEY_EXPLICIT_SIGN;
            return 0;
        }
    }
    return rv;
}

/* Set validity of certificates in an SSL structure */
void tls1_set_cert_validity(SSL *s)
{
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA_ENC);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA_SIGN);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DSA_SIGN);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_ECC);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST01);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST12_256);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_GOST12_512);
}

/* User level utiity function to check a chain is suitable */
int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain)
{
    return tls1_check_chain(s, x, pk, chain, -1);
}

#ifndef OPENSSL_NO_DH
DH *ssl_get_auto_dh(SSL *s)
{
    int dh_secbits = 80;
    if (s->cert->dh_tmp_auto == 2)
        return DH_get_1024_160();
    if (s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL | SSL_aPSK)) {
        if (s->s3->tmp.new_cipher->strength_bits == 256)
            dh_secbits = 128;
        else
            dh_secbits = 80;
    } else {
        CERT_PKEY *cpk = ssl_get_server_send_pkey(s);
        dh_secbits = EVP_PKEY_security_bits(cpk->privatekey);
    }

    if (dh_secbits >= 128) {
        DH *dhp = DH_new();
        BIGNUM *p, *g;
        if (dhp == NULL)
            return NULL;
        g = BN_new();
        if (g != NULL)
            BN_set_word(g, 2);
        if (dh_secbits >= 192)
            p = BN_get_rfc3526_prime_8192(NULL);
        else
            p = BN_get_rfc3526_prime_3072(NULL);
        if (p == NULL || g == NULL || !DH_set0_pqg(dhp, p, NULL, g)) {
            DH_free(dhp);
            BN_free(p);
            BN_free(g);
            return NULL;
        }
        return dhp;
    }
    if (dh_secbits >= 112)
        return DH_get_2048_224();
    return DH_get_1024_160();
}
#endif

static int ssl_security_cert_key(SSL *s, SSL_CTX *ctx, X509 *x, int op)
{
    int secbits = -1;
    EVP_PKEY *pkey = X509_get0_pubkey(x);
    if (pkey) {
        /*
         * If no parameters this will return -1 and fail using the default
         * security callback for any non-zero security level. This will
         * reject keys which omit parameters but this only affects DSA and
         * omission of parameters is never (?) done in practice.
         */
        secbits = EVP_PKEY_security_bits(pkey);
    }
    if (s)
        return ssl_security(s, op, secbits, 0, x);
    else
        return ssl_ctx_security(ctx, op, secbits, 0, x);
}

static int ssl_security_cert_sig(SSL *s, SSL_CTX *ctx, X509 *x, int op)
{
    /* Lookup signature algorithm digest */
    int secbits = -1, md_nid = NID_undef, sig_nid;
    /* Don't check signature if self signed */
    if ((X509_get_extension_flags(x) & EXFLAG_SS) != 0)
        return 1;
    sig_nid = X509_get_signature_nid(x);
    if (sig_nid && OBJ_find_sigid_algs(sig_nid, &md_nid, NULL)) {
        const EVP_MD *md;
        if (md_nid && (md = EVP_get_digestbynid(md_nid)))
            secbits = EVP_MD_size(md) * 4;
    }
    if (s)
        return ssl_security(s, op, secbits, md_nid, x);
    else
        return ssl_ctx_security(ctx, op, secbits, md_nid, x);
}

int ssl_security_cert(SSL *s, SSL_CTX *ctx, X509 *x, int vfy, int is_ee)
{
    if (vfy)
        vfy = SSL_SECOP_PEER;
    if (is_ee) {
        if (!ssl_security_cert_key(s, ctx, x, SSL_SECOP_EE_KEY | vfy))
            return SSL_R_EE_KEY_TOO_SMALL;
    } else {
        if (!ssl_security_cert_key(s, ctx, x, SSL_SECOP_CA_KEY | vfy))
            return SSL_R_CA_KEY_TOO_SMALL;
    }
    if (!ssl_security_cert_sig(s, ctx, x, SSL_SECOP_CA_MD | vfy))
        return SSL_R_CA_MD_TOO_WEAK;
    return 1;
}

/*
 * Check security of a chain, if sk includes the end entity certificate then
 * x is NULL. If vfy is 1 then we are verifying a peer chain and not sending
 * one to the peer. Return values: 1 if ok otherwise error code to use
 */

int ssl_security_cert_chain(SSL *s, STACK_OF(X509) *sk, X509 *x, int vfy)
{
    int rv, start_idx, i;
    if (x == NULL) {
        x = sk_X509_value(sk, 0);
        start_idx = 1;
    } else
        start_idx = 0;

    rv = ssl_security_cert(s, NULL, x, vfy, 1);
    if (rv != 1)
        return rv;

    for (i = start_idx; i < sk_X509_num(sk); i++) {
        x = sk_X509_value(sk, i);
        rv = ssl_security_cert(s, NULL, x, vfy, 0);
        if (rv != 1)
            return rv;
    }
    return 1;
}
