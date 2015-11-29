/* ssl/t1_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
# include <openssl/bn.h>
#endif
#include "ssl_locl.h"

static int tls_decrypt_ticket(SSL *s, const unsigned char *tick, int ticklen,
                              const unsigned char *sess_id, int sesslen,
                              SSL_SESSION **psess);
static int ssl_check_clienthello_tlsext_early(SSL *s);
int ssl_check_serverhello_tlsext(SSL *s);

SSL3_ENC_METHOD const TLSv1_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS1_FINISH_MAC_LENGTH,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    0,
    SSL3_HM_HEADER_LENGTH,
    ssl3_set_handshake_header,
    ssl3_handshake_write
};

SSL3_ENC_METHOD const TLSv1_1_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS1_FINISH_MAC_LENGTH,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_EXPLICIT_IV,
    SSL3_HM_HEADER_LENGTH,
    ssl3_set_handshake_header,
    ssl3_handshake_write
};

SSL3_ENC_METHOD const TLSv1_2_enc_data = {
    tls1_enc,
    tls1_mac,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    tls1_final_finish_mac,
    TLS1_FINISH_MAC_LENGTH,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tls1_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF
        | SSL_ENC_FLAG_TLS1_2_CIPHERS,
    SSL3_HM_HEADER_LENGTH,
    ssl3_set_handshake_header,
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
    OPENSSL_free(s->tlsext_session_ticket);
    ssl3_free(s);
}

void tls1_clear(SSL *s)
{
    ssl3_clear(s);
    s->version = s->method->version;
}

#ifndef OPENSSL_NO_EC

typedef struct {
    int nid;                    /* Curve NID */
    int secbits;                /* Bits of security (from SP800-57) */
    unsigned int flags;         /* Flags: currently just field type */
} tls_curve_info;

# define TLS_CURVE_CHAR2         0x1
# define TLS_CURVE_PRIME         0x0

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
};

static const unsigned char ecformats_default[] = {
    TLSEXT_ECPOINTFORMAT_uncompressed,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2
};

/* The client's default curves / the server's 'auto' curves. */
static const unsigned char eccurves_auto[] = {
    /* Prefer P-256 which has the fastest and most secure implementations. */
    0, 23,                      /* secp256r1 (23) */
    /* Other >= 256-bit prime curves. */
    0, 25,                      /* secp521r1 (25) */
    0, 28,                      /* brainpool512r1 (28) */
    0, 27,                      /* brainpoolP384r1 (27) */
    0, 24,                      /* secp384r1 (24) */
    0, 26,                      /* brainpoolP256r1 (26) */
    0, 22,                      /* secp256k1 (22) */
    /* >= 256-bit binary curves. */
    0, 14,                      /* sect571r1 (14) */
    0, 13,                      /* sect571k1 (13) */
    0, 11,                      /* sect409k1 (11) */
    0, 12,                      /* sect409r1 (12) */
    0, 9,                       /* sect283k1 (9) */
    0, 10,                      /* sect283r1 (10) */
};

static const unsigned char eccurves_all[] = {
    /* Prefer P-256 which has the fastest and most secure implementations. */
    0, 23,                      /* secp256r1 (23) */
    /* Other >= 256-bit prime curves. */
    0, 25,                      /* secp521r1 (25) */
    0, 28,                      /* brainpool512r1 (28) */
    0, 27,                      /* brainpoolP384r1 (27) */
    0, 24,                      /* secp384r1 (24) */
    0, 26,                      /* brainpoolP256r1 (26) */
    0, 22,                      /* secp256k1 (22) */
    /* >= 256-bit binary curves. */
    0, 14,                      /* sect571r1 (14) */
    0, 13,                      /* sect571k1 (13) */
    0, 11,                      /* sect409k1 (11) */
    0, 12,                      /* sect409r1 (12) */
    0, 9,                       /* sect283k1 (9) */
    0, 10,                      /* sect283r1 (10) */
    /*
     * Remaining curves disabled by default but still permitted if set
     * via an explicit callback or parameters.
     */
    0, 20,                      /* secp224k1 (20) */
    0, 21,                      /* secp224r1 (21) */
    0, 18,                      /* secp192k1 (18) */
    0, 19,                      /* secp192r1 (19) */
    0, 15,                      /* secp160k1 (15) */
    0, 16,                      /* secp160r1 (16) */
    0, 17,                      /* secp160r2 (17) */
    0, 8,                       /* sect239k1 (8) */
    0, 6,                       /* sect233k1 (6) */
    0, 7,                       /* sect233r1 (7) */
    0, 4,                       /* sect193r1 (4) */
    0, 5,                       /* sect193r2 (5) */
    0, 1,                       /* sect163k1 (1) */
    0, 2,                       /* sect163r1 (2) */
    0, 3,                       /* sect163r2 (3) */
};


static const unsigned char suiteb_curves[] = {
    0, TLSEXT_curve_P_256,
    0, TLSEXT_curve_P_384
};

int tls1_ec_curve_id2nid(int curve_id)
{
    /* ECC curves from RFC 4492 and RFC 7027 */
    if ((curve_id < 1) || ((unsigned int)curve_id > OSSL_NELEM(nid_list)))
        return 0;
    return nid_list[curve_id - 1].nid;
}

int tls1_ec_nid2curve_id(int nid)
{
    /* ECC curves from RFC 4492 and RFC 7027 */
    switch (nid) {
    case NID_sect163k1:        /* sect163k1 (1) */
        return 1;
    case NID_sect163r1:        /* sect163r1 (2) */
        return 2;
    case NID_sect163r2:        /* sect163r2 (3) */
        return 3;
    case NID_sect193r1:        /* sect193r1 (4) */
        return 4;
    case NID_sect193r2:        /* sect193r2 (5) */
        return 5;
    case NID_sect233k1:        /* sect233k1 (6) */
        return 6;
    case NID_sect233r1:        /* sect233r1 (7) */
        return 7;
    case NID_sect239k1:        /* sect239k1 (8) */
        return 8;
    case NID_sect283k1:        /* sect283k1 (9) */
        return 9;
    case NID_sect283r1:        /* sect283r1 (10) */
        return 10;
    case NID_sect409k1:        /* sect409k1 (11) */
        return 11;
    case NID_sect409r1:        /* sect409r1 (12) */
        return 12;
    case NID_sect571k1:        /* sect571k1 (13) */
        return 13;
    case NID_sect571r1:        /* sect571r1 (14) */
        return 14;
    case NID_secp160k1:        /* secp160k1 (15) */
        return 15;
    case NID_secp160r1:        /* secp160r1 (16) */
        return 16;
    case NID_secp160r2:        /* secp160r2 (17) */
        return 17;
    case NID_secp192k1:        /* secp192k1 (18) */
        return 18;
    case NID_X9_62_prime192v1: /* secp192r1 (19) */
        return 19;
    case NID_secp224k1:        /* secp224k1 (20) */
        return 20;
    case NID_secp224r1:        /* secp224r1 (21) */
        return 21;
    case NID_secp256k1:        /* secp256k1 (22) */
        return 22;
    case NID_X9_62_prime256v1: /* secp256r1 (23) */
        return 23;
    case NID_secp384r1:        /* secp384r1 (24) */
        return 24;
    case NID_secp521r1:        /* secp521r1 (25) */
        return 25;
    case NID_brainpoolP256r1:  /* brainpoolP256r1 (26) */
        return 26;
    case NID_brainpoolP384r1:  /* brainpoolP384r1 (27) */
        return 27;
    case NID_brainpoolP512r1:  /* brainpool512r1 (28) */
        return 28;
    default:
        return 0;
    }
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
static int tls1_get_curvelist(SSL *s, int sess,
                              const unsigned char **pcurves,
                              size_t *num_curves)
{
    size_t pcurveslen = 0;
    if (sess) {
        *pcurves = s->session->tlsext_ellipticcurvelist;
        pcurveslen = s->session->tlsext_ellipticcurvelist_length;
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
            *pcurves = s->tlsext_ellipticcurvelist;
            pcurveslen = s->tlsext_ellipticcurvelist_length;
        }
        if (!*pcurves) {
            if (!s->server || s->cert->ecdh_tmp_auto) {
                *pcurves = eccurves_auto;
                pcurveslen = sizeof(eccurves_auto);
            } else {
                *pcurves = eccurves_all;
                pcurveslen = sizeof(eccurves_all);
            }
        }
    }

    /* We do not allow odd length arrays to enter the system. */
    if (pcurveslen & 1) {
        SSLerr(SSL_F_TLS1_GET_CURVELIST, ERR_R_INTERNAL_ERROR);
        *num_curves = 0;
        return 0;
    } else {
        *num_curves = pcurveslen / 2;
        return 1;
    }
}

/* See if curve is allowed by security callback */
static int tls_curve_allowed(SSL *s, const unsigned char *curve, int op)
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
 * Return |nmatch|th shared curve or NID_undef if there is no match.
 * For nmatch == -1, return number of  matches
 * For nmatch == -2, return the NID of the curve to use for
 * an EC tmp key, or NID_undef if there is no match.
 */
int tls1_shared_curve(SSL *s, int nmatch)
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
    if (!tls1_get_curvelist
        (s, (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0, &supp,
         &num_supp))
        /* In practice, NID_undef == 0 but let's be precise. */
        return nmatch == -1 ? 0 : NID_undef;
    if (!tls1_get_curvelist
        (s, !(s->options & SSL_OP_CIPHER_SERVER_PREFERENCE), &pref,
         &num_pref))
        return nmatch == -1 ? 0 : NID_undef;

    /*
     * If the client didn't send the elliptic_curves extension all of them
     * are allowed.
     */
    if (num_supp == 0 && (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0) {
        supp = eccurves_all;
        num_supp = sizeof(eccurves_all) / 2;
    } else if (num_pref == 0 &&
        (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) == 0) {
        pref = eccurves_all;
        num_pref = sizeof(eccurves_all) / 2;
    }

    k = 0;
    for (i = 0; i < num_pref; i++, pref += 2) {
        const unsigned char *tsupp = supp;
        for (j = 0; j < num_supp; j++, tsupp += 2) {
            if (pref[0] == tsupp[0] && pref[1] == tsupp[1]) {
                if (!tls_curve_allowed(s, pref, SSL_SECOP_CURVE_SHARED))
                    continue;
                if (nmatch == k) {
                    int id = (pref[0] << 8) | pref[1];
                    return tls1_ec_curve_id2nid(id);
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

int tls1_set_curves(unsigned char **pext, size_t *pextlen,
                    int *curves, size_t ncurves)
{
    unsigned char *clist, *p;
    size_t i;
    /*
     * Bitmap of curves included to detect duplicates: only works while curve
     * ids < 32
     */
    unsigned long dup_list = 0;
    clist = OPENSSL_malloc(ncurves * 2);
    if (clist == NULL)
        return 0;
    for (i = 0, p = clist; i < ncurves; i++) {
        unsigned long idmask;
        int id;
        id = tls1_ec_nid2curve_id(curves[i]);
        idmask = 1L << id;
        if (!id || (dup_list & idmask)) {
            OPENSSL_free(clist);
            return 0;
        }
        dup_list |= idmask;
        s2n(id, p);
    }
    OPENSSL_free(*pext);
    *pext = clist;
    *pextlen = ncurves * 2;
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

/* Set curves based on a colon separate list */
int tls1_set_curves_list(unsigned char **pext, size_t *pextlen,
                         const char *str)
{
    nid_cb_st ncb;
    ncb.nidcnt = 0;
    if (!CONF_parse_list(str, ':', 1, nid_cb, &ncb))
        return 0;
    if (pext == NULL)
        return 1;
    return tls1_set_curves(pext, pextlen, ncb.nid_arr, ncb.nidcnt);
}

/* For an EC key set TLS id and required compression based on parameters */
static int tls1_set_ec_id(unsigned char *curve_id, unsigned char *comp_id,
                          EC_KEY *ec)
{
    int is_prime, id;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    if (!ec)
        return 0;
    /* Determine if it is a prime field */
    grp = EC_KEY_get0_group(ec);
    if (!grp)
        return 0;
    meth = EC_GROUP_method_of(grp);
    if (!meth)
        return 0;
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
        is_prime = 1;
    else
        is_prime = 0;
    /* Determine curve ID */
    id = EC_GROUP_get_curve_name(grp);
    id = tls1_ec_nid2curve_id(id);
    /* If we have an ID set it, otherwise set arbitrary explicit curve */
    if (id) {
        curve_id[0] = 0;
        curve_id[1] = (unsigned char)id;
    } else {
        curve_id[0] = 0xff;
        if (is_prime)
            curve_id[1] = 0x01;
        else
            curve_id[1] = 0x02;
    }
    if (comp_id) {
        if (EC_KEY_get0_public_key(ec) == NULL)
            return 0;
        if (EC_KEY_get_conv_form(ec) == POINT_CONVERSION_COMPRESSED) {
            if (is_prime)
                *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime;
            else
                *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;
        } else
            *comp_id = TLSEXT_ECPOINTFORMAT_uncompressed;
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
    if (comp_id && s->session->tlsext_ecpointformatlist) {
        pformats = s->session->tlsext_ecpointformatlist;
        num_formats = s->session->tlsext_ecpointformatlist_length;
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

static void tls1_get_formatlist(SSL *s, const unsigned char **pformats,
                                size_t *num_formats)
{
    /*
     * If we have a custom point format list use it otherwise use default
     */
    if (s->tlsext_ecpointformatlist) {
        *pformats = s->tlsext_ecpointformatlist;
        *num_formats = s->tlsext_ecpointformatlist_length;
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
    pkey = X509_get_pubkey(x);
    if (!pkey)
        return 0;
    /* If not EC nothing to do */
    if (pkey->type != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return 1;
    }
    rv = tls1_set_ec_id(curve_id, &comp_id, pkey->pkey.ec);
    EVP_PKEY_free(pkey);
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
/* Check EC temporary key is compatible with client extensions */
int tls1_check_ec_tmp_key(SSL *s, unsigned long cid)
{
    unsigned char curve_id[2];
    EC_KEY *ec = s->cert->ecdh_tmp;
#  ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    /* Allow any curve: not just those peer supports */
    if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL)
        return 1;
#  endif
    /*
     * If Suite B, AES128 MUST use P-256 and AES256 MUST use P-384, no other
     * curves permitted.
     */
    if (tls1_suiteb(s)) {
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
        /* If auto or setting curve from callback assume OK */
        if (s->cert->ecdh_tmp_auto || s->cert->ecdh_tmp_cb)
            return 1;
        /* Otherwise check curve is acceptable */
        else {
            unsigned char curve_tmp[2];
            if (!ec)
                return 0;
            if (!tls1_set_ec_id(curve_tmp, NULL, ec))
                return 0;
            if (!curve_tmp[0] || curve_tmp[1] == curve_id[1])
                return 1;
            return 0;
        }

    }
    if (s->cert->ecdh_tmp_auto) {
        /* Need a shared curve */
        if (tls1_shared_curve(s, 0))
            return 1;
        else
            return 0;
    }
    if (!ec) {
        if (s->cert->ecdh_tmp_cb)
            return 1;
        else
            return 0;
    }
    if (!tls1_set_ec_id(curve_id, NULL, ec))
        return 0;
/* Set this to allow use of invalid curves for testing */
#  if 0
    return 1;
#  else
    return tls1_check_ec_key(s, curve_id, NULL);
#  endif
}
# endif                         /* OPENSSL_NO_EC */

#else

static int tls1_check_cert_param(SSL *s, X509 *x, int set_ee_md)
{
    return 1;
}

#endif                          /* OPENSSL_NO_EC */

/*
 * List of supported signature algorithms and hashes. Should make this
 * customisable at some point, for now include everything we support.
 */

#ifdef OPENSSL_NO_RSA
# define tlsext_sigalg_rsa(md) /* */
#else
# define tlsext_sigalg_rsa(md) md, TLSEXT_signature_rsa,
#endif

#ifdef OPENSSL_NO_DSA
# define tlsext_sigalg_dsa(md) /* */
#else
# define tlsext_sigalg_dsa(md) md, TLSEXT_signature_dsa,
#endif

#ifdef OPENSSL_NO_EC
# define tlsext_sigalg_ecdsa(md) /* */
#else
# define tlsext_sigalg_ecdsa(md) md, TLSEXT_signature_ecdsa,
#endif

#define tlsext_sigalg(md) \
                tlsext_sigalg_rsa(md) \
                tlsext_sigalg_dsa(md) \
                tlsext_sigalg_ecdsa(md)

static const unsigned char tls12_sigalgs[] = {
    tlsext_sigalg(TLSEXT_hash_sha512)
        tlsext_sigalg(TLSEXT_hash_sha384)
        tlsext_sigalg(TLSEXT_hash_sha256)
        tlsext_sigalg(TLSEXT_hash_sha224)
        tlsext_sigalg(TLSEXT_hash_sha1)
#ifndef OPENSSL_NO_GOST
        TLSEXT_hash_gostr3411, TLSEXT_signature_gostr34102001,
        TLSEXT_hash_gostr34112012_256, TLSEXT_signature_gostr34102012_256,
        TLSEXT_hash_gostr34112012_512, TLSEXT_signature_gostr34102012_512
#endif
};

#ifndef OPENSSL_NO_EC
static const unsigned char suiteb_sigalgs[] = {
    tlsext_sigalg_ecdsa(TLSEXT_hash_sha256)
        tlsext_sigalg_ecdsa(TLSEXT_hash_sha384)
};
#endif
size_t tls12_get_psigalgs(SSL *s, const unsigned char **psigs)
{
    /*
     * If Suite B mode use Suite B sigalgs only, ignore any other
     * preferences.
     */
#ifndef OPENSSL_NO_EC
    switch (tls1_suiteb(s)) {
    case SSL_CERT_FLAG_SUITEB_128_LOS:
        *psigs = suiteb_sigalgs;
        return sizeof(suiteb_sigalgs);

    case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *psigs = suiteb_sigalgs;
        return 2;

    case SSL_CERT_FLAG_SUITEB_192_LOS:
        *psigs = suiteb_sigalgs + 2;
        return 2;
    }
#endif
    /* If server use client authentication sigalgs if not NULL */
    if (s->server && s->cert->client_sigalgs) {
        *psigs = s->cert->client_sigalgs;
        return s->cert->client_sigalgslen;
    } else if (s->cert->conf_sigalgs) {
        *psigs = s->cert->conf_sigalgs;
        return s->cert->conf_sigalgslen;
    } else {
        *psigs = tls12_sigalgs;
        return sizeof(tls12_sigalgs);
    }
}

/*
 * Check signature algorithm is consistent with sent supported signature
 * algorithms and if so return relevant digest.
 */
int tls12_check_peer_sigalg(const EVP_MD **pmd, SSL *s,
                            const unsigned char *sig, EVP_PKEY *pkey)
{
    const unsigned char *sent_sigs;
    size_t sent_sigslen, i;
    int sigalg = tls12_get_sigid(pkey);
    /* Should never happen */
    if (sigalg == -1)
        return -1;
    /* Check key type is consistent with signature */
    if (sigalg != (int)sig[1]) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
#ifndef OPENSSL_NO_EC
    if (pkey->type == EVP_PKEY_EC) {
        unsigned char curve_id[2], comp_id;
        /* Check compression and curve matches extensions */
        if (!tls1_set_ec_id(curve_id, &comp_id, pkey->pkey.ec))
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
                if (sig[0] != TLSEXT_hash_sha256) {
                    SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG,
                           SSL_R_ILLEGAL_SUITEB_DIGEST);
                    return 0;
                }
            } else if (curve_id[1] == TLSEXT_curve_P_384) {
                if (sig[0] != TLSEXT_hash_sha384) {
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
    sent_sigslen = tls12_get_psigalgs(s, &sent_sigs);
    for (i = 0; i < sent_sigslen; i += 2, sent_sigs += 2) {
        if (sig[0] == sent_sigs[0] && sig[1] == sent_sigs[1])
            break;
    }
    /* Allow fallback to SHA1 if not strict mode */
    if (i == sent_sigslen
        && (sig[0] != TLSEXT_hash_sha1
            || s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
    *pmd = tls12_get_hash(sig[0]);
    if (*pmd == NULL) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_UNKNOWN_DIGEST);
        return 0;
    }
    /* Make sure security callback allows algorithm */
    if (!ssl_security(s, SSL_SECOP_SIGALG_CHECK,
                      EVP_MD_size(*pmd) * 4, EVP_MD_type(*pmd),
                      (void *)sig)) {
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
 * Get a mask of disabled algorithms: an algorithm is disabled if it isn't
 * supported or doesn't appear in supported signature algorithms. Unlike
 * ssl_cipher_get_disabled this applies to a specific session and not global
 * settings.
 */
void ssl_set_client_disabled(SSL *s)
{
    s->s3->tmp.mask_a = 0;
    s->s3->tmp.mask_k = 0;
    /* Don't allow TLS 1.2 only ciphers if we don't suppport them */
    if (!SSL_CLIENT_USE_TLS1_2_CIPHERS(s))
        s->s3->tmp.mask_ssl = SSL_TLSV1_2;
    else
        s->s3->tmp.mask_ssl = 0;
    /* Disable TLS 1.0 ciphers if using SSL v3 */
    if (s->client_version == SSL3_VERSION)
        s->s3->tmp.mask_ssl |= SSL_TLSV1;
    ssl_set_sig_mask(&s->s3->tmp.mask_a, s, SSL_SECOP_SIGALG_MASK);
    /*
     * Disable static DH if we don't include any appropriate signature
     * algorithms.
     */
    if (s->s3->tmp.mask_a & SSL_aRSA)
        s->s3->tmp.mask_k |= SSL_kDHr | SSL_kECDHr;
    if (s->s3->tmp.mask_a & SSL_aDSS)
        s->s3->tmp.mask_k |= SSL_kDHd;
    if (s->s3->tmp.mask_a & SSL_aECDSA)
        s->s3->tmp.mask_k |= SSL_kECDHe;
# ifndef OPENSSL_NO_PSK
    /* with PSK there must be client callback set */
    if (!s->psk_client_callback) {
        s->s3->tmp.mask_a |= SSL_aPSK;
        s->s3->tmp.mask_k |= SSL_PSK;
    }
#endif                         /* OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (!(s->srp_ctx.srp_Mask & SSL_kSRP)) {
        s->s3->tmp.mask_a |= SSL_aSRP;
        s->s3->tmp.mask_k |= SSL_kSRP;
    }
#endif
}

int ssl_cipher_disabled(SSL *s, const SSL_CIPHER *c, int op)
{
    if (c->algorithm_ssl & s->s3->tmp.mask_ssl
        || c->algorithm_mkey & s->s3->tmp.mask_k
        || c->algorithm_auth & s->s3->tmp.mask_a)
        return 1;
    return !ssl_security(s, op, c->strength_bits, 0, (void *)c);
}

static int tls_use_ticket(SSL *s)
{
    if (s->options & SSL_OP_NO_TICKET)
        return 0;
    return ssl_security(s, SSL_SECOP_TICKET, 0, 0, NULL);
}

unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *buf,
                                          unsigned char *limit, int *al)
{
    int extdatalen = 0;
    unsigned char *orig = buf;
    unsigned char *ret = buf;
#ifndef OPENSSL_NO_EC
    /* See if we support any ECC ciphersuites */
    int using_ecc = 0;
    if (s->version >= TLS1_VERSION || SSL_IS_DTLS(s)) {
        int i;
        unsigned long alg_k, alg_a;
        STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(s);

        for (i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);

            alg_k = c->algorithm_mkey;
            alg_a = c->algorithm_auth;
            if ((alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe | SSL_kECDHEPSK)
                 || (alg_a & SSL_aECDSA))) {
                using_ecc = 1;
                break;
            }
        }
    }
#endif

    ret += 2;

    if (ret >= limit)
        return NULL;            /* this really never occurs, but ... */

    /* Add RI if renegotiating */
    if (s->renegotiate) {
        int el;

        if (!ssl_add_clienthello_renegotiate_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_renegotiate, ret);
        s2n(el, ret);

        if (!ssl_add_clienthello_renegotiate_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        ret += el;
    }
    /* Only add RI for SSLv3 */
    if (s->client_version == SSL3_VERSION)
        goto done;

    if (s->tlsext_hostname != NULL) {
        /* Add TLS extension servername to the Client Hello message */
        unsigned long size_str;
        long lenmax;

        /*-
         * check for enough space.
         * 4 for the servername type and entension length
         * 2 for servernamelist length
         * 1 for the hostname type
         * 2 for hostname length
         * + hostname length
         */

        if ((lenmax = limit - ret - 9) < 0
            || (size_str =
                strlen(s->tlsext_hostname)) > (unsigned long)lenmax)
            return NULL;

        /* extension type and length */
        s2n(TLSEXT_TYPE_server_name, ret);
        s2n(size_str + 5, ret);

        /* length of servername list */
        s2n(size_str + 3, ret);

        /* hostname type, length and hostname */
        *(ret++) = (unsigned char)TLSEXT_NAMETYPE_host_name;
        s2n(size_str, ret);
        memcpy(ret, s->tlsext_hostname, size_str);
        ret += size_str;
    }
#ifndef OPENSSL_NO_SRP
    /* Add SRP username if there is one */
    if (s->srp_ctx.login != NULL) { /* Add TLS extension SRP username to the
                                     * Client Hello message */

        int login_len = strlen(s->srp_ctx.login);
        if (login_len > 255 || login_len == 0) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        /*-
         * check for enough space.
         * 4 for the srp type type and entension length
         * 1 for the srp user identity
         * + srp user identity length
         */
        if ((limit - ret - 5 - login_len) < 0)
            return NULL;

        /* fill in the extension */
        s2n(TLSEXT_TYPE_srp, ret);
        s2n(login_len + 1, ret);
        (*ret++) = (unsigned char)login_len;
        memcpy(ret, s->srp_ctx.login, login_len);
        ret += login_len;
    }
#endif

#ifndef OPENSSL_NO_EC
    if (using_ecc) {
        /*
         * Add TLS extension ECPointFormats to the ClientHello message
         */
        long lenmax;
        const unsigned char *pcurves, *pformats;
        size_t num_curves, num_formats, curves_list_len;
        size_t i;
        unsigned char *etmp;

        tls1_get_formatlist(s, &pformats, &num_formats);

        if ((lenmax = limit - ret - 5) < 0)
            return NULL;
        if (num_formats > (size_t)lenmax)
            return NULL;
        if (num_formats > 255) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_ec_point_formats, ret);
        /* The point format list has 1-byte length. */
        s2n(num_formats + 1, ret);
        *(ret++) = (unsigned char)num_formats;
        memcpy(ret, pformats, num_formats);
        ret += num_formats;

        /*
         * Add TLS extension EllipticCurves to the ClientHello message
         */
        pcurves = s->tlsext_ellipticcurvelist;
        if (!tls1_get_curvelist(s, 0, &pcurves, &num_curves))
            return NULL;

        if ((lenmax = limit - ret - 6) < 0)
            return NULL;
        if (num_curves > (size_t)lenmax / 2)
            return NULL;
        if (num_curves > 65532 / 2) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_elliptic_curves, ret);
        etmp = ret + 4;
        /* Copy curve ID if supported */
        for (i = 0; i < num_curves; i++, pcurves += 2) {
            if (tls_curve_allowed(s, pcurves, SSL_SECOP_CURVE_SUPPORTED)) {
                *etmp++ = pcurves[0];
                *etmp++ = pcurves[1];
            }
        }

        curves_list_len = etmp - ret - 4;

        s2n(curves_list_len + 2, ret);
        s2n(curves_list_len, ret);
        ret += curves_list_len;
    }
#endif                         /* OPENSSL_NO_EC */

    if (tls_use_ticket(s)) {
        int ticklen;
        if (!s->new_session && s->session && s->session->tlsext_tick)
            ticklen = s->session->tlsext_ticklen;
        else if (s->session && s->tlsext_session_ticket &&
                 s->tlsext_session_ticket->data) {
            ticklen = s->tlsext_session_ticket->length;
            s->session->tlsext_tick = OPENSSL_malloc(ticklen);
            if (s->session->tlsext_tick == NULL)
                return NULL;
            memcpy(s->session->tlsext_tick,
                   s->tlsext_session_ticket->data, ticklen);
            s->session->tlsext_ticklen = ticklen;
        } else
            ticklen = 0;
        if (ticklen == 0 && s->tlsext_session_ticket &&
            s->tlsext_session_ticket->data == NULL)
            goto skip_ext;
        /*
         * Check for enough room 2 for extension type, 2 for len rest for
         * ticket
         */
        if ((long)(limit - ret - 4 - ticklen) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_session_ticket, ret);
        s2n(ticklen, ret);
        if (ticklen) {
            memcpy(ret, s->session->tlsext_tick, ticklen);
            ret += ticklen;
        }
    }
 skip_ext:

    if (SSL_USE_SIGALGS(s)) {
        size_t salglen;
        const unsigned char *salg;
        unsigned char *etmp;
        salglen = tls12_get_psigalgs(s, &salg);
        if ((size_t)(limit - ret) < salglen + 6)
            return NULL;
        s2n(TLSEXT_TYPE_signature_algorithms, ret);
        etmp = ret;
        /* Skip over lengths for now */
        ret += 4;
        salglen = tls12_copy_sigalgs(s, ret, salg, salglen);
        /* Fill in lengths */
        s2n(salglen + 2, etmp);
        s2n(salglen, etmp);
        ret += salglen;
    }

    if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
        int i;
        long extlen, idlen, itmp;
        OCSP_RESPID *id;

        idlen = 0;
        for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
            id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
            itmp = i2d_OCSP_RESPID(id, NULL);
            if (itmp <= 0)
                return NULL;
            idlen += itmp + 2;
        }

        if (s->tlsext_ocsp_exts) {
            extlen = i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, NULL);
            if (extlen < 0)
                return NULL;
        } else
            extlen = 0;

        if ((long)(limit - ret - 7 - extlen - idlen) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_status_request, ret);
        if (extlen + idlen > 0xFFF0)
            return NULL;
        s2n(extlen + idlen + 5, ret);
        *(ret++) = TLSEXT_STATUSTYPE_ocsp;
        s2n(idlen, ret);
        for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
            /* save position of id len */
            unsigned char *q = ret;
            id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
            /* skip over id len */
            ret += 2;
            itmp = i2d_OCSP_RESPID(id, &ret);
            /* write id len */
            s2n(itmp, q);
        }
        s2n(extlen, ret);
        if (extlen > 0)
            i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, &ret);
    }
#ifndef OPENSSL_NO_HEARTBEATS
    /* Add Heartbeat extension */
    if ((limit - ret - 4 - 1) < 0)
        return NULL;
    s2n(TLSEXT_TYPE_heartbeat, ret);
    s2n(1, ret);
    /*-
     * Set mode:
     * 1: peer may send requests
     * 2: peer not allowed to send requests
     */
    if (s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_RECV_REQUESTS)
        *(ret++) = SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
    else
        *(ret++) = SSL_TLSEXT_HB_ENABLED;
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
    if (s->ctx->next_proto_select_cb && !s->s3->tmp.finish_md_len) {
        /*
         * The client advertises an emtpy extension to indicate its support
         * for Next Protocol Negotiation
         */
        if (limit - ret - 4 < 0)
            return NULL;
        s2n(TLSEXT_TYPE_next_proto_neg, ret);
        s2n(0, ret);
    }
#endif

    if (s->alpn_client_proto_list && !s->s3->tmp.finish_md_len) {
        if ((size_t)(limit - ret) < 6 + s->alpn_client_proto_list_len)
            return NULL;
        s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
        s2n(2 + s->alpn_client_proto_list_len, ret);
        s2n(s->alpn_client_proto_list_len, ret);
        memcpy(ret, s->alpn_client_proto_list, s->alpn_client_proto_list_len);
        ret += s->alpn_client_proto_list_len;
    }
#ifndef OPENSSL_NO_SRTP
    if (SSL_IS_DTLS(s) && SSL_get_srtp_profiles(s)) {
        int el;

        /* Returns 0 on success!! */
        if (ssl_add_clienthello_use_srtp_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_use_srtp, ret);
        s2n(el, ret);

        if (ssl_add_clienthello_use_srtp_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        ret += el;
    }
#endif
    custom_ext_init(&s->cert->cli_ext);
    /* Add custom TLS Extensions to ClientHello */
    if (!custom_ext_add(s, 0, &ret, limit, al))
        return NULL;
#ifdef TLSEXT_TYPE_encrypt_then_mac
    s2n(TLSEXT_TYPE_encrypt_then_mac, ret);
    s2n(0, ret);
#endif
    s2n(TLSEXT_TYPE_extended_master_secret, ret);
    s2n(0, ret);

    /*
     * Add padding to workaround bugs in F5 terminators. See
     * https://tools.ietf.org/html/draft-agl-tls-padding-03 NB: because this
     * code works out the length of all existing extensions it MUST always
     * appear last.
     */
    if (s->options & SSL_OP_TLSEXT_PADDING) {
        int hlen = ret - (unsigned char *)s->init_buf->data;

        if (hlen > 0xff && hlen < 0x200) {
            hlen = 0x200 - hlen;
            if (hlen >= 4)
                hlen -= 4;
            else
                hlen = 0;

            s2n(TLSEXT_TYPE_padding, ret);
            s2n(hlen, ret);
            memset(ret, 0, hlen);
            ret += hlen;
        }
    }

 done:

    if ((extdatalen = ret - orig - 2) == 0)
        return orig;

    s2n(extdatalen, orig);
    return ret;
}

unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *buf,
                                          unsigned char *limit, int *al)
{
    int extdatalen = 0;
    unsigned char *orig = buf;
    unsigned char *ret = buf;
#ifndef OPENSSL_NO_NEXTPROTONEG
    int next_proto_neg_seen;
#endif
#ifndef OPENSSL_NO_EC
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    int using_ecc = (alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe))
        || (alg_a & SSL_aECDSA);
    using_ecc = using_ecc && (s->session->tlsext_ecpointformatlist != NULL);
#endif

    ret += 2;
    if (ret >= limit)
        return NULL;            /* this really never occurs, but ... */

    if (s->s3->send_connection_binding) {
        int el;

        if (!ssl_add_serverhello_renegotiate_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_renegotiate, ret);
        s2n(el, ret);

        if (!ssl_add_serverhello_renegotiate_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        ret += el;
    }

    /* Only add RI for SSLv3 */
    if (s->version == SSL3_VERSION)
        goto done;

    if (!s->hit && s->servername_done == 1
        && s->session->tlsext_hostname != NULL) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_server_name, ret);
        s2n(0, ret);
    }
#ifndef OPENSSL_NO_EC
    if (using_ecc) {
        const unsigned char *plist;
        size_t plistlen;
        /*
         * Add TLS extension ECPointFormats to the ServerHello message
         */
        long lenmax;

        tls1_get_formatlist(s, &plist, &plistlen);

        if ((lenmax = limit - ret - 5) < 0)
            return NULL;
        if (plistlen > (size_t)lenmax)
            return NULL;
        if (plistlen > 255) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_ec_point_formats, ret);
        s2n(plistlen + 1, ret);
        *(ret++) = (unsigned char)plistlen;
        memcpy(ret, plist, plistlen);
        ret += plistlen;

    }
    /*
     * Currently the server should not respond with a SupportedCurves
     * extension
     */
#endif                         /* OPENSSL_NO_EC */

    if (s->tlsext_ticket_expected && tls_use_ticket(s)) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_session_ticket, ret);
        s2n(0, ret);
    }

    if (s->tlsext_status_expected) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_status_request, ret);
        s2n(0, ret);
    }

#ifndef OPENSSL_NO_SRTP
    if (SSL_IS_DTLS(s) && s->srtp_profile) {
        int el;

        /* Returns 0 on success!! */
        if (ssl_add_serverhello_use_srtp_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_use_srtp, ret);
        s2n(el, ret);

        if (ssl_add_serverhello_use_srtp_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        ret += el;
    }
#endif

    if (((s->s3->tmp.new_cipher->id & 0xFFFF) == 0x80
         || (s->s3->tmp.new_cipher->id & 0xFFFF) == 0x81)
        && (SSL_get_options(s) & SSL_OP_CRYPTOPRO_TLSEXT_BUG)) {
        const unsigned char cryptopro_ext[36] = {
            0xfd, 0xe8,         /* 65000 */
            0x00, 0x20,         /* 32 bytes length */
            0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
            0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
            0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08,
            0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17
        };
        if (limit - ret < 36)
            return NULL;
        memcpy(ret, cryptopro_ext, 36);
        ret += 36;

    }
#ifndef OPENSSL_NO_HEARTBEATS
    /* Add Heartbeat extension if we've received one */
    if (s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) {
        if ((limit - ret - 4 - 1) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_heartbeat, ret);
        s2n(1, ret);
        /*-
         * Set mode:
         * 1: peer may send requests
         * 2: peer not allowed to send requests
         */
        if (s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_RECV_REQUESTS)
            *(ret++) = SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
        else
            *(ret++) = SSL_TLSEXT_HB_ENABLED;

    }
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
    next_proto_neg_seen = s->s3->next_proto_neg_seen;
    s->s3->next_proto_neg_seen = 0;
    if (next_proto_neg_seen && s->ctx->next_protos_advertised_cb) {
        const unsigned char *npa;
        unsigned int npalen;
        int r;

        r = s->ctx->next_protos_advertised_cb(s, &npa, &npalen,
                                              s->
                                              ctx->next_protos_advertised_cb_arg);
        if (r == SSL_TLSEXT_ERR_OK) {
            if ((long)(limit - ret - 4 - npalen) < 0)
                return NULL;
            s2n(TLSEXT_TYPE_next_proto_neg, ret);
            s2n(npalen, ret);
            memcpy(ret, npa, npalen);
            ret += npalen;
            s->s3->next_proto_neg_seen = 1;
        }
    }
#endif
    if (!custom_ext_add(s, 1, &ret, limit, al))
        return NULL;
#ifdef TLSEXT_TYPE_encrypt_then_mac
    if (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC) {
        /*
         * Don't use encrypt_then_mac if AEAD or RC4 might want to disable
         * for other cases too.
         */
        if (s->s3->tmp.new_cipher->algorithm_mac == SSL_AEAD
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_RC4
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12)
            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
        else {
            s2n(TLSEXT_TYPE_encrypt_then_mac, ret);
            s2n(0, ret);
        }
    }
#endif
    if (!s->hit && s->session->flags & SSL_SESS_FLAG_EXTMS) {
        s2n(TLSEXT_TYPE_extended_master_secret, ret);
        s2n(0, ret);
    }

    if (s->s3->alpn_selected) {
        const unsigned char *selected = s->s3->alpn_selected;
        unsigned len = s->s3->alpn_selected_len;

        if ((long)(limit - ret - 4 - 2 - 1 - len) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
        s2n(3 + len, ret);
        s2n(1 + len, ret);
        *ret++ = len;
        memcpy(ret, selected, len);
        ret += len;
    }

 done:

    if ((extdatalen = ret - orig - 2) == 0)
        return orig;

    s2n(extdatalen, orig);
    return ret;
}

/*
 * tls1_alpn_handle_client_hello is called to process the ALPN extension in a
 * ClientHello.  data: the contents of the extension, not including the type
 * and length.  data_len: the number of bytes in |data| al: a pointer to the
 * alert value to send in the event of a non-zero return.  returns: 0 on
 * success.
 */
static int tls1_alpn_handle_client_hello(SSL *s, PACKET *pkt, int *al)
{
    unsigned int data_len;
    unsigned int proto_len;
    const unsigned char *selected;
    unsigned char *data;
    unsigned char selected_len;
    int r;

    if (s->ctx->alpn_select_cb == NULL)
        return 0;

    /*
     * data should contain a uint16 length followed by a series of 8-bit,
     * length-prefixed strings.
     */
    if (!PACKET_get_net_2(pkt, &data_len)
            || PACKET_remaining(pkt) != data_len
            || !PACKET_peek_bytes(pkt, &data, data_len))
        goto parse_error;

    do {
        if (!PACKET_get_1(pkt, &proto_len)
                || proto_len == 0
                || !PACKET_forward(pkt, proto_len))
            goto parse_error;
    } while (PACKET_remaining(pkt));

    r = s->ctx->alpn_select_cb(s, &selected, &selected_len, data, data_len,
                               s->ctx->alpn_select_cb_arg);
    if (r == SSL_TLSEXT_ERR_OK) {
        OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = OPENSSL_malloc(selected_len);
        if (s->s3->alpn_selected == NULL) {
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
        memcpy(s->s3->alpn_selected, selected, selected_len);
        s->s3->alpn_selected_len = selected_len;
    }
    return 0;

 parse_error:
    *al = SSL_AD_DECODE_ERROR;
    return -1;
}

#ifndef OPENSSL_NO_EC
/*-
 * ssl_check_for_safari attempts to fingerprint Safari using OS X
 * SecureTransport using the TLS extension block in |d|, of length |n|.
 * Safari, since 10.6, sends exactly these extensions, in this order:
 *   SNI,
 *   elliptic_curves
 *   ec_point_formats
 *
 * We wish to fingerprint Safari because they broke ECDHE-ECDSA support in 10.8,
 * but they advertise support. So enabling ECDHE-ECDSA ciphers breaks them.
 * Sadly we cannot differentiate 10.6, 10.7 and 10.8.4 (which work), from
 * 10.8..10.8.3 (which don't work).
 */
static void ssl_check_for_safari(SSL *s, const PACKET *pkt)
{
    unsigned int type, size;
    unsigned char *eblock1, *eblock2;
    PACKET tmppkt;

    static const unsigned char kSafariExtensionsBlock[] = {
        0x00, 0x0a,             /* elliptic_curves extension */
        0x00, 0x08,             /* 8 bytes */
        0x00, 0x06,             /* 6 bytes of curve ids */
        0x00, 0x17,             /* P-256 */
        0x00, 0x18,             /* P-384 */
        0x00, 0x19,             /* P-521 */

        0x00, 0x0b,             /* ec_point_formats */
        0x00, 0x02,             /* 2 bytes */
        0x01,                   /* 1 point format */
        0x00,                   /* uncompressed */
    };

    /* The following is only present in TLS 1.2 */
    static const unsigned char kSafariTLS12ExtensionsBlock[] = {
        0x00, 0x0d,             /* signature_algorithms */
        0x00, 0x0c,             /* 12 bytes */
        0x00, 0x0a,             /* 10 bytes */
        0x05, 0x01,             /* SHA-384/RSA */
        0x04, 0x01,             /* SHA-256/RSA */
        0x02, 0x01,             /* SHA-1/RSA */
        0x04, 0x03,             /* SHA-256/ECDSA */
        0x02, 0x03,             /* SHA-1/ECDSA */
    };

    tmppkt = *pkt;

    if (!PACKET_forward(&tmppkt, 2)
            || !PACKET_get_net_2(&tmppkt, &type)
            || !PACKET_get_net_2(&tmppkt, &size)
            || !PACKET_forward(&tmppkt, size))
        return;

    if (type != TLSEXT_TYPE_server_name)
        return;

    if (TLS1_get_client_version(s) >= TLS1_2_VERSION) {
        const size_t len1 = sizeof(kSafariExtensionsBlock);
        const size_t len2 = sizeof(kSafariTLS12ExtensionsBlock);

        if (!PACKET_get_bytes(&tmppkt, &eblock1, len1)
                || !PACKET_get_bytes(&tmppkt, &eblock2, len2)
                || PACKET_remaining(&tmppkt))
            return;
        if (memcmp(eblock1, kSafariExtensionsBlock, len1) != 0)
            return;
        if (memcmp(eblock2, kSafariTLS12ExtensionsBlock, len2) != 0)
            return;
    } else {
        const size_t len = sizeof(kSafariExtensionsBlock);

        if (!PACKET_get_bytes(&tmppkt, &eblock1, len)
                || PACKET_remaining(&tmppkt))
            return;
        if (memcmp(eblock1, kSafariExtensionsBlock, len) != 0)
            return;
    }

    s->s3->is_probably_safari = 1;
}
#endif                         /* !OPENSSL_NO_EC */

static int ssl_scan_clienthello_tlsext(SSL *s, PACKET *pkt, int *al)
{
    unsigned int type;
    unsigned int size;
    unsigned int len;
    unsigned char *data;
    int renegotiate_seen = 0;

    s->servername_done = 0;
    s->tlsext_status_type = -1;
#ifndef OPENSSL_NO_NEXTPROTONEG
    s->s3->next_proto_neg_seen = 0;
#endif

    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;
#ifndef OPENSSL_NO_HEARTBEATS
    s->tlsext_heartbeat &= ~(SSL_TLSEXT_HB_ENABLED |
                             SSL_TLSEXT_HB_DONT_SEND_REQUESTS);
#endif

#ifndef OPENSSL_NO_EC
    if (s->options & SSL_OP_SAFARI_ECDHE_ECDSA_BUG)
        ssl_check_for_safari(s, pkt);
# endif /* !OPENSSL_NO_EC */

    /* Clear any signature algorithms extension received */
    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = NULL;
#ifdef TLSEXT_TYPE_encrypt_then_mac
    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
#endif

#ifndef OPENSSL_NO_SRP
    OPENSSL_free(s->srp_ctx.login);
    s->srp_ctx.login = NULL;
#endif

    s->srtp_profile = NULL;

    if (PACKET_remaining(pkt) == 0)
        goto ri_check;

    if (!PACKET_get_net_2(pkt, &len))
        goto err;

    if (PACKET_remaining(pkt) != len)
        goto err;

    while (PACKET_get_net_2(pkt, &type) && PACKET_get_net_2(pkt, &size)) {
        PACKET subpkt;

        if (!PACKET_peek_bytes(pkt, &data, size))
            goto err;

        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, 0, type, data, size, s->tlsext_debug_arg);

        if (!PACKET_get_sub_packet(pkt, &subpkt, size))
            goto err;

        if (type == TLSEXT_TYPE_renegotiate) {
            if (!ssl_parse_clienthello_renegotiate_ext(s, &subpkt, al))
                return 0;
            renegotiate_seen = 1;
        } else if (s->version == SSL3_VERSION) {
        }
/*-
 * The servername extension is treated as follows:
 *
 * - Only the hostname type is supported with a maximum length of 255.
 * - The servername is rejected if too long or if it contains zeros,
 *   in which case an fatal alert is generated.
 * - The servername field is maintained together with the session cache.
 * - When a session is resumed, the servername call back invoked in order
 *   to allow the application to position itself to the right context.
 * - The servername is acknowledged if it is new for a session or when
 *   it is identical to a previously used for the same session.
 *   Applications can control the behaviour.  They can at any time
 *   set a 'desirable' servername for a new SSL object. This can be the
 *   case for example with HTTPS when a Host: header field is received and
 *   a renegotiation is requested. In this case, a possible servername
 *   presented in the new client hello is only acknowledged if it matches
 *   the value of the Host: field.
 * - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
 *   if they provide for changing an explicit servername context for the
 *   session, i.e. when the session has been established with a servername
 *   extension.
 * - On session reconnect, the servername extension may be absent.
 *
 */

        else if (type == TLSEXT_TYPE_server_name) {
            unsigned char *sdata;
            unsigned int servname_type;
            unsigned int dsize;
            PACKET ssubpkt;

            if (!PACKET_get_net_2(&subpkt, &dsize)
                    || !PACKET_get_sub_packet(&subpkt, &ssubpkt, dsize))
                goto err;

            while (PACKET_remaining(&ssubpkt) > 3) {
                if (!PACKET_get_1(&ssubpkt, &servname_type)
                        || !PACKET_get_net_2(&ssubpkt, &len)
                        || PACKET_remaining(&ssubpkt) < len)
                    goto err;

                if (s->servername_done == 0)
                    switch (servname_type) {
                    case TLSEXT_NAMETYPE_host_name:
                        if (!s->hit) {
                            if (s->session->tlsext_hostname)
                                goto err;

                            if (len > TLSEXT_MAXLEN_host_name) {
                                *al = TLS1_AD_UNRECOGNIZED_NAME;
                                return 0;
                            }
                            if ((s->session->tlsext_hostname =
                                 OPENSSL_malloc(len + 1)) == NULL) {
                                *al = TLS1_AD_INTERNAL_ERROR;
                                return 0;
                            }
                            if (!PACKET_copy_bytes(&ssubpkt,
                                    (unsigned char *)s->session
                                        ->tlsext_hostname,
                                    len)) {
                                *al = SSL_AD_DECODE_ERROR;
                                return 0;
                            }
                            s->session->tlsext_hostname[len] = '\0';
                            if (strlen(s->session->tlsext_hostname) != len) {
                                OPENSSL_free(s->session->tlsext_hostname);
                                s->session->tlsext_hostname = NULL;
                                *al = TLS1_AD_UNRECOGNIZED_NAME;
                                return 0;
                            }
                            s->servername_done = 1;

                        } else {
                            if (!PACKET_get_bytes(&ssubpkt, &sdata, len)) {
                                *al = SSL_AD_DECODE_ERROR;
                                return 0;
                            }
                            s->servername_done = s->session->tlsext_hostname
                                && strlen(s->session->tlsext_hostname) == len
                                && strncmp(s->session->tlsext_hostname,
                                           (char *)sdata, len) == 0;
                        }

                        break;

                    default:
                        break;
                    }
            }
            /* We shouldn't have any bytes left */
            if (PACKET_remaining(&ssubpkt) != 0)
                goto err;

        }
#ifndef OPENSSL_NO_SRP
        else if (type == TLSEXT_TYPE_srp) {
            if (!PACKET_get_1(&subpkt, &len)
                    || s->srp_ctx.login != NULL)
                goto err;

            if ((s->srp_ctx.login = OPENSSL_malloc(len + 1)) == NULL)
                return -1;
            if (!PACKET_copy_bytes(&subpkt, (unsigned char *)s->srp_ctx.login,
                                   len))
                goto err;
            s->srp_ctx.login[len] = '\0';

            if (strlen(s->srp_ctx.login) != len
                    || PACKET_remaining(&subpkt))
                goto err;
        }
#endif

#ifndef OPENSSL_NO_EC
        else if (type == TLSEXT_TYPE_ec_point_formats) {
            unsigned int ecpointformatlist_length;

            if (!PACKET_get_1(&subpkt, &ecpointformatlist_length)
                    || ecpointformatlist_length == 0)
                goto err;

            if (!s->hit) {
                OPENSSL_free(s->session->tlsext_ecpointformatlist);
                s->session->tlsext_ecpointformatlist = NULL;
                s->session->tlsext_ecpointformatlist_length = 0;
                if ((s->session->tlsext_ecpointformatlist =
                     OPENSSL_malloc(ecpointformatlist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ecpointformatlist_length =
                    ecpointformatlist_length;
                if (!PACKET_copy_bytes(&subpkt,
                        s->session->tlsext_ecpointformatlist,
                        ecpointformatlist_length))
                    goto err;
            } else if (!PACKET_forward(&subpkt, ecpointformatlist_length)) {
                goto err;
            }
            /* We should have consumed all the bytes by now */
            if (PACKET_remaining(&subpkt)) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
        } else if (type == TLSEXT_TYPE_elliptic_curves) {
            unsigned int ellipticcurvelist_length;

            /* Each NamedCurve is 2 bytes and we must have at least 1 */
            if (!PACKET_get_net_2(&subpkt, &ellipticcurvelist_length)
                    || ellipticcurvelist_length == 0
                    || (ellipticcurvelist_length & 1) != 0)
                goto err;

            if (!s->hit) {
                if (s->session->tlsext_ellipticcurvelist)
                    goto err;

                s->session->tlsext_ellipticcurvelist_length = 0;
                if ((s->session->tlsext_ellipticcurvelist =
                     OPENSSL_malloc(ellipticcurvelist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ellipticcurvelist_length =
                    ellipticcurvelist_length;
                if (!PACKET_copy_bytes(&subpkt,
                        s->session->tlsext_ellipticcurvelist,
                        ellipticcurvelist_length))
                    goto err;
            } else if (!PACKET_forward(&subpkt, ellipticcurvelist_length)) {
                goto err;
            }
            /* We should have consumed all the bytes by now */
            if (PACKET_remaining(&subpkt)) {
                goto err;
            }
        }
#endif                         /* OPENSSL_NO_EC */
        else if (type == TLSEXT_TYPE_session_ticket) {
            if (!PACKET_forward(&subpkt, size)
                || (s->tls_session_ticket_ext_cb &&
                    !s->tls_session_ticket_ext_cb(s, data, size,
                                        s->tls_session_ticket_ext_cb_arg))) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
        } else if (type == TLSEXT_TYPE_signature_algorithms) {
            unsigned int dsize;

            if (s->s3->tmp.peer_sigalgs
                    || !PACKET_get_net_2(&subpkt, &dsize)
                    || (dsize & 1) != 0
                    || (dsize == 0)
                    || !PACKET_get_bytes(&subpkt, &data, dsize)
                    || PACKET_remaining(&subpkt) != 0
                    || !tls1_save_sigalgs(s, data, dsize)) {
                goto err;
            }
        } else if (type == TLSEXT_TYPE_status_request) {
            PACKET ssubpkt;

            if (!PACKET_get_1(&subpkt,
                              (unsigned int *)&s->tlsext_status_type))
                goto err;

            if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
                const unsigned char *sdata;
                unsigned int dsize;
                /* Read in responder_id_list */
                if (!PACKET_get_net_2(&subpkt, &dsize)
                        || !PACKET_get_sub_packet(&subpkt, &ssubpkt, dsize))
                    goto err;

                while (PACKET_remaining(&ssubpkt)) {
                    OCSP_RESPID *id;
                    unsigned int idsize;

                    if (PACKET_remaining(&ssubpkt) < 4
                            || !PACKET_get_net_2(&ssubpkt, &idsize)
                            || !PACKET_get_bytes(&ssubpkt, &data, idsize)) {
                        goto err;
                    }
                    sdata = data;
                    data += idsize;
                    id = d2i_OCSP_RESPID(NULL, &sdata, idsize);
                    if (!id)
                        goto err;
                    if (data != sdata) {
                        OCSP_RESPID_free(id);
                        goto err;
                    }
                    if (!s->tlsext_ocsp_ids
                        && !(s->tlsext_ocsp_ids =
                             sk_OCSP_RESPID_new_null())) {
                        OCSP_RESPID_free(id);
                        *al = SSL_AD_INTERNAL_ERROR;
                        return 0;
                    }
                    if (!sk_OCSP_RESPID_push(s->tlsext_ocsp_ids, id)) {
                        OCSP_RESPID_free(id);
                        *al = SSL_AD_INTERNAL_ERROR;
                        return 0;
                    }
                }

                /* Read in request_extensions */
                if (!PACKET_get_net_2(&subpkt, &dsize)
                        || !PACKET_get_bytes(&subpkt, &data, dsize)
                        || PACKET_remaining(&subpkt)) {
                    goto err;
                }
                sdata = data;
                if (dsize > 0) {
                    sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts,
                                               X509_EXTENSION_free);
                    s->tlsext_ocsp_exts =
                        d2i_X509_EXTENSIONS(NULL, &sdata, dsize);
                    if (!s->tlsext_ocsp_exts || (data + dsize != sdata))
                        goto err;
                }
            }
            /*
             * We don't know what to do with any other type * so ignore it.
             */
            else
                s->tlsext_status_type = -1;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (type == TLSEXT_TYPE_heartbeat) {
            unsigned int hbtype;

            if (!PACKET_get_1(&subpkt, &hbtype)
                    || PACKET_remaining(&subpkt)) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            switch (hbtype) {
            case 0x01:         /* Client allows us to send HB requests */
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                break;
            case 0x02:         /* Client doesn't accept HB requests */
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
                break;
            default:
                *al = SSL_AD_ILLEGAL_PARAMETER;
                return 0;
            }
        }
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
        else if (type == TLSEXT_TYPE_next_proto_neg &&
                 s->s3->tmp.finish_md_len == 0 &&
                 s->s3->alpn_selected == NULL) {
            /*-
             * We shouldn't accept this extension on a
             * renegotiation.
             *
             * s->new_session will be set on renegotiation, but we
             * probably shouldn't rely that it couldn't be set on
             * the initial renegotation too in certain cases (when
             * there's some other reason to disallow resuming an
             * earlier session -- the current code won't be doing
             * anything like that, but this might change).
             *
             * A valid sign that there's been a previous handshake
             * in this connection is if s->s3->tmp.finish_md_len >
             * 0.  (We are talking about a check that will happen
             * in the Hello protocol round, well before a new
             * Finished message could have been computed.)
             */
            s->s3->next_proto_neg_seen = 1;
        }
#endif

        else if (type == TLSEXT_TYPE_application_layer_protocol_negotiation &&
                 s->ctx->alpn_select_cb && s->s3->tmp.finish_md_len == 0) {
            if (tls1_alpn_handle_client_hello(s, &subpkt, al) != 0)
                return 0;
#ifndef OPENSSL_NO_NEXTPROTONEG
            /* ALPN takes precedence over NPN. */
            s->s3->next_proto_neg_seen = 0;
#endif
        }

        /* session ticket processed earlier */
#ifndef OPENSSL_NO_SRTP
        else if (SSL_IS_DTLS(s) && SSL_get_srtp_profiles(s)
                 && type == TLSEXT_TYPE_use_srtp) {
            if (ssl_parse_clienthello_use_srtp_ext(s, &subpkt, al))
                return 0;
        }
#endif
#ifdef TLSEXT_TYPE_encrypt_then_mac
        else if (type == TLSEXT_TYPE_encrypt_then_mac)
            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;
#endif
        else if (type == TLSEXT_TYPE_extended_master_secret) {
            if (!s->hit)
                s->session->flags |= SSL_SESS_FLAG_EXTMS;
        }
        /*
         * If this ClientHello extension was unhandled and this is a
         * nonresumed connection, check whether the extension is a custom
         * TLS Extension (has a custom_srv_ext_record), and if so call the
         * callback and record the extension number so that an appropriate
         * ServerHello may be later returned.
         */
        else if (!s->hit) {
            if (custom_ext_parse(s, 1, type, data, size, al) <= 0)
                return 0;
        }
    }

    /* Spurious data on the end */
    if (PACKET_remaining(pkt) != 0)
        goto err;

 ri_check:

    /* Need RI if renegotiating */

    if (!renegotiate_seen && s->renegotiate &&
        !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    return 1;
err:
    *al = SSL_AD_DECODE_ERROR;
    return 0;
}

int ssl_parse_clienthello_tlsext(SSL *s, PACKET *pkt)
{
    int al = -1;
    custom_ext_init(&s->cert->srv_ext);
    if (ssl_scan_clienthello_tlsext(s, pkt, &al) <= 0) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return 0;
    }

    if (ssl_check_clienthello_tlsext_early(s) <= 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT, SSL_R_CLIENTHELLO_TLSEXT);
        return 0;
    }
    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly
 * fill the length of the block.
 */
static char ssl_next_proto_validate(PACKET *pkt)
{
    unsigned int len;

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_1(pkt, &len)
                || !PACKET_forward(pkt, len))
            return 0;
    }

    return 1;
}
#endif

static int ssl_scan_serverhello_tlsext(SSL *s, PACKET *pkt, int *al)
{
    unsigned int length, type, size;
    int tlsext_servername = 0;
    int renegotiate_seen = 0;

#ifndef OPENSSL_NO_NEXTPROTONEG
    s->s3->next_proto_neg_seen = 0;
#endif
    s->tlsext_ticket_expected = 0;

    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;
#ifndef OPENSSL_NO_HEARTBEATS
    s->tlsext_heartbeat &= ~(SSL_TLSEXT_HB_ENABLED |
                             SSL_TLSEXT_HB_DONT_SEND_REQUESTS);
#endif

#ifdef TLSEXT_TYPE_encrypt_then_mac
    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
#endif

    if (!PACKET_get_net_2(pkt, &length))
        goto ri_check;

    if (PACKET_remaining(pkt) != length) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    while (PACKET_get_net_2(pkt, &type) && PACKET_get_net_2(pkt, &size)) {
        unsigned char *data;
        PACKET spkt;

        if (!PACKET_get_sub_packet(pkt, &spkt, size)
                ||  !PACKET_peek_bytes(&spkt, &data, size))
            goto ri_check;

        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, 1, type, data, size, s->tlsext_debug_arg);

        if (type == TLSEXT_TYPE_renegotiate) {
            if (!ssl_parse_serverhello_renegotiate_ext(s, &spkt, al))
                return 0;
            renegotiate_seen = 1;
        } else if (s->version == SSL3_VERSION) {
        } else if (type == TLSEXT_TYPE_server_name) {
            if (s->tlsext_hostname == NULL || size > 0) {
                *al = TLS1_AD_UNRECOGNIZED_NAME;
                return 0;
            }
            tlsext_servername = 1;
        }
#ifndef OPENSSL_NO_EC
        else if (type == TLSEXT_TYPE_ec_point_formats) {
            unsigned int ecpointformatlist_length;
            if (!PACKET_get_1(&spkt, &ecpointformatlist_length)
                    || ecpointformatlist_length != size - 1) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (!s->hit) {
                s->session->tlsext_ecpointformatlist_length = 0;
                OPENSSL_free(s->session->tlsext_ecpointformatlist);
                if ((s->session->tlsext_ecpointformatlist =
                     OPENSSL_malloc(ecpointformatlist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ecpointformatlist_length =
                    ecpointformatlist_length;
                if (!PACKET_copy_bytes(&spkt,
                                       s->session->tlsext_ecpointformatlist,
                                       ecpointformatlist_length)) {
                    *al = TLS1_AD_DECODE_ERROR;
                    return 0;
                }

            }
        }
#endif                         /* OPENSSL_NO_EC */

        else if (type == TLSEXT_TYPE_session_ticket) {
            if (s->tls_session_ticket_ext_cb &&
                !s->tls_session_ticket_ext_cb(s, data, size,
                                              s->tls_session_ticket_ext_cb_arg))
            {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            if (!tls_use_ticket(s) || (size > 0)) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            s->tlsext_ticket_expected = 1;
        }
        else if (type == TLSEXT_TYPE_status_request) {
            /*
             * MUST be empty and only sent if we've requested a status
             * request message.
             */
            if ((s->tlsext_status_type == -1) || (size > 0)) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            /* Set flag to expect CertificateStatus message */
            s->tlsext_status_expected = 1;
        }
#ifndef OPENSSL_NO_NEXTPROTONEG
        else if (type == TLSEXT_TYPE_next_proto_neg &&
                 s->s3->tmp.finish_md_len == 0) {
            unsigned char *selected;
            unsigned char selected_len;
            /* We must have requested it. */
            if (s->ctx->next_proto_select_cb == NULL) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            /* The data must be valid */
            if (!ssl_next_proto_validate(&spkt)) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (s->
                ctx->next_proto_select_cb(s, &selected, &selected_len, data,
                                          size,
                                          s->ctx->next_proto_select_cb_arg) !=
                SSL_TLSEXT_ERR_OK) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            s->next_proto_negotiated = OPENSSL_malloc(selected_len);
            if (s->next_proto_negotiated == NULL) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            memcpy(s->next_proto_negotiated, selected, selected_len);
            s->next_proto_negotiated_len = selected_len;
            s->s3->next_proto_neg_seen = 1;
        }
#endif

        else if (type == TLSEXT_TYPE_application_layer_protocol_negotiation) {
            unsigned len;
            /* We must have requested it. */
            if (s->alpn_client_proto_list == NULL) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            /*-
             * The extension data consists of:
             *   uint16 list_length
             *   uint8 proto_length;
             *   uint8 proto[proto_length];
             */
            if (!PACKET_get_net_2(&spkt, &len)
                    || PACKET_remaining(&spkt) != len
                    || !PACKET_get_1(&spkt, &len)
                    || PACKET_remaining(&spkt) != len) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            OPENSSL_free(s->s3->alpn_selected);
            s->s3->alpn_selected = OPENSSL_malloc(len);
            if (s->s3->alpn_selected == NULL) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            if (!PACKET_copy_bytes(&spkt, s->s3->alpn_selected, len)) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            s->s3->alpn_selected_len = len;
        }
#ifndef OPENSSL_NO_HEARTBEATS
        else if (type == TLSEXT_TYPE_heartbeat) {
            unsigned int hbtype;
            if (!PACKET_get_1(&spkt, &hbtype)) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            switch (hbtype) {
            case 0x01:         /* Server allows us to send HB requests */
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                break;
            case 0x02:         /* Server doesn't accept HB requests */
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
                break;
            default:
                *al = SSL_AD_ILLEGAL_PARAMETER;
                return 0;
            }
        }
#endif
#ifndef OPENSSL_NO_SRTP
        else if (SSL_IS_DTLS(s) && type == TLSEXT_TYPE_use_srtp) {
            if (ssl_parse_serverhello_use_srtp_ext(s, &spkt, al))
                return 0;
        }
#endif
#ifdef TLSEXT_TYPE_encrypt_then_mac
        else if (type == TLSEXT_TYPE_encrypt_then_mac) {
            /* Ignore if inappropriate ciphersuite */
            if (s->s3->tmp.new_cipher->algorithm_mac != SSL_AEAD
                && s->s3->tmp.new_cipher->algorithm_enc != SSL_RC4)
                s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;
        }
#endif
        else if (type == TLSEXT_TYPE_extended_master_secret) {
            if (!s->hit)
                s->session->flags |= SSL_SESS_FLAG_EXTMS;
        }
        /*
         * If this extension type was not otherwise handled, but matches a
         * custom_cli_ext_record, then send it to the c callback
         */
        else if (custom_ext_parse(s, 0, type, data, size, al) <= 0)
            return 0;
    }

    if (PACKET_remaining(pkt) != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit && tlsext_servername == 1) {
        if (s->tlsext_hostname) {
            if (s->session->tlsext_hostname == NULL) {
                s->session->tlsext_hostname = BUF_strdup(s->tlsext_hostname);
                if (!s->session->tlsext_hostname) {
                    *al = SSL_AD_UNRECOGNIZED_NAME;
                    return 0;
                }
            } else {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
        }
    }

 ri_check:

    /*
     * Determine if we need to see RI. Strictly speaking if we want to avoid
     * an attack we should *always* see RI even on initial server hello
     * because the client doesn't see any renegotiation during an attack.
     * However this would mean we could not connect to any server which
     * doesn't support RI so for the immediate future tolerate RI absence on
     * initial connect only.
     */
    if (!renegotiate_seen && !(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
        && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    return 1;
}

int ssl_prepare_clienthello_tlsext(SSL *s)
{

    return 1;
}

int ssl_prepare_serverhello_tlsext(SSL *s)
{
    return 1;
}

static int ssl_check_clienthello_tlsext_early(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int al = SSL_AD_UNRECOGNIZED_NAME;

#ifndef OPENSSL_NO_EC
    /*
     * The handling of the ECPointFormats extension is done elsewhere, namely
     * in ssl3_choose_cipher in s3_lib.c.
     */
    /*
     * The handling of the EllipticCurves extension is done elsewhere, namely
     * in ssl3_choose_cipher in s3_lib.c.
     */
#endif

    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret =
            s->ctx->tlsext_servername_callback(s, &al,
                                               s->ctx->tlsext_servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->tlsext_servername_callback != 0)
        ret =
            s->initial_ctx->tlsext_servername_callback(s, &al,
                                                       s->
                                                       initial_ctx->tlsext_servername_arg);

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
    default:
        return 1;
    }
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
    /* Clear any shared sigtnature algorithms */
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
                   SSL_R_NO_SHARED_SIGATURE_ALGORITHMS);
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

int ssl_check_clienthello_tlsext_late(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_OK;
    int al = SSL_AD_INTERNAL_ERROR;

    /*
     * If status request then ask callback what to do. Note: this must be
     * called after servername callbacks in case the certificate has changed,
     * and must be called after the cipher has been chosen because this may
     * influence which certificate is sent
     */
    if ((s->tlsext_status_type != -1) && s->ctx && s->ctx->tlsext_status_cb) {
        int r;
        CERT_PKEY *certpkey;
        certpkey = ssl_get_server_send_pkey(s);
        /* If no certificate can't return certificate status */
        if (certpkey == NULL) {
            s->tlsext_status_expected = 0;
            return 1;
        }
        /*
         * Set current certificate to one we will use so SSL_get_certificate
         * et al can pick it up.
         */
        s->cert->key = certpkey;
        r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        switch (r) {
            /* We don't want to send a status request response */
        case SSL_TLSEXT_ERR_NOACK:
            s->tlsext_status_expected = 0;
            break;
            /* status request response should be sent */
        case SSL_TLSEXT_ERR_OK:
            if (s->tlsext_ocsp_resp)
                s->tlsext_status_expected = 1;
            else
                s->tlsext_status_expected = 0;
            break;
            /* something bad happened */
        case SSL_TLSEXT_ERR_ALERT_FATAL:
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
            al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
    } else
        s->tlsext_status_expected = 0;

 err:
    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    default:
        return 1;
    }
}

int ssl_check_serverhello_tlsext(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int al = SSL_AD_UNRECOGNIZED_NAME;

#ifndef OPENSSL_NO_EC
    /*
     * If we are client and using an elliptic curve cryptography cipher
     * suite, then if server returns an EC point formats lists extension it
     * must contain uncompressed.
     */
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    if ((s->tlsext_ecpointformatlist != NULL)
        && (s->tlsext_ecpointformatlist_length > 0)
        && (s->session->tlsext_ecpointformatlist != NULL)
        && (s->session->tlsext_ecpointformatlist_length > 0)
        && ((alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe))
            || (alg_a & SSL_aECDSA))) {
        /* we are using an ECC cipher */
        size_t i;
        unsigned char *list;
        int found_uncompressed = 0;
        list = s->session->tlsext_ecpointformatlist;
        for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++) {
            if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed) {
                found_uncompressed = 1;
                break;
            }
        }
        if (!found_uncompressed) {
            SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT,
                   SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
            return -1;
        }
    }
    ret = SSL_TLSEXT_ERR_OK;
#endif                         /* OPENSSL_NO_EC */

    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret =
            s->ctx->tlsext_servername_callback(s, &al,
                                               s->ctx->tlsext_servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->tlsext_servername_callback != 0)
        ret =
            s->initial_ctx->tlsext_servername_callback(s, &al,
                                                       s->
                                                       initial_ctx->tlsext_servername_arg);

    /*
     * If we've requested certificate status and we wont get one tell the
     * callback
     */
    if ((s->tlsext_status_type != -1) && !(s->tlsext_status_expected)
        && s->ctx && s->ctx->tlsext_status_cb) {
        int r;
        /*
         * Set resp to NULL, resplen to -1 so callback knows there is no
         * response.
         */
        OPENSSL_free(s->tlsext_ocsp_resp);
        s->tlsext_ocsp_resp = NULL;
        s->tlsext_ocsp_resplen = -1;
        r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        if (r == 0) {
            al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        if (r < 0) {
            al = SSL_AD_INTERNAL_ERROR;
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
    default:
        return 1;
    }
}

int ssl_parse_serverhello_tlsext(SSL *s, PACKET *pkt)
{
    int al = -1;
    if (s->version < SSL3_VERSION)
        return 1;
    if (ssl_scan_serverhello_tlsext(s, pkt, &al) <= 0) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return 0;
    }

    if (ssl_check_serverhello_tlsext(s) <= 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT, SSL_R_SERVERHELLO_TLSEXT);
        return 0;
    }
    return 1;
}

/*-
 * Since the server cache lookup is done early on in the processing of the
 * ClientHello, and other operations depend on the result, we need to handle
 * any TLS session ticket extension at the same time.
 *
 *   session_id: ClientHello session ID.
 *   ext: ClientHello extensions (including length prefix)
 *   ret: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * If s->tls_session_secret_cb is set then we are expecting a pre-shared key
 * ciphersuite, in which case we have no use for session tickets and one will
 * never be decrypted, nor will s->tlsext_ticket_expected be set to 1.
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
 *   Sets s->tlsext_ticket_expected to 1 if the server will have to issue
 *   a new session ticket to the client because the client indicated support
 *   (and s->tls_session_secret_cb is NULL) but the client either doesn't have
 *   a session ticket or we couldn't use the one it gave us, or if
 *   s->ctx->tlsext_ticket_key_cb asked to renew the client's ticket.
 *   Otherwise, s->tlsext_ticket_expected is set to 0.
 */
int tls1_process_ticket(SSL *s, const PACKET *ext, const PACKET *session_id,
                        SSL_SESSION **ret)
{
    unsigned int i;
    PACKET local_ext = *ext;
    int retv = -1;

    *ret = NULL;
    s->tlsext_ticket_expected = 0;

    /*
     * If tickets disabled behave as if no ticket present to permit stateful
     * resumption.
     */
    if (!tls_use_ticket(s))
        return 0;
    if ((s->version <= SSL3_VERSION))
        return 0;

    if (!PACKET_get_net_2(&local_ext, &i)) {
        retv = 0;
        goto end;
    }
    while (PACKET_remaining(&local_ext) >= 4) {
        unsigned int type, size;

        if (!PACKET_get_net_2(&local_ext, &type)
                || !PACKET_get_net_2(&local_ext, &size)) {
            /* Shouldn't ever happen */
            retv = -1;
            goto end;
        }
        if (PACKET_remaining(&local_ext) < size) {
            retv = 0;
            goto end;
        }
        if (type == TLSEXT_TYPE_session_ticket) {
            int r;
            unsigned char *etick;

            if (size == 0) {
                /*
                 * The client will accept a ticket but doesn't currently have
                 * one.
                 */
                s->tlsext_ticket_expected = 1;
                retv = 1;
                goto end;
            }
            if (s->tls_session_secret_cb) {
                /*
                 * Indicate that the ticket couldn't be decrypted rather than
                 * generating the session from ticket now, trigger
                 * abbreviated handshake based on external mechanism to
                 * calculate the master secret later.
                 */
                retv = 2;
                goto end;
            }
            if (!PACKET_get_bytes(&local_ext, &etick, size)) {
                /* Shouldn't ever happen */
                retv = -1;
                goto end;
            }
            r = tls_decrypt_ticket(s, etick, size, PACKET_data(session_id),
                                   PACKET_remaining(session_id), ret);
            switch (r) {
            case 2:            /* ticket couldn't be decrypted */
                s->tlsext_ticket_expected = 1;
                retv = 2;
                break;
            case 3:            /* ticket was decrypted */
                retv = r;
                break;
            case 4:            /* ticket decrypted but need to renew */
                s->tlsext_ticket_expected = 1;
                retv = 3;
                break;
            default:           /* fatal error */
                retv = -1;
                break;
            }
            goto end;
        } else {
            if (!PACKET_forward(&local_ext, size)) {
                retv = -1;
                goto end;
            }
        }
    }
    retv = 0;
end:
    return retv;
}

/*-
 * tls_decrypt_ticket attempts to decrypt a session ticket.
 *
 *   etick: points to the body of the session ticket extension.
 *   eticklen: the length of the session tickets extenion.
 *   sess_id: points at the session ID.
 *   sesslen: the length of the session ID.
 *   psess: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * Returns:
 *   -1: fatal error, either from parsing or decrypting the ticket.
 *    2: the ticket couldn't be decrypted.
 *    3: a ticket was successfully decrypted and *psess was set.
 *    4: same as 3, but the ticket needs to be renewed.
 */
static int tls_decrypt_ticket(SSL *s, const unsigned char *etick,
                              int eticklen, const unsigned char *sess_id,
                              int sesslen, SSL_SESSION **psess)
{
    SSL_SESSION *sess;
    unsigned char *sdec;
    const unsigned char *p;
    int slen, mlen, renew_ticket = 0;
    unsigned char tick_hmac[EVP_MAX_MD_SIZE];
    HMAC_CTX hctx;
    EVP_CIPHER_CTX ctx;
    SSL_CTX *tctx = s->initial_ctx;
    /* Need at least keyname + iv + some encrypted data */
    if (eticklen < 48)
        return 2;
    /* Initialize session ticket encryption and HMAC contexts */
    HMAC_CTX_init(&hctx);
    EVP_CIPHER_CTX_init(&ctx);
    if (tctx->tlsext_ticket_key_cb) {
        unsigned char *nctick = (unsigned char *)etick;
        int rv = tctx->tlsext_ticket_key_cb(s, nctick, nctick + 16,
                                            &ctx, &hctx, 0);
        if (rv < 0)
            return -1;
        if (rv == 0)
            return 2;
        if (rv == 2)
            renew_ticket = 1;
    } else {
        /* Check key name matches */
        if (memcmp(etick, tctx->tlsext_tick_key_name, 16))
            return 2;
        if (HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16,
                         EVP_sha256(), NULL) <= 0
                || EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
                                      tctx->tlsext_tick_aes_key,
                                      etick + 16) <= 0) {
            goto err;
       }
    }
    /*
     * Attempt to process session ticket, first conduct sanity and integrity
     * checks on ticket.
     */
    mlen = HMAC_size(&hctx);
    if (mlen < 0) {
        goto err;
    }
    eticklen -= mlen;
    /* Check HMAC of encrypted ticket */
    if (HMAC_Update(&hctx, etick, eticklen) <= 0
            || HMAC_Final(&hctx, tick_hmac, NULL) <= 0) {
        goto err;
    }
    HMAC_CTX_cleanup(&hctx);
    if (CRYPTO_memcmp(tick_hmac, etick + eticklen, mlen)) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 2;
    }
    /* Attempt to decrypt session data */
    /* Move p after IV to start of encrypted ticket, update length */
    p = etick + 16 + EVP_CIPHER_CTX_iv_length(&ctx);
    eticklen -= 16 + EVP_CIPHER_CTX_iv_length(&ctx);
    sdec = OPENSSL_malloc(eticklen);
    if (sdec == NULL
            || EVP_DecryptUpdate(&ctx, sdec, &slen, p, eticklen) <= 0) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    if (EVP_DecryptFinal(&ctx, sdec + slen, &mlen) <= 0) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        OPENSSL_free(sdec);
        return 2;
    }
    slen += mlen;
    EVP_CIPHER_CTX_cleanup(&ctx);
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
    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hctx);
    return -1;
}

/* Tables to translate from NIDs to TLS v1.2 ids */

typedef struct {
    int nid;
    int id;
} tls12_lookup;

static const tls12_lookup tls12_md[] = {
    {NID_md5, TLSEXT_hash_md5},
    {NID_sha1, TLSEXT_hash_sha1},
    {NID_sha224, TLSEXT_hash_sha224},
    {NID_sha256, TLSEXT_hash_sha256},
    {NID_sha384, TLSEXT_hash_sha384},
    {NID_sha512, TLSEXT_hash_sha512},
    {NID_id_GostR3411_94, TLSEXT_hash_gostr3411},
    {NID_id_GostR3411_2012_256, TLSEXT_hash_gostr34112012_256},
    {NID_id_GostR3411_2012_512, TLSEXT_hash_gostr34112012_512},
};

static const tls12_lookup tls12_sig[] = {
    {EVP_PKEY_RSA, TLSEXT_signature_rsa},
    {EVP_PKEY_DSA, TLSEXT_signature_dsa},
    {EVP_PKEY_EC, TLSEXT_signature_ecdsa},
    {NID_id_GostR3410_2001, TLSEXT_signature_gostr34102001},
    {NID_id_GostR3410_2012_256, TLSEXT_signature_gostr34102012_256},
    {NID_id_GostR3410_2012_512, TLSEXT_signature_gostr34102012_512}
};

static int tls12_find_id(int nid, const tls12_lookup *table, size_t tlen)
{
    size_t i;
    for (i = 0; i < tlen; i++) {
        if (table[i].nid == nid)
            return table[i].id;
    }
    return -1;
}

static int tls12_find_nid(int id, const tls12_lookup *table, size_t tlen)
{
    size_t i;
    for (i = 0; i < tlen; i++) {
        if ((table[i].id) == id)
            return table[i].nid;
    }
    return NID_undef;
}

int tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk,
                         const EVP_MD *md)
{
    int sig_id, md_id;
    if (!md)
        return 0;
    md_id = tls12_find_id(EVP_MD_type(md), tls12_md, OSSL_NELEM(tls12_md));
    if (md_id == -1)
        return 0;
    sig_id = tls12_get_sigid(pk);
    if (sig_id == -1)
        return 0;
    p[0] = (unsigned char)md_id;
    p[1] = (unsigned char)sig_id;
    return 1;
}

int tls12_get_sigid(const EVP_PKEY *pk)
{
    return tls12_find_id(pk->type, tls12_sig, OSSL_NELEM(tls12_sig));
}

typedef struct {
    int nid;
    int secbits;
    int md_idx;
    unsigned char tlsext_hash;
} tls12_hash_info;

static const tls12_hash_info tls12_md_info[] = {
    {NID_md5, 64, SSL_MD_MD5_IDX, TLSEXT_hash_md5},
    {NID_sha1, 80, SSL_MD_SHA1_IDX, TLSEXT_hash_sha1},
    {NID_sha224, 112, SSL_MD_SHA224_IDX, TLSEXT_hash_sha224},
    {NID_sha256, 128, SSL_MD_SHA256_IDX, TLSEXT_hash_sha256},
    {NID_sha384, 192, SSL_MD_SHA384_IDX, TLSEXT_hash_sha384},
    {NID_sha512, 256, SSL_MD_SHA512_IDX, TLSEXT_hash_sha512},
    {NID_id_GostR3411_94,       128, SSL_MD_GOST94_IDX, TLSEXT_hash_gostr3411},
    {NID_id_GostR3411_2012_256, 128, SSL_MD_GOST12_256_IDX, TLSEXT_hash_gostr34112012_256},
    {NID_id_GostR3411_2012_512, 256, SSL_MD_GOST12_512_IDX, TLSEXT_hash_gostr34112012_512},
};

static const tls12_hash_info *tls12_get_hash_info(unsigned char hash_alg)
{
    unsigned int i;
    if (hash_alg == 0)
        return NULL;

    for (i=0; i < OSSL_NELEM(tls12_md_info); i++)
    {
        if (tls12_md_info[i].tlsext_hash == hash_alg)
            return tls12_md_info + i;
    }

    return NULL;
}

const EVP_MD *tls12_get_hash(unsigned char hash_alg)
{
    const tls12_hash_info *inf;
    if (hash_alg == TLSEXT_hash_md5 && FIPS_mode())
        return NULL;
    inf = tls12_get_hash_info(hash_alg);
    if (!inf)
        return NULL;
    return ssl_md(inf->md_idx);
}

static int tls12_get_pkey_idx(unsigned char sig_alg)
{
    switch (sig_alg) {
#ifndef OPENSSL_NO_RSA
    case TLSEXT_signature_rsa:
        return SSL_PKEY_RSA_SIGN;
#endif
#ifndef OPENSSL_NO_DSA
    case TLSEXT_signature_dsa:
        return SSL_PKEY_DSA_SIGN;
#endif
#ifndef OPENSSL_NO_EC
    case TLSEXT_signature_ecdsa:
        return SSL_PKEY_ECC;
#endif
# ifndef OPENSSL_NO_GOST
    case TLSEXT_signature_gostr34102001:
        return SSL_PKEY_GOST01;

    case TLSEXT_signature_gostr34102012_256:
        return SSL_PKEY_GOST12_256;

    case TLSEXT_signature_gostr34102012_512:
        return SSL_PKEY_GOST12_512;
# endif
    }
    return -1;
}

/* Convert TLS 1.2 signature algorithm extension values into NIDs */
static void tls1_lookup_sigalg(int *phash_nid, int *psign_nid,
                               int *psignhash_nid, const unsigned char *data)
{
    int sign_nid = 0, hash_nid = 0;
    if (!phash_nid && !psign_nid && !psignhash_nid)
        return;
    if (phash_nid || psignhash_nid) {
        hash_nid = tls12_find_nid(data[0], tls12_md, OSSL_NELEM(tls12_md));
        if (phash_nid)
            *phash_nid = hash_nid;
    }
    if (psign_nid || psignhash_nid) {
        sign_nid = tls12_find_nid(data[1], tls12_sig, OSSL_NELEM(tls12_sig));
        if (psign_nid)
            *psign_nid = sign_nid;
    }
    if (psignhash_nid) {
        if (sign_nid && hash_nid)
            OBJ_find_sigid_by_algs(psignhash_nid, hash_nid, sign_nid);
        else
            *psignhash_nid = NID_undef;
    }
}

/* Check to see if a signature algorithm is allowed */
static int tls12_sigalg_allowed(SSL *s, int op, const unsigned char *ptmp)
{
    /* See if we have an entry in the hash table and it is enabled */
    const tls12_hash_info *hinf = tls12_get_hash_info(ptmp[0]);
    if (hinf == NULL || ssl_md(hinf->md_idx) == NULL)
        return 0;
    /* See if public key algorithm allowed */
    if (tls12_get_pkey_idx(ptmp[1]) == -1)
        return 0;
    /* Finally see if security callback allows it */
    return ssl_security(s, op, hinf->secbits, hinf->nid, (void *)ptmp);
}

/*
 * Get a mask of disabled public key algorithms based on supported signature
 * algorithms. For example if no signature algorithm supports RSA then RSA is
 * disabled.
 */

void ssl_set_sig_mask(uint32_t *pmask_a, SSL *s, int op)
{
    const unsigned char *sigalgs;
    size_t i, sigalgslen;
    int have_rsa = 0, have_dsa = 0, have_ecdsa = 0;
    /*
     * Now go through all signature algorithms seeing if we support any for
     * RSA, DSA, ECDSA. Do this for all versions not just TLS 1.2. To keep
     * down calls to security callback only check if we have to.
     */
    sigalgslen = tls12_get_psigalgs(s, &sigalgs);
    for (i = 0; i < sigalgslen; i += 2, sigalgs += 2) {
        switch (sigalgs[1]) {
#ifndef OPENSSL_NO_RSA
        case TLSEXT_signature_rsa:
            if (!have_rsa && tls12_sigalg_allowed(s, op, sigalgs))
                have_rsa = 1;
            break;
#endif
#ifndef OPENSSL_NO_DSA
        case TLSEXT_signature_dsa:
            if (!have_dsa && tls12_sigalg_allowed(s, op, sigalgs))
                have_dsa = 1;
            break;
#endif
#ifndef OPENSSL_NO_EC
        case TLSEXT_signature_ecdsa:
            if (!have_ecdsa && tls12_sigalg_allowed(s, op, sigalgs))
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

size_t tls12_copy_sigalgs(SSL *s, unsigned char *out,
                          const unsigned char *psig, size_t psiglen)
{
    unsigned char *tmpout = out;
    size_t i;
    for (i = 0; i < psiglen; i += 2, psig += 2) {
        if (tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SUPPORTED, psig)) {
            *tmpout++ = psig[0];
            *tmpout++ = psig[1];
        }
    }
    return tmpout - out;
}

/* Given preference and allowed sigalgs set shared sigalgs */
static int tls12_shared_sigalgs(SSL *s, TLS_SIGALGS *shsig,
                                const unsigned char *pref, size_t preflen,
                                const unsigned char *allow, size_t allowlen)
{
    const unsigned char *ptmp, *atmp;
    size_t i, j, nmatch = 0;
    for (i = 0, ptmp = pref; i < preflen; i += 2, ptmp += 2) {
        /* Skip disabled hashes or signature algorithms */
        if (!tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SHARED, ptmp))
            continue;
        for (j = 0, atmp = allow; j < allowlen; j += 2, atmp += 2) {
            if (ptmp[0] == atmp[0] && ptmp[1] == atmp[1]) {
                nmatch++;
                if (shsig) {
                    shsig->rhash = ptmp[0];
                    shsig->rsign = ptmp[1];
                    tls1_lookup_sigalg(&shsig->hash_nid,
                                       &shsig->sign_nid,
                                       &shsig->signandhash_nid, ptmp);
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
    const unsigned char *pref, *allow, *conf;
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
        conflen = tls12_get_psigalgs(s, &conf);
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

int tls1_save_sigalgs(SSL *s, const unsigned char *data, int dsize)
{
    CERT *c = s->cert;
    /* Extension ignored for inappropriate versions */
    if (!SSL_USE_SIGALGS(s))
        return 1;
    /* Should never happen */
    if (!c)
        return 0;

    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = OPENSSL_malloc(dsize);
    if (s->s3->tmp.peer_sigalgs == NULL)
        return 0;
    s->s3->tmp.peer_sigalgslen = dsize;
    memcpy(s->s3->tmp.peer_sigalgs, data, dsize);
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

#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL) {
        /*
         * Use first set signature preference to force message digest,
         * ignoring any peer preferences.
         */
        const unsigned char *sigs = NULL;
        if (s->server)
            sigs = c->conf_sigalgs;
        else
            sigs = c->client_sigalgs;
        if (sigs) {
            idx = tls12_get_pkey_idx(sigs[1]);
            md = tls12_get_hash(sigs[0]);
            pmd[idx] = md;
            pvalid[idx] = CERT_PKEY_EXPLICIT_SIGN;
            if (idx == SSL_PKEY_RSA_SIGN) {
                pvalid[SSL_PKEY_RSA_ENC] = CERT_PKEY_EXPLICIT_SIGN;
                pmd[SSL_PKEY_RSA_ENC] = md;
            }
        }
    }
#endif

    for (i = 0, sigptr = c->shared_sigalgs;
         i < c->shared_sigalgslen; i++, sigptr++) {
        idx = tls12_get_pkey_idx(sigptr->rsign);
        if (idx > 0 && pmd[idx] == NULL) {
            md = tls12_get_hash(sigptr->rhash);
            pmd[idx] = md;
            pvalid[idx] = CERT_PKEY_EXPLICIT_SIGN;
            if (idx == SSL_PKEY_RSA_SIGN) {
                pvalid[SSL_PKEY_RSA_ENC] = CERT_PKEY_EXPLICIT_SIGN;
                pmd[SSL_PKEY_RSA_ENC] = md;
            }
        }

    }
    /*
     * In strict mode leave unset digests as NULL to indicate we can't use
     * the certificate for signing.
     */
    if (!(s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)) {
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
# ifndef OPENSSL_NO_GOST
        if (pmd[SSL_PKEY_GOST01] == NULL)
            pmd[SSL_PKEY_GOST01] = EVP_get_digestbynid(NID_id_GostR3411_94);
        if (pmd[SSL_PKEY_GOST12_256] == NULL)
            pmd[SSL_PKEY_GOST12_256] = EVP_get_digestbynid(NID_id_GostR3411_2012_256);
        if (pmd[SSL_PKEY_GOST12_512] == NULL)
            pmd[SSL_PKEY_GOST12_512] = EVP_get_digestbynid(NID_id_GostR3411_2012_512);
# endif
    }
    return 1;
}

int SSL_get_sigalgs(SSL *s, int idx,
                    int *psign, int *phash, int *psignhash,
                    unsigned char *rsig, unsigned char *rhash)
{
    const unsigned char *psig = s->s3->tmp.peer_sigalgs;
    if (psig == NULL)
        return 0;
    if (idx >= 0) {
        idx <<= 1;
        if (idx >= (int)s->s3->tmp.peer_sigalgslen)
            return 0;
        psig += idx;
        if (rhash)
            *rhash = psig[0];
        if (rsig)
            *rsig = psig[1];
        tls1_lookup_sigalg(phash, psign, psignhash, psig);
    }
    return s->s3->tmp.peer_sigalgslen / 2;
}

int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignhash,
                           unsigned char *rsig, unsigned char *rhash)
{
    TLS_SIGALGS *shsigalgs = s->cert->shared_sigalgs;
    if (!shsigalgs || idx >= (int)s->cert->shared_sigalgslen)
        return 0;
    shsigalgs += idx;
    if (phash)
        *phash = shsigalgs->hash_nid;
    if (psign)
        *psign = shsigalgs->sign_nid;
    if (psignhash)
        *psignhash = shsigalgs->signandhash_nid;
    if (rsig)
        *rsig = shsigalgs->rsign;
    if (rhash)
        *rhash = shsigalgs->rhash;
    return s->cert->shared_sigalgslen;
}

#ifndef OPENSSL_NO_HEARTBEATS
int tls1_process_heartbeat(SSL *s, unsigned char *p, unsigned int length)
{
    unsigned char *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;  /* Use minimum padding */

    if (s->msg_callback)
        s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
                        p, length,
                        s, s->msg_callback_arg);

    /* Read type and payload length first */
    if (1 + 2 + 16 > length)
        return 0;               /* silently discard */
    hbtype = *p++;
    n2s(p, payload);
    if (1 + 2 + payload + 16 > length)
        return 0;               /* silently discard per RFC 6520 sec. 4 */
    pl = p;

    if (hbtype == TLS1_HB_REQUEST) {
        unsigned char *buffer, *bp;
        int r;

        /*
         * Allocate memory for the response, size is 1 bytes message type,
         * plus 2 bytes payload length, plus payload, plus padding
         */
        buffer = OPENSSL_malloc(1 + 2 + payload + padding);
        if (buffer == NULL) {
            SSLerr(SSL_F_TLS1_PROCESS_HEARTBEAT, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        bp = buffer;

        /* Enter response type, length and copy payload */
        *bp++ = TLS1_HB_RESPONSE;
        s2n(payload, bp);
        memcpy(bp, pl, payload);
        bp += payload;
        /* Random padding */
        if (RAND_bytes(bp, padding) <= 0) {
            OPENSSL_free(buffer);
            return -1;
        }

        r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer,
                             3 + payload + padding);

        if (r >= 0 && s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
                            buffer, 3 + payload + padding,
                            s, s->msg_callback_arg);

        OPENSSL_free(buffer);

        if (r < 0)
            return r;
    } else if (hbtype == TLS1_HB_RESPONSE) {
        unsigned int seq;

        /*
         * We only send sequence numbers (2 bytes unsigned int), and 16
         * random bytes, so we just try to read the sequence number
         */
        n2s(pl, seq);

        if (payload == 18 && seq == s->tlsext_hb_seq) {
            s->tlsext_hb_seq++;
            s->tlsext_hb_pending = 0;
        }
    }

    return 0;
}

int tls1_heartbeat(SSL *s)
{
    unsigned char *buf, *p;
    int ret = -1;
    unsigned int payload = 18;  /* Sequence number + random bytes */
    unsigned int padding = 16;  /* Use minimum padding */

    /* Only send if peer supports and accepts HB requests... */
    if (!(s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) ||
        s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT);
        return -1;
    }

    /* ...and there is none in flight yet... */
    if (s->tlsext_hb_pending) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PENDING);
        return -1;
    }

    /* ...and no handshake in progress. */
    if (SSL_in_init(s) || ossl_statem_get_in_handshake(s)) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_UNEXPECTED_MESSAGE);
        return -1;
    }

    /*-
     * Create HeartBeat message, we just use a sequence number
     * as payload to distuingish different messages and add
     * some random stuff.
     *  - Message Type, 1 byte
     *  - Payload Length, 2 bytes (unsigned int)
     *  - Payload, the sequence number (2 bytes uint)
     *  - Payload, random bytes (16 bytes uint)
     *  - Padding
     */
    buf = OPENSSL_malloc(1 + 2 + payload + padding);
    if (buf == NULL) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    p = buf;
    /* Message Type */
    *p++ = TLS1_HB_REQUEST;
    /* Payload length (18 bytes here) */
    s2n(payload, p);
    /* Sequence number */
    s2n(s->tlsext_hb_seq, p);
    /* 16 random bytes */
    if (RAND_bytes(p, 16) <= 0) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    p += 16;
    /* Random padding */
    if (RAND_bytes(p, padding) <= 0) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding);
    if (ret >= 0) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
                            buf, 3 + payload + padding,
                            s, s->msg_callback_arg);

        s->tlsext_hb_pending = 1;
    }

 err:
    OPENSSL_free(buf);
    return ret;
}
#endif

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
 * Set suppored signature algorithms based on a colon separated list of the
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

int tls1_set_sigalgs(CERT *c, const int *psig_nids, size_t salglen,
                     int client)
{
    unsigned char *sigalgs, *sptr;
    int rhash, rsign;
    size_t i;
    if (salglen & 1)
        return 0;
    sigalgs = OPENSSL_malloc(salglen);
    if (sigalgs == NULL)
        return 0;
    for (i = 0, sptr = sigalgs; i < salglen; i += 2) {
        rhash = tls12_find_id(*psig_nids++, tls12_md, OSSL_NELEM(tls12_md));
        rsign = tls12_find_id(*psig_nids++, tls12_sig, OSSL_NELEM(tls12_sig));

        if (rhash == -1 || rsign == -1)
            goto err;
        *sptr++ = rhash;
        *sptr++ = rsign;
    }

    if (client) {
        OPENSSL_free(c->client_sigalgs);
        c->client_sigalgs = sigalgs;
        c->client_sigalgslen = salglen;
    } else {
        OPENSSL_free(c->conf_sigalgs);
        c->conf_sigalgs = sigalgs;
        c->conf_sigalgslen = salglen;
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
            idx = cpk - c->pkeys;
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
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        /* Allow any certificate to pass test */
        if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL) {
            rv = CERT_PKEY_STRICT_FLAGS | CERT_PKEY_EXPLICIT_SIGN |
                CERT_PKEY_VALID | CERT_PKEY_SIGN;
            *pvalid = rv;
            return rv;
        }
#endif
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
        unsigned char rsign = 0;
        if (s->s3->tmp.peer_sigalgs)
            default_nid = 0;
        /* If no sigalgs extension use defaults from RFC5246 */
        else {
            switch (idx) {
            case SSL_PKEY_RSA_ENC:
            case SSL_PKEY_RSA_SIGN:
            case SSL_PKEY_DH_RSA:
                rsign = TLSEXT_signature_rsa;
                default_nid = NID_sha1WithRSAEncryption;
                break;

            case SSL_PKEY_DSA_SIGN:
            case SSL_PKEY_DH_DSA:
                rsign = TLSEXT_signature_dsa;
                default_nid = NID_dsaWithSHA1;
                break;

            case SSL_PKEY_ECC:
                rsign = TLSEXT_signature_ecdsa;
                default_nid = NID_ecdsa_with_SHA1;
                break;

            case SSL_PKEY_GOST01:
                rsign = TLSEXT_signature_gostr34102001;
                default_nid = NID_id_GostR3411_94_with_GostR3410_2001;
                break;

            case SSL_PKEY_GOST12_256:
                rsign = TLSEXT_signature_gostr34102012_256;
                default_nid = NID_id_tc26_signwithdigest_gost3410_2012_256;
                break;

            case SSL_PKEY_GOST12_512:
                rsign = TLSEXT_signature_gostr34102012_512;
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
            const unsigned char *p = c->conf_sigalgs;
            for (j = 0; j < c->conf_sigalgslen; j += 2, p += 2) {
                if (p[0] == TLSEXT_hash_sha1 && p[1] == rsign)
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
        switch (pk->type) {
        case EVP_PKEY_RSA:
            check_type = TLS_CT_RSA_SIGN;
            break;
        case EVP_PKEY_DSA:
            check_type = TLS_CT_DSS_SIGN;
            break;
        case EVP_PKEY_EC:
            check_type = TLS_CT_ECDSA_SIGN;
            break;
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            {
                int cert_type = X509_certificate_type(x, pk);
                if (cert_type & EVP_PKS_RSA)
                    check_type = TLS_CT_RSA_FIXED_DH;
                if (cert_type & EVP_PKS_DSA)
                    check_type = TLS_CT_DSS_FIXED_DH;
            }
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
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DH_RSA);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DH_DSA);
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
        if (dhp == NULL)
            return NULL;
        dhp->g = BN_new();
        if (dhp->g != NULL)
            BN_set_word(dhp->g, 2);
        if (dh_secbits >= 192)
            dhp->p = get_rfc3526_prime_8192(NULL);
        else
            dhp->p = get_rfc3526_prime_3072(NULL);
        if (dhp->p == NULL || dhp->g == NULL) {
            DH_free(dhp);
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
    int secbits;
    EVP_PKEY *pkey = X509_get_pubkey(x);
    if (pkey) {
        secbits = EVP_PKEY_security_bits(pkey);
        EVP_PKEY_free(pkey);
    } else
        secbits = -1;
    if (s)
        return ssl_security(s, op, secbits, 0, x);
    else
        return ssl_ctx_security(ctx, op, secbits, 0, x);
}

static int ssl_security_cert_sig(SSL *s, SSL_CTX *ctx, X509 *x, int op)
{
    /* Lookup signature algorithm digest */
    int secbits = -1, md_nid = NID_undef, sig_nid;
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
