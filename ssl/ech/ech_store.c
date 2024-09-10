/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "../ssl_local.h"
#include "ech_local.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#ifndef OPENSSL_NO_ECH

/* a size for some crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 2048

/*
 * Used for ech_bio2buf, when reading from a BIO we allocate in chunks sized
 * as per below, with a max number of chunks as indicated, we don't expect to
 * go beyond one chunk in almost all cases
 */
# define OSSL_ECH_BUFCHUNK 512
# define OSSL_ECH_MAXITER  32

/*
 * TODO(ECH): consider whether to keep this...
 * To meet the needs of script-based tools (likely to deal with
 * base64 or ascii-hex encodings) and of libraries that might
 * handle binary values we support various input formats for
 * encoded ECHConfigList API inputs:
 * - binary encoded ECHConfigList
 * - binary (wireform) HTTPS/SVCB RRVALUE
 * - base64 encoded ECHConfigList
 * - ascii-hex encoded ECHConfigList
 * - DNS zone-file presentation-like format containing "ech=<b64-stuff>"
 *
 * We guess which format we're given by checking until something works
 * or nothing has.
 */
# define OSSL_ECH_FMT_GUESS     0  /* implementation will guess */
# define OSSL_ECH_FMT_BIN       1  /* catenated binary ECHConfigList */
# define OSSL_ECH_FMT_B64TXT    2  /* base64 ECHConfigList (';' separated) */
# define OSSL_ECH_FMT_ASCIIHEX  3  /* ascii-hex ECHConfigList (';' separated */
# define OSSL_ECH_FMT_HTTPSSVC  4  /* presentation form with "ech=<b64>" */
# define OSSL_ECH_FMT_DIG_UNK   5  /* dig unknown format (mainly ascii-hex) */
# define OSSL_ECH_FMT_DNS_WIRE  6  /* DNS wire format (binary + other) */
/* special case: HTTPS RR presentation form with no "ech=<b64>" */
# define OSSL_ECH_FMT_HTTPSSVC_NO_ECH 7

/*
 * TODO(ECH): consider whether to keep this...
 * We support catenated lists of encoded ECHConfigLists (to make it easier
 * to feed values from scripts). Catenated binary values need no separator
 * as there is internal length information. Catenated ascii-hex or
 * base64 values need a separator semi-colon.
 *
 * All catenated values passed in a single call must use the same
 * encoding method.
 */
# define OSSL_ECH_B64_SEPARATOR " "    /* separator str for b64 decode  */
# define OSSL_ECH_FMT_LINESEP   "\r\n" /* separator str for lines  */

/*
 * Telltales we use when guessing which form of encoded input we've
 * been given for an RR value or ECHConfig.
 * We give these the EBCDIC treatment as well - why not? :-)
 */
/*
 * ascii hex with either case allowed, plus a semi-colon separator
 * "0123456789ABCDEFabcdef;"
 */
static const char *AH_alphabet =
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x61\x62"
    "\x63\x64\x65\x66\x3b";
/*
 * b64 plus a semi-colon - we accept multiple semi-colon separated values
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;"
 */
static const char *B64_alphabet =
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52"
    "\x53\x54\x55\x56\x57\x58\x59\x5a\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a"
    "\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x30\x31"
    "\x32\x33\x34\x35\x36\x37\x38\x39\x2b\x2f\x3d\x3b";
/*
 * telltales for ECH HTTPS/SVCB in presentation format, as per svcb spec
 * 1: "ech=" 2: "alpn=" 3: "ipv4hint=" 4: "ipv6hint="
 */
static const char *httpssvc_telltale1 = "\x65\x63\x68\x3d";
static const char *httpssvc_telltale2 = "\x61\x6c\x70\x6e\x3d";
static const char *httpssvc_telltale3 = "\x69\x70\x76\x34\x68\x69\x6e\x74\x3d";
static const char *httpssvc_telltale4 = "\x69\x70\x76\x36\x68\x69\x6e\x74\x3d";
/*
 * telltale for ECH HTTPS/SVCB in dig unknownformat (i.e. ascii-hex with a
 * header and some spaces
 * "\# " is the telltale
 */
static const char *unknownformat_telltale = "\x5c\x23\x20";

/*
 * Wire-format type code for ECH/ECHConfiGList within an SVCB or HTTPS RR
 * value
 */
# define OSSL_ECH_PCODE_ECH 0x0005

# ifndef TLSEXT_MINLEN_host_name
/*
 * TODO(ECH): shortest DNS name we allow, e.g. "a.bc" - maybe that should
 * be defined elsewhere, or should the check be skipped in case there's
 * a local deployment that uses shorter names?
 */
#  define TLSEXT_MINLEN_host_name 4
# endif

/*
 * local functions - public APIs are at the end
 */

static void ossl_echext_free(OSSL_ECHEXT *e)
{
    if (e == NULL)
        return;
    OPENSSL_free(e->val);
    OPENSSL_free(e);
    return;
}

static void ossl_echstore_entry_free(OSSL_ECHSTORE_ENTRY *ee)
{
    if (ee == NULL)
        return;
    OPENSSL_free(ee->public_name);
    OPENSSL_free(ee->pub);
    OPENSSL_free(ee->pemfname);
    EVP_PKEY_free(ee->keyshare);
    OPENSSL_free(ee->encoded);
    OPENSSL_free(ee->suites);
    sk_OSSL_ECHEXT_pop_free(ee->exts, ossl_echext_free);
    OPENSSL_free(ee);
    return;
}

static int ech_ah_decode(size_t ahlen, const char *ah,
                         size_t *blen, unsigned char **buf)
{
    size_t llen = 0;
    unsigned char *lbuf = NULL;

    if (ahlen < 2 || ah == NULL || blen == NULL || buf == NULL)
        return 0;
    if (OPENSSL_hexstr2buf_ex(NULL, 0, &llen, ah, '\0') != 1)
        return 0;
    lbuf = OPENSSL_malloc(llen);
    if (lbuf == NULL)
        return 0;
    if (OPENSSL_hexstr2buf_ex(lbuf, llen, blen, ah, '\0') != 1) {
        OPENSSL_free(lbuf);
        return 0;
    }
    *buf = lbuf;
    return 1;
}

/*
 * @brief hash a buffer as a pretend file name being ascii-hex of hashed buffer
 * @param es is the OSSL_ECHSTORE we're dealing with
 * @param buf is the input buffer
 * @param blen is the length of buf
 * @param ah_hash is a pointer to where to put the result
 * @param ah_len is the length of ah_hash
 */
static int ech_hash_pub_as_fname(OSSL_ECHSTORE *es,
                                 const unsigned char *buf, size_t blen,
                                 char *ah_hash, size_t ah_len)
{
    unsigned char hashval[EVP_MAX_MD_SIZE];
    size_t hashlen, actual_ah_len;

    if (es == NULL
        || EVP_Q_digest(es->libctx, "SHA2-256", es->propq,
                        buf, blen, hashval, &hashlen) != 1
        || OPENSSL_buf2hexstr_ex(ah_hash, ah_len, &actual_ah_len,
                                 hashval, hashlen, '\0') != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

/*
 * @brief Read a buffer from an input 'till eof
 * @param in is the BIO input
 * @param buf is where to put the buffer, allocated inside here
 * @param len is the length of that buffer
 *
 * This is intended for small inputs, either files or buffers and
 * not other kinds of BIO.
 * TODO(ECH): how to check for oddball input BIOs?
 */
static int ech_bio2buf(BIO *in, unsigned char **buf, size_t *len)
{
    unsigned char *lptr = NULL, *lbuf = NULL, *tmp = NULL;
    size_t sofar = 0, readbytes = 0;
    int done = 0, brv,  iter = 0;

    if (buf == NULL || len == NULL)
        return 0;
    sofar=OSSL_ECH_BUFCHUNK;
    lbuf = OPENSSL_zalloc(sofar);
    if (lbuf == NULL)
        return 0;
    lptr = lbuf;
    while (!BIO_eof(in) && !done && iter++ < OSSL_ECH_MAXITER) {
        brv = BIO_read_ex(in, lptr, OSSL_ECH_BUFCHUNK, &readbytes);
        if (brv != 1)
            goto err;
        if (readbytes < OSSL_ECH_BUFCHUNK) {
            done = 1;
            break;
        }
        sofar += OSSL_ECH_BUFCHUNK;
        tmp = OPENSSL_realloc(lbuf, sofar);
        if (tmp == NULL)
            goto err;
        lptr += OSSL_ECH_BUFCHUNK;
    }
    if (BIO_eof(in) && done == 1)  {
        *len = (lptr + readbytes) - lbuf;
        *buf = lbuf;
        return 1;
    }
err:
    OPENSSL_free(lbuf);
    return 0;
}

/*
 * @brief decode the DNS name in a binary RRData
 * @param buf points to the buffer (in/out)
 * @param remaining points to the remaining buffer length (in/out)
 * @param dnsname returns the string-form name on success
 * @return is 1 for success, error otherwise
 *
 * The encoding here is defined in
 * https://tools.ietf.org/html/rfc1035#section-3.1
 *
 * The input buffer pointer will be modified so it points to
 * just after the end of the DNS name encoding on output. (And
 * that's why it's an "unsigned char **" :-)
 */
static int ech_decode_rdata_name(unsigned char **buf, size_t *remaining,
                                 char **dnsname)
{
    unsigned char *cp = NULL;
    int rem = 0;
    char *thename = NULL, *tp = NULL;
    unsigned char clen = 0; /* chunk len */

    if (buf == NULL || remaining == NULL || dnsname == NULL)
        return 0;
    rem = (int)*remaining;
    thename = OPENSSL_malloc(TLSEXT_MAXLEN_host_name);
    if (thename == NULL)
        return 0;
    cp = *buf;
    tp = thename;
    clen = *cp++;
    rem -= 1;
    if (clen == 0) {
        /* special case - return "." as name */
        thename[0] = '.';
        thename[1] = 0x00;
    }
    while (clen != 0 && rem > 0) {
        if (clen > rem) {
            OPENSSL_free(thename);
            return 0;
        }
        if (((tp - thename) + clen + 1) > TLSEXT_MAXLEN_host_name) {
            OPENSSL_free(thename);
            return 0;
        }
        memcpy(tp, cp, clen);
        tp += clen;
        *tp++ = '.';
        cp += clen;
        rem -= (clen + 1);
        if (rem <= 0) {
            OPENSSL_free(thename);
            return 0;
        }
        clen = *cp++;
    }
    *buf = cp;
    if (rem <= 0) {
        OPENSSL_free(thename);
        return 0;
    }
    *remaining = rem;
    *dnsname = thename;
    return 1;
}

/*
 * @brief Try figure out ECHConfig encodng by looking for telltales
 * @param encodedval is a buffer with the encoding
 * @param encodedlen is the length of that buffer
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 *
 * We try check from most to least restrictive  to avoid wrong
 * answers. IOW we try from most constrained to least in that
 * order.
 *
 * The wrong answer could be derived with a low probability.
 * If the application can't handle that, then it ought not use
 * OSSL_ech_find_echconfigs()
 */
static int ech_guess_format(unsigned char *encodedval, size_t encodedlen,
                            int *guessedfmt)
{
    size_t span = 0;
    char *dnsname = NULL;
    unsigned char *cp = NULL, *rdin = NULL;
    size_t remaining;

    if (guessedfmt == NULL || encodedlen == 0 || encodedval == NULL)
        return 0;
    /*
     * check for binary encoding of an ECHConfigList that starts with a
     * two octet length and then our ECH extension type codepoint
     */
    if (encodedlen <= 2)
        return 0;
    cp = OPENSSL_malloc(encodedlen + 1);
    if (cp == NULL)
        return 0;
    memcpy(cp, encodedval, encodedlen);
    cp[encodedlen] = '\0'; /* make sure string funcs have a NUL terminator */
    if (encodedlen > 4
        && encodedlen == ((size_t)(cp[0]) * 256 + (size_t)(cp[1])) + 2
        && cp[3] == ((OSSL_ECH_RFCXXXX_VERSION / 256) & 0xff)
        && cp[4] == ((OSSL_ECH_RFCXXXX_VERSION % 256) & 0xff)) {
        *guessedfmt = OSSL_ECH_FMT_BIN;
        goto win;
    }
    if (encodedlen < strlen(unknownformat_telltale))
        goto err;
    if (!strncmp((char *)cp, unknownformat_telltale,
                 strlen(unknownformat_telltale))) {
        *guessedfmt = OSSL_ECH_FMT_DIG_UNK;
        goto win;
    }
    if (strstr((char *)cp, httpssvc_telltale1)) {
        *guessedfmt = OSSL_ECH_FMT_HTTPSSVC;
        goto win;
    }
    if (strstr((char *)cp, httpssvc_telltale2)
        || strstr((char *)cp, httpssvc_telltale3)
        || strstr((char *)cp, httpssvc_telltale4)) {
        *guessedfmt = OSSL_ECH_FMT_HTTPSSVC_NO_ECH;
        goto win;
    }
    span = strspn((char *)cp, AH_alphabet);
    if (encodedlen <= span) {
        *guessedfmt = OSSL_ECH_FMT_ASCIIHEX;
        goto win;
    }
    span = strspn((char *)cp, B64_alphabet);
    if (encodedlen <= span) {
        *guessedfmt = OSSL_ECH_FMT_B64TXT;
        goto win;
    }
    /*
     * check for HTTPS RR DNS wire format - we'll go with that if
     * the buffer starts with a two octet priority and then a
     * wire-format encoded DNS name
     */
    rdin = cp + 2;
    remaining = encodedlen - 2;
    if (ech_decode_rdata_name(&rdin, &remaining, &dnsname) == 1) {
        *guessedfmt = OSSL_ECH_FMT_DNS_WIRE;
        OPENSSL_free(dnsname);
        goto win;
    }
    /* fallback - try binary */
    *guessedfmt = OSSL_ECH_FMT_BIN;
win:
    OPENSSL_free(cp);
    return 1;
err:
    OPENSSL_free(cp);
    return 0;
}

/*
 * @brief helper to decode ECHConfig extensions
 * @param ee is the OSSL_ECHSTORE entry for these
 * @param exts is the binary form extensions
 * @return 1 for good, 0 for error
 */
static int ech_decode_echconfig_exts(OSSL_ECHSTORE_ENTRY *ee, PACKET *exts)
{
    unsigned int exttype = 0;
    unsigned int extlen = 0;
    unsigned char *extval = NULL;
    OSSL_ECHEXT *oe = NULL;

    /*
     * reminder: exts is a two-octet length prefixed list of:
     * - two octet extension type
     * - two octet extension length (can be zero)
     * - length octets
     * we've consumed the overall length before getting here
     */
    while (PACKET_remaining(exts) > 0) {
        exttype = 0, extlen = 0;
        extval = NULL;
        if (!PACKET_get_net_2(exts, &exttype)
            || !PACKET_get_net_2(exts, &extlen)
            || extlen >= OSSL_ECH_MAX_ECHCONFIGEXT_LEN) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (extlen != 0) {
            extval = (unsigned char *)OPENSSL_malloc(extlen);
            if (extval == NULL)
                goto err;
            if (!PACKET_copy_bytes(exts, extval, extlen)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        oe = (OSSL_ECHEXT *) OPENSSL_malloc(sizeof(*oe));
        if (oe == NULL)
            goto err;
        oe->type = exttype;
        oe->val = extval;
        oe->len = extlen;
        if (ee->exts == NULL)
            ee->exts = sk_OSSL_ECHEXT_new_null();
        if (ee->exts == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!sk_OSSL_ECHEXT_push(ee->exts, oe)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    return 1;
err:
    sk_OSSL_ECHEXT_pop_free(ee->exts, ossl_echext_free);
    ee->exts = 0;
    ossl_echext_free(oe);
    OPENSSL_free(extval);
    return 0;
}

/*
 * @brief Check entry to see if looks good or bad
 * @param ee is the ECHConfig to check
 * @return 1 for all good, 0 otherwise
 */
static int ech_final_config_checks(OSSL_ECHSTORE_ENTRY *ee)
{
    OSSL_HPKE_SUITE hpke_suite;
    size_t ind = 0, num;
    int goodsuitefound = 0;

    /* check local support for some suite */
    for (ind = 0; ind != ee->nsuites; ind++) {
        /*
         * suite_check says yes to the pseudo-aead for export, but we don't
         * want to see it here coming from outside in an encoding
         */
        hpke_suite = ee->suites[ind];
        if (OSSL_HPKE_suite_check(hpke_suite) == 1
            && hpke_suite.aead_id != OSSL_HPKE_AEAD_ID_EXPORTONLY) {
            goodsuitefound = 1;
            break;
        }
    }
    if (goodsuitefound == 0) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "ECH: No supported suites for ECHConfig");
        } OSSL_TRACE_END(TLS);
        return 0;
    }

    /* check no mandatory exts (with high bit set in type) */
    num = (ee->exts == NULL ? 0 : sk_OSSL_ECHEXT_num(ee->exts));
    for (ind = 0; ind != num; ind++) {
        OSSL_ECHEXT *oe = sk_OSSL_ECHEXT_value(ee->exts, ind);
        if (oe->type & 0x8000) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ECH: Unsupported mandatory ECHConfig "
                           "extension (0x%04x)", oe->type);
            } OSSL_TRACE_END(TLS);
            return 0;
        }
    }
    /* check public_name rules, as per spec section 4 */
    if (ee->public_name == NULL
        || ee->public_name[0] == '\0'
        || ee->public_name[0] == '.'
        || ee->public_name[strlen(ee->public_name) - 1] == '.')
        return 0;
    return 1;
}

/*
 * @brief decode and flatten a binary encoded ECHConfigList
 * @param es an OSSL_ECHSTORE
 * @param priv is an optional private key (NULL if absent)
 * @param for_retry says whether to include in a retry_config (if priv present)
 * @param binbuf binary encoded ECHConfigList (we hope)
 * @param binlen length of binbuf
 * @return 1 for success, 0 for error
 *
 * We may only get one ECHConfig per list, but there can be more.  We want each
 * element of the output to contain exactly one ECHConfig so that a client
 * could sensibly down select to the one they prefer later, and so that we have
 * the specific encoded value of that ECHConfig for inclusion in the HPKE info
 * parameter when finally encrypting or decrypting an inner ClientHello.
 *
 * If a private value is provided then that'll only be associated with the
 * relevant public value, if >1 public value was present in the ECHConfigList.
 */
static int ech_decode_and_flatten(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                  int for_retry,
                                  unsigned char *binbuf, size_t binblen,
                                  size_t *leftover)
{
    int rv = 0;
    size_t remaining = 0, not_to_consume = 0;
    PACKET pkt;
    unsigned int olen = 0;
    unsigned char *skip = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;

    if (binbuf == NULL || binblen == 0
        || binblen < OSSL_ECH_MIN_ECHCONFIG_LEN
        || binblen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Overall length of this ECHConfigList (olen) still could be less than
     * the input buffer length, (binblen) if the caller has been given a
     * catenated set of binary buffers
     */
    if (PACKET_buf_init(&pkt, binbuf, binblen) != 1
        || !PACKET_get_net_2(&pkt, &olen)
        || olen < (OSSL_ECH_MIN_ECHCONFIG_LEN - 2)
        || olen > (binblen - 2)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    not_to_consume = binblen - olen;
    remaining = PACKET_remaining(&pkt);
    while (remaining > not_to_consume) {
        unsigned int ech_content_length = 0, tmpi;
        unsigned char *tmpecstart = NULL;
        const unsigned char *tmpecp = NULL;
        size_t tmpeclen = 0;
        PACKET pub_pkt, cipher_suites, public_name_pkt, exts;
        uint16_t thiskemid;
        unsigned int suiteoctets = 0, public_name_len, ci = 0;
        unsigned char cipher[OSSL_ECH_CIPHER_LEN], max_name_len;
        unsigned char test_pub[OSSL_ECH_CRYPTO_VAR_SIZE];
        size_t test_publen = 0;

        ee = OPENSSL_zalloc(sizeof(*ee));
        if (ee == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* note start of encoding so we can make a copy later */
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1
            || !PACKET_get_net_2(&pkt, &tmpi)
            || !PACKET_get_net_2(&pkt, &ech_content_length)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee->version = (uint16_t) tmpi;
        /* the length of one ECHConfig can't be more than that of the list */
        if (ech_content_length >= olen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        remaining = PACKET_remaining(&pkt);
        if (ech_content_length > (remaining + 2)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        switch (ee->version) {
        case OSSL_ECH_RFCXXXX_VERSION:
            break;
        default:
            /* skip over in case we get something we can handle later */
            skip = OPENSSL_malloc(ech_content_length);
            if (skip == NULL)
                goto err;
            if (!PACKET_copy_bytes(&pkt, skip, ech_content_length)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                OPENSSL_free(skip);
                goto err;
            }
            OPENSSL_free(skip);
            remaining = PACKET_remaining(&pkt);
            /* unallocate that one */
            ossl_echstore_entry_free(ee);
            ee = NULL;
            continue;
        }
        if (!PACKET_copy_bytes(&pkt, &ee->config_id, 1)
            || !PACKET_get_net_2(&pkt, &tmpi)
            || !PACKET_get_length_prefixed_2(&pkt, &pub_pkt)
            || (ee->pub_len = PACKET_remaining(&pub_pkt)) == 0
            || (ee->pub = OPENSSL_malloc(ee->pub_len)) == NULL
            || !PACKET_copy_bytes(&pub_pkt, ee->pub, ee->pub_len)
            || !PACKET_get_length_prefixed_2(&pkt, &cipher_suites)
            || (suiteoctets = PACKET_remaining(&cipher_suites)) <= 0
            || (suiteoctets % 2) == 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        thiskemid = (uint16_t) tmpi;
        ee->nsuites = suiteoctets / OSSL_ECH_CIPHER_LEN;
        ee->suites = OPENSSL_malloc(ee->nsuites * sizeof(*ee->suites));
        if (ee->suites == NULL)
            goto err;
        while (PACKET_copy_bytes(&cipher_suites, cipher,
                                 OSSL_ECH_CIPHER_LEN)) {
            ee->suites[ci].kem_id = thiskemid;
            ee->suites[ci].kdf_id = cipher[0] << 8 | cipher [1];
            ee->suites[ci].aead_id = cipher[2] << 8 | cipher [3];
            if (ci++ > ee->nsuites) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        if (PACKET_remaining(&cipher_suites) > 0
            || !PACKET_copy_bytes(&pkt, &max_name_len, 1)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee->max_name_length = max_name_len;
        if (!PACKET_get_length_prefixed_1(&pkt, &public_name_pkt)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        public_name_len = PACKET_remaining(&public_name_pkt);
        if (public_name_len < TLSEXT_MINLEN_host_name
            || public_name_len > TLSEXT_MAXLEN_host_name) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee->public_name = OPENSSL_malloc(public_name_len + 1);
        if (ee->public_name == NULL)
            goto err;
        if (PACKET_copy_bytes(&public_name_pkt,
                              (unsigned char *) ee->public_name,
                              public_name_len) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee->public_name[public_name_len] = '\0';
        /* ensure no NUL inside public_name string */
        if (strlen(ee->public_name) != public_name_len) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (PACKET_remaining(&exts) > 0
            && ech_decode_echconfig_exts(ee, &exts) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* set length of encoding of this ECHConfig */
        ee->encoded = (unsigned char *)tmpecp;
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee->encoded_len = tmpecp - ee->encoded;
        /* copy encoding_start as it might get free'd if a reduce happens */
        tmpecstart = OPENSSL_malloc(ee->encoded_len);
        if (tmpecstart == NULL) {
            ee->encoded = NULL; /* don't free twice in this case */
            goto err;
        }
        memcpy(tmpecstart, ee->encoded, ee->encoded_len);
        ee->encoded = tmpecstart;
        if (priv != NULL) {
            if (EVP_PKEY_get_octet_string_param(priv,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        test_pub, OSSL_ECH_CRYPTO_VAR_SIZE,
                                        &test_publen) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (test_publen == ee->pub_len
                && !memcmp(test_pub, ee->pub, ee->pub_len)) {
                /* associate the private key */
                EVP_PKEY_up_ref(priv);
                ee->keyshare = priv;
                ee->for_retry = for_retry;
            }
        }
        ee->loadtime = time(0);
        remaining = PACKET_remaining(&pkt);
        /* do final checks on suites, exts, and skip this one if issues */
        if (ech_final_config_checks(ee) != 1) {
            ossl_echstore_entry_free(ee);
            ee = NULL;
            continue;
        }
        /* push entry into store */
        if (es->entries == NULL)
            es->entries = sk_OSSL_ECHSTORE_ENTRY_new_null();
        if (es->entries == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!sk_OSSL_ECHSTORE_ENTRY_push(es->entries, ee)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ee = NULL;
    }
    *leftover = PACKET_remaining(&pkt);
    rv = 1;
err:
    ossl_echstore_entry_free(ee);
    return rv;
}

/*
 * @brief decode input ECHConfigList and associate optional private info
 * @param es is the OSSL_ECHSTORE
 * @param in is the BIO from which we'll get the ECHConfigList
 * @param priv is an optional private key
 * @param for_retry 1 if the public related to priv ought be in retry_config
 */
static int ech_read_priv_echconfiglist(OSSL_ECHSTORE *es, BIO *in,
                                       EVP_PKEY *priv, int for_retry)
{
    int rv = 0, detfmt = OSSL_ECH_FMT_GUESS, origfmt;
    size_t encodedlen=0, leftover = 0;
    unsigned char *encodedval=NULL;
    int multiline = 0, linesdone = 0,  nonehere = 0, tdeclen = 0;
    unsigned char *lval, *binbuf = NULL;
    size_t llen , binlen = 0, linelen = 0, slen = 0, ldiff = 0;
    char *dnsname = NULL, *tmp = NULL, *lstr = NULL, *ekstart = NULL;

    if (es == NULL || in == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ech_bio2buf(in, &encodedval, &encodedlen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ech_guess_format(encodedval, encodedlen, &detfmt) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC_NO_ECH) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    origfmt = detfmt;
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC || detfmt == OSSL_ECH_FMT_DIG_UNK)
        multiline = 1;
    llen = encodedlen;
    lval = encodedval;
    while (linesdone == 0) { /* if blank line, then skip */
        if (multiline == 1 && strchr(OSSL_ECH_FMT_LINESEP, lval[0]) != NULL) {
            if (llen > 1) {
                lval++;
                llen -= 1;
                continue;
            } else {
                break; /* we're done */
            }
        }
        if (llen >= OSSL_ECH_MAX_ECHCONFIG_LEN) { /* sanity check */
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        detfmt = origfmt; /* restore format from before loop */
        if (detfmt == OSSL_ECH_FMT_BIN || detfmt == OSSL_ECH_FMT_DNS_WIRE) {
            /* copy buffer if binary format */
            binbuf = OPENSSL_malloc(encodedlen);
            if (binbuf == NULL)
                goto err;
            memcpy(binbuf, encodedval, encodedlen);
            binlen = encodedlen;
        }
        /* do decodes, some of these fall through to others */
        if (detfmt == OSSL_ECH_FMT_DIG_UNK) {
            /* chew up header and length, e.g. "\\# 232 " */
            if (llen < strlen(unknownformat_telltale) + 3) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            lstr = (char *)(lval + strlen(unknownformat_telltale));
            tmp = strstr(lstr, " ");
            if (tmp == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ldiff = tmp - (char *)lval;
            if (ldiff >= llen
                || ech_ah_decode(llen - ldiff, (char *)lval + ldiff,
                                 &binlen, &binbuf) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            detfmt = OSSL_ECH_FMT_DNS_WIRE;
        }
        if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
            /* AH decode and fall throught to DNS wire or binary */
            if (ech_ah_decode(llen, (char *)lval, &binlen, &binbuf) != 1
                || binlen < 4) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /*
             * ECHConfigList has a 2-octet length then version. SCVB RDATA wire
             * format starts with 2-octet svcPriority field, then encoded DNS
             * name. Our RFC XXXX field has a value of 0xfe0d, and it's
             * extremely unlikely we deal with a DNS name label of length 0xfe
             * (254), that being disallowed.
             */
            if ((size_t)(binbuf[0] * 256 + binbuf[1]) == (binlen - 2)
                && binbuf[2] == ((OSSL_ECH_RFCXXXX_VERSION >> 8) & 0xff)
                && binbuf[3] == (OSSL_ECH_RFCXXXX_VERSION & 0xff))
                detfmt = OSSL_ECH_FMT_BIN;
            else
                detfmt = OSSL_ECH_FMT_DNS_WIRE;
        }
        if (detfmt == OSSL_ECH_FMT_DNS_WIRE) {
            /* decode DNS wire and fall through to binary */
            size_t remaining = binlen, eklen = 0;
            unsigned char *cp = binbuf, *ekval = NULL;
            uint16_t pcode = 0, plen = 0;
            int done = 0;

            if (remaining <= 2) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            cp += 2;
            remaining -= 2;
            if (ech_decode_rdata_name(&cp, &remaining, &dnsname) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            OPENSSL_free(dnsname);
            dnsname = NULL;
            while (done != 1 && remaining >= 4) {
                pcode = (*cp << 8) + (*(cp + 1));
                cp += 2;
                plen = (*cp << 8) + (*(cp + 1));
                cp += 2;
                remaining -= 4;
                if (pcode == OSSL_ECH_PCODE_ECH) {
                    eklen = (size_t)plen;
                    ekval = cp;
                    done = 1;
                }
                if (plen != 0 && plen <= remaining) {
                    cp += plen;
                    remaining -= plen;
                }
            }
            if (done == 0) {
                nonehere = 1; /* not an error just didn't find an ECH here */
            } else {
                /* binbuf is bigger, so the in-place memmove is ok */
                memmove(binbuf, ekval, eklen);
                binlen = eklen;
                detfmt = OSSL_ECH_FMT_BIN;
            }
        }
        if (detfmt == OSSL_ECH_FMT_HTTPSSVC) {
            ekstart = strstr((char *)lval, httpssvc_telltale1);
            if (ekstart == NULL) {
                nonehere = 1;
            } else {
                if (strlen(ekstart) <= strlen(httpssvc_telltale1)) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ekstart += strlen(httpssvc_telltale1);
                llen = strcspn(ekstart, " \n");
                lval = (unsigned char *)ekstart;
                detfmt = OSSL_ECH_FMT_B64TXT;
            }
        }
        if (detfmt == OSSL_ECH_FMT_B64TXT) {
            BIO *btmp, *btmp1;

            btmp = BIO_new_mem_buf(lval, -1);
            if (btmp == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            btmp1 = BIO_new(BIO_f_base64());
            if (btmp1 == NULL) {
                BIO_free_all(btmp);
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            BIO_set_flags(btmp1, BIO_FLAGS_BASE64_NO_NL);
            btmp = BIO_push(btmp1, btmp);
            /* overestimate but good enough */
            binbuf=OPENSSL_malloc(llen);
            if (binbuf == NULL) {
                BIO_free_all(btmp);
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            tdeclen = BIO_read(btmp, binbuf, llen);
            BIO_free_all(btmp);
            if (tdeclen <= 0) { /* need int for -1 return in failure case */
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            binlen = tdeclen;
            detfmt = OSSL_ECH_FMT_BIN;
        }
        if (nonehere != 1 && detfmt != OSSL_ECH_FMT_BIN) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (nonehere == 0) {
            if (ech_decode_and_flatten(es, priv, for_retry,
                                       binbuf, binlen, &leftover) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        OPENSSL_free(binbuf);
        binbuf = NULL;
        if (multiline == 0) { /* check at end if more lines to do */
            linesdone = 1;
        } else {
            slen = strlen((char *)lval); /* is there a next line? */
            linelen = strcspn((char *)lval, OSSL_ECH_FMT_LINESEP);
            if (linelen >= slen) {
                linesdone = 1;
            } else {
                lval = lval + linelen + 1;
                llen = slen - linelen - 1;
            }
        }
    }
    rv = 1;
err:
    OPENSSL_free(dnsname);
    OPENSSL_free(binbuf);
    OPENSSL_free(encodedval);
    return rv;
}

/*
 * API calls built around OSSL_ECHSSTORE
 */

OSSL_ECHSTORE *OSSL_ECHSTORE_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_ECHSTORE *es = NULL;

    es = OPENSSL_zalloc(sizeof(*es));
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    es->libctx = libctx;
    es->propq = propq;
    return es;
}

void OSSL_ECHSTORE_free(OSSL_ECHSTORE *es)
{
    if (es == NULL)
        return;
    sk_OSSL_ECHSTORE_ENTRY_pop_free(es->entries, ossl_echstore_entry_free);
    OPENSSL_free(es);
    return;
}

int OSSL_ECHSTORE_new_config(OSSL_ECHSTORE *es,
                             uint16_t echversion, uint8_t max_name_length,
                             const char *public_name, OSSL_HPKE_SUITE suite)
{
    size_t pnlen = 0, publen = OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char pub[OSSL_ECH_CRYPTO_VAR_SIZE];
    int rv = 0;
    unsigned char *bp = NULL;
    size_t bblen = 0;
    EVP_PKEY *privp = NULL;
    uint8_t config_id = 0;
    WPACKET epkt;
    BUF_MEM *epkt_mem = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    char pembuf[2 * EVP_MAX_MD_SIZE + 1];
    size_t pembuflen = 2 * EVP_MAX_MD_SIZE + 1;

    /* basic checks */
    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pnlen = (public_name == NULL ? 0 : strlen(public_name));
    if (pnlen == 0 || pnlen > OSSL_ECH_MAX_PUBLICNAME
        || max_name_length > OSSL_ECH_MAX_MAXNAMELEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* this used have more versions and will again in future */
    switch (echversion) {
    case OSSL_ECH_RFCXXXX_VERSION:
        break;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* so WPACKET_cleanup() won't go wrong */
    memset(&epkt, 0, sizeof(epkt));
    /* random config_id */
    if (RAND_bytes_ex(es->libctx, (unsigned char *)&config_id, 1,
                      RAND_DRBG_STRENGTH) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* key pair */
    if (OSSL_HPKE_keygen(suite, pub, &publen, &privp, NULL, 0,
                         es->libctx, es->propq) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     *   Reminder, for draft-13 we want this:
     *
     *   opaque HpkePublicKey<1..2^16-1>;
     *   uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
     *   uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
     *   struct {
     *       HpkeKdfId kdf_id;
     *       HpkeAeadId aead_id;
     *   } HpkeSymmetricCipherSuite;
     *   struct {
     *       uint8 config_id;
     *       HpkeKemId kem_id;
     *       HpkePublicKey public_key;
     *       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
     *   } HpkeKeyConfig;
     *   struct {
     *       HpkeKeyConfig key_config;
     *       uint8 maximum_name_length;
     *       opaque public_name<1..255>;
     *       Extension extensions<0..2^16-1>;
     *   } ECHConfigContents;
     *   struct {
     *       uint16 version;
     *       uint16 length;
     *       select (ECHConfig.version) {
     *         case 0xfe0d: ECHConfigContents contents;
     *       }
     *   } ECHConfig;
     *   ECHConfig ECHConfigList<1..2^16-1>;
     */
    if ((epkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(epkt_mem, OSSL_ECH_MAX_ECHCONFIG_LEN)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* config id, KEM, public, KDF, AEAD, max name len, public_name, exts */
    if (!WPACKET_init(&epkt, epkt_mem)
        || (bp = WPACKET_get_curr(&epkt)) == NULL
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, echversion)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, config_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.kem_id)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, pub, publen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_put_bytes_u16(&epkt, suite.kdf_id)
        || !WPACKET_put_bytes_u16(&epkt, suite.aead_id)
        || !WPACKET_close(&epkt)
        || !WPACKET_put_bytes_u8(&epkt, max_name_length)
        || !WPACKET_start_sub_packet_u8(&epkt)
        || !WPACKET_memcpy(&epkt, public_name, pnlen)
        || !WPACKET_close(&epkt)
        || !WPACKET_start_sub_packet_u16(&epkt)
        || !WPACKET_memcpy(&epkt, NULL, 0) /* no extensions */
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* bp, bblen has encoding */
    WPACKET_get_total_written(&epkt, &bblen);
    if ((ee = OPENSSL_zalloc(sizeof(*ee))) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->suites = OPENSSL_malloc(sizeof(*ee->suites));
    if (ee->suites == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ech_hash_pub_as_fname(es, pub, publen, pembuf, pembuflen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->version = echversion;
    ee->pub_len = publen;
    ee->pub = OPENSSL_memdup(pub, publen);
    if (ee->pub == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->nsuites = 1;
    ee->suites[0] = suite;
    ee->public_name = OPENSSL_strdup(public_name);
    if (ee->public_name == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->max_name_length = max_name_length;
    ee->config_id = config_id;
    ee->keyshare = privp;
    ee->encoded = OPENSSL_memdup(bp, bblen);
    if (ee->encoded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->encoded_len = bblen;
    ee->pemfname = OPENSSL_strdup(pembuf);
    if (ee->pemfname == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ee->loadtime = time(0);
    /* push entry into store */
    if (es->entries == NULL)
        es->entries = sk_OSSL_ECHSTORE_ENTRY_new_null();
    if (es->entries == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!sk_OSSL_ECHSTORE_ENTRY_push(es->entries, ee)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    WPACKET_finish(&epkt);
    BUF_MEM_free(epkt_mem);
    return 1;

err:
    EVP_PKEY_free(privp);
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    ossl_echstore_entry_free(ee);
    return rv;
}

int OSSL_ECHSTORE_write_pem(OSSL_ECHSTORE *es, int index, BIO *out)
{
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int rv = 0, num = 0, chosen = 0, doall = 0;

    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    num = (es->entries == NULL ? 0 : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    if (num <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index >= num) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index == OSSL_ECHSTORE_ALL)
        doall = 1;
    else if (index == OSSL_ECHSTORE_LAST)
        chosen = num - 1;
    else
        chosen = index;
    if (doall == 0) {
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, chosen);
        if (ee == NULL || ee->keyshare == NULL || ee->encoded == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        /* private key first */
        if (!PEM_write_bio_PrivateKey(out, ee->keyshare, NULL, NULL, 0,
                                    NULL, NULL)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (PEM_write_bio(out, PEM_STRING_ECHCONFIG, NULL,
                        ee->encoded, ee->encoded_len) <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        for (chosen = 0; chosen != num; chosen++) {
            ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, chosen);
            if (ee == NULL || ee->encoded == NULL) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                return 0;
            }
            if (PEM_write_bio(out, PEM_STRING_ECHCONFIG, NULL,
                            ee->encoded, ee->encoded_len) <= 0) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    rv = 1;
err:
    return rv;
}

int OSSL_ECHSTORE_read_echconfiglist(OSSL_ECHSTORE *es, BIO *in)
{
    return ech_read_priv_echconfiglist(es, in, NULL, 0);
}

int OSSL_ECHSTORE_get1_info(OSSL_ECHSTORE *es, OSSL_ECH_INFO **info,
                            int *count)
{
    OSSL_ECH_INFO *linfo = NULL, *inst = NULL;
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    unsigned int i = 0, j = 0, num = 0;
    BIO *out = NULL;
    time_t now = time(0);
    size_t ehlen;
    unsigned char *ignore = NULL;

    if (es == NULL || info == NULL || count == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    num = (es->entries == NULL ? 0 : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    if (num == 0) {
        *info = NULL;
        *count = 0;
        return 1;
    }
    linfo = OPENSSL_zalloc(num * sizeof(*linfo));
    if (linfo == NULL)
        goto err;
    for (i = 0; i != num; i++) {
        inst = &linfo[i];
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);

        inst->index = i;
        inst->seconds_in_memory = now - ee->loadtime;
        inst->public_name = OPENSSL_strdup(ee->public_name);
        inst->has_private_key = (ee->keyshare == NULL ? 0 : 1);
        /* Now "print" the ECHConfigList */
        out = BIO_new(BIO_s_mem());
        if (out == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
            goto err;
        }
        if (ee->version != OSSL_ECH_RFCXXXX_VERSION) {
            /* just note we don't support that one today */
            BIO_printf(out, "[Unsupported version (%04x)]", ee->version);
            continue;
        }
        /* version, config_id, public_name, and kem */
        BIO_printf(out, "[%04x,%02x,%s,[", ee->version,
                   ee->config_id,
                   ee->public_name != NULL ? (char *)ee->public_name : "NULL");
        /* ciphersuites */
        for (j = 0; j != ee->nsuites; j++) {
            BIO_printf(out, "%04x,%04x,%04x", ee->suites[j].kem_id,
                       ee->suites[j].kdf_id, ee->suites[j].aead_id);
            if (j < (ee->nsuites - 1))
                BIO_printf(out, ",");
        }
        BIO_printf(out, "],");
        /* public key */
        for (j = 0; j != ee->pub_len; j++)
            BIO_printf(out, "%02x", ee->pub[j]);
        /* max name length and (only) number of extensions */
        BIO_printf(out, ",%02x,%02x]", ee->max_name_length,
                   ee->exts == NULL ? 0 : sk_OSSL_ECHEXT_num(ee->exts));
        ehlen = BIO_get_mem_data(out, &ignore);
        inst->echconfig = OPENSSL_malloc(ehlen + 1);
        if (inst->echconfig == NULL)
            goto err;
        if (BIO_read(out, inst->echconfig, ehlen) <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
            goto err;
        }
        inst->echconfig[ehlen] = '\0';
        BIO_free(out);
        out = NULL;
    }
    *count = num;
    *info = linfo;
    return 1;
err:
    BIO_free(out);
    OSSL_ECH_INFO_free(linfo, num);
    return 0;
}

int OSSL_ECHSTORE_downselect(OSSL_ECHSTORE *es, int index)
{
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num = 0, chosen = OSSL_ECHSTORE_ALL;

    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    num = (es->entries == NULL ? 0 : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    if (num == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index <= OSSL_ECHSTORE_ALL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (index == OSSL_ECHSTORE_LAST)
        chosen = num - 1;
    else if (index >= num) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    } else
        chosen = index;
    for (i = num -1; i >= 0; i--) {
        if (i == chosen)
            continue;
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);
        ossl_echstore_entry_free(ee);
        sk_OSSL_ECHSTORE_ENTRY_delete(es->entries, i);
    }
    return 1;
}

int OSSL_ECHSTORE_set1_key_and_read_pem(OSSL_ECHSTORE *es, EVP_PKEY *priv,
                                        BIO *in, int for_retry)
{
    unsigned char *b64 = NULL;
    long b64len = 0;
    BIO *b64bio = NULL;
    int rv = 0;
    char *pname = NULL, *pheader = NULL;

    /* we allow for a NULL private key */
    if (es == NULL || in == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (PEM_read_bio(in, &pname, &pheader, &b64, &b64len) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (pname == NULL
        || strncmp(pname, PEM_STRING_ECHCONFIG, strlen(PEM_STRING_ECHCONFIG))) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    b64bio = BIO_new(BIO_s_mem());
    if (b64bio == NULL
        || BIO_write(b64bio, b64, b64len) <= 0
        || ech_read_priv_echconfiglist(es, b64bio, priv, for_retry) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
    OPENSSL_free(pname);
    OPENSSL_free(pheader);
    BIO_free_all(b64bio);
    OPENSSL_free(b64);
    return rv;
}

int OSSL_ECHSTORE_read_pem(OSSL_ECHSTORE *es, BIO *in, int for_retry)
{
    EVP_PKEY *priv = NULL;
    int rv = 0;

    if (es == NULL || in == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /*
     * read private key then handoff to set1_key_and_read_pem
     * we allow for no private key as an option
     */
    if (!PEM_read_bio_PrivateKey(in, &priv, NULL, NULL)) {
        /* TODO(ECH): this is ok for file and mem BIOs but is it ok for all? */
        if (BIO_method_type(in) == BIO_TYPE_MEM)
            BIO_set_flags(in, BIO_FLAGS_NONCLEAR_RST);
        if (BIO_reset(in) < 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    rv = OSSL_ECHSTORE_set1_key_and_read_pem(es, priv, in, for_retry);
    EVP_PKEY_free(priv);
    return rv;
}

int OSSL_ECHSTORE_num_keys(OSSL_ECHSTORE *es, int *numkeys)
{
    int i, num = 0, count = 0;
    OSSL_ECHSTORE_ENTRY *ee = NULL;

    if (es == NULL || numkeys == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    num = (es->entries == NULL ? 0 : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    for (i = 0; i != num; i++) {
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);
        if (ee == NULL)
            return 0;
        count += (ee->keyshare != NULL);
    }
    *numkeys = count;
    return 1;
}

int OSSL_ECHSTORE_flush_keys(OSSL_ECHSTORE *es, time_t age)
{
    OSSL_ECHSTORE_ENTRY *ee = NULL;
    int i, num = 0;
    time_t now = time(0);

    if (es == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    num = (es->entries == NULL ? 0 : sk_OSSL_ECHSTORE_ENTRY_num(es->entries));
    if (num == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    for (i = num - 1; i >= 0; i--) {
        ee = sk_OSSL_ECHSTORE_ENTRY_value(es->entries, i);
        if (ee == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            return 0;
        }
        if (ee->keyshare != NULL && ((ee->loadtime + age) > now)) {
            ossl_echstore_entry_free(ee);
            sk_OSSL_ECHSTORE_ENTRY_delete(es->entries, i);
        }
    }
    return 1;
}

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *info, int count)
{
    int i;

    if (info == NULL)
        return;
    for (i = 0; i != count; i++) {
        OPENSSL_free(info[i].public_name);
        OPENSSL_free(info[i].inner_name);
        OPENSSL_free(info[i].outer_alpns);
        OPENSSL_free(info[i].inner_alpns);
        OPENSSL_free(info[i].echconfig);
    }
    OPENSSL_free(info);
    return;
}

int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *info, int count)
{
    if (out == NULL || info == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    BIO_printf(out, "ECH entry: %d public_name: %s%s\n",
               count + 1, info[count].public_name,
               info[count].has_private_key ? " (has private key)" : "");
    BIO_printf(out, "\t%s\n", info[count].echconfig);
    return 1;
}

#endif
