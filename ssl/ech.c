/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "ssl_local.h"
#include "ech_local.h"
#include "statem/statem_local.h"
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Needed to use stat for file status below in ech_check_filenames */
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(OPENSSL_SYS_WINDOWS)
# include <unistd.h>
#endif
#include "internal/o_dir.h"

#ifndef OPENSSL_NO_ECH

# ifndef PATH_MAX
#  define PATH_MAX 4096
# endif

/* For ossl_assert */
# include "internal/cryptlib.h"

/* For HPKE APIs */
# include <openssl/hpke.h>

# include "internal/ech_helpers.h"

/* SECTION: Macros */

/* a size for some crypto vars */
# define OSSL_ECH_CRYPTO_VAR_SIZE 2048

# define OSSL_ECH_MAX_GREASE_PUB 0x100 /* max peer key share we'll decode */
# define OSSL_ECH_MAX_GREASE_CT 0x200 /* max GREASEy ciphertext we'll emit */

/*
 * When including a different key_share in the inner CH, 256 is the
 * size we produce for a real ECH when including padding in the inner
 * CH with the default/current client hello padding code.
 * This value doesn't vary with at least minor changes to inner SNI
 * length. The 272 is 256 of padded cleartext plus a 16-octet AEAD
 * tag.
 *
 * If we compress the key_share then that brings us down to 128 for
 * the padded inner CH and 144 for the ciphertext including AEAD
 * tag.
 *
 * We'll adjust the GREASE number below to match whatever
 * key_share handling we do.
 */
# define OSSL_ECH_DEF_CIPHER_LEN_SMALL 144
# define OSSL_ECH_DEF_CIPHER_LEN_LARGE 272

/*
 * We can add/subtract a few octets if jitter is desirable - if set then
 * we'll add or subtract a random number of octets less than the max jitter
 * setting. If the default value is set to zero, we won't bother. It is
 * probably better for now at least to not bother with jitter at all but
 * keeping the compile-time capability for now is probably worthwhile in
 * case experiments indicate such jitter is useful. To turn off jitter
 * just set the default to zero, as is currently done below.
 */
# define OSSL_ECH_MAX_CIPHER_LEN_JITTER 32 /* max jitter in cipher len */
# define OSSL_ECH_DEF_CIPHER_LEN_JITTER 0 /* default jitter in cipher len */

# ifndef TLSEXT_MINLEN_host_name
/*
 * the shortest DNS name we allow, e.g. "a.bc" - maybe that should be defined
 * elsewhere?
 */
#  define TLSEXT_MINLEN_host_name 4
# endif

/*
 * DUPEMALL is useful for testing - this turns off compression and
 * causes two calls to each extension constructor, which'd be the same
 * as making all entries in ext_ext_handling use the CALL_BOTH value
 */
# undef DUPEMALL

/*
 * To control the number of zeros added after a draft-13
 * EncodedClientHello - we pad to a target number of octets
 * or, if there are naturally more, to a number divisible by
 * the defined increment (we also do the draft-13 recommended
 * SNI padding thing first)
 */
# define OSSL_ECH_PADDING_TARGET 128 /* ECH cleartext padded to at least this */
# define OSSL_ECH_PADDING_INCREMENT 32 /* ECH padded to a multiple of this */

/*
 * To meet the needs of script-based tools (likely to deal with
 * base64 or ascii-hex encodings) and of libraries that might
 * handle binary values we supported various input formats for
 * encoded ECHConfigList API inputs:
 * - a binary (wireform) HTTPS/SVCB RRVALUE or just the ECHConfigList
 *   set of octets from that
 * - base64 encoded version of the above
 * - ascii-hex encoded version of the above
 * - DNS zone-file presentation-like format containing "ech=<b64-stuff>"
 * - we ccan also indicate the caller would like the library to guess
 *   which ecoding is being used
 *
 * This code supports catenated lists of such values (to make it easier
 * to feed values from scripts). Catenated binary values need no separator
 * as there is internal length information. Catenated ascii-hex or
 * base64 values need a separator semi-colon.
 *
 * All catenated values passed in a single call must use the same
 * encoding method.
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

# define OSSL_ECH_B64_SEPARATOR " "    /* separator str for b64 decode  */
# define OSSL_ECH_FMT_LINESEP   "\r\n" /* separator str for lines  */

/*
 * The wire-format type code for ECH/ECHConfiGList within an SVCB or HTTPS RR
 * value
 */
# define OSSL_ECH_PCODE_ECH 0x0005

/*
 * return values from ech_check_filenames() used to decide if a keypair
 * needs reloading or not
 */
# define OSSL_ECH_KEYPAIR_ERROR          0
# define OSSL_ECH_KEYPAIR_NEW            1
# define OSSL_ECH_KEYPAIR_UNMODIFIED     2
# define OSSL_ECH_KEYPAIR_MODIFIED       3
# define OSSL_ECH_KEYPAIR_FILEMISSING    4

/* Copy old->f (with length flen) to new->f (used in ECHConfig_dup() */
# define ECHFDUP(__f__, __flen__, __type__) \
    if (old->__flen__ != 0) { \
        new->__f__ = (__type__)ech_len_field_dup((__type__)old->__f__, \
                                                 old->__flen__); \
        if (new->__f__ == NULL) \
            return 0; \
    }

/* Map ascii to binary - utility macro used in ah_decode() */
# define LOCAL_A2B(__c__) (__c__ >= '0' && __c__ <= '9'  \
                           ? (__c__ - '0') \
                           : (__c__ >= 'A' && __c__ <= 'F' \
                              ? (__c__ - 'A' + 10) \
                              : (__c__ >= 'a' && __c__ <= 'f' \
                                 ? (__c__ - 'a' + 10) \
                                 : 0)))

/* SECTION: local vars */

/*
 * Strings used in ECH crypto derivations (odd format for EBCDIC goodness)
 */
/* "ech accept confirmation" */
static const char OSSL_ECH_ACCEPT_CONFIRM_STRING[] = "\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";
/* "hrr ech accept confirmation" */
static const char OSSL_ECH_HRR_CONFIRM_STRING[] = "\x68\x72\x72\x20\x65\x63\x68\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x6e\x66\x69\x72\x6d\x61\x74\x69\x6f\x6e";

/*
 * When doing ECH, this table specifies how we handle the encoding of
 * each extension type in the inner and outer ClientHello.
 *
 * If an extension constructor has side-effects then it is (in general)
 * unsafe to call twice. For others, we need to be able to call twice,
 * if we do want possibly different values in inner and outer, or if
 * the extension constructor is ECH-aware and handles side-effects
 * specially for inner and outer. If OTOH we want the inner to contain
 * a compressed form of the value in the outer we also need to signal
 * that.
 *
 * In general, if an extension constructor is ECH-aware then you ought
 * use the CALL_BOTH option. That currently (and perhaps unexpectedly)
 * includes early_data due to some side-effects of the first call being
 * specially handled in the 2nd. You should be able to select between
 * COMPRESS or DUPLICATE for any extension that's not CALL_BOTH below.
 *
 * Note that the set of COMPRESSed extensions in use for this TLS session
 * will be emitted first, in the order below, followed by those not
 * using COMPRESS, also in the order below. That means that changing
 * to/from COMPRESS for extensions will affect fingerprinting based on
 * the outer ClientHello. (That's because the compression mechanism for
 * ECH requires the compressed extensions to be a contiguous set in the
 * outer encoding.)
 *
 * DUPLICATE handling means one call to the constructor with the
 * value generated being in both inner and outer. There doesn't seem
 * to be much reason for preferring that to COMPRESS, but we keep
 * it, for now, anyway.
 *
 * The above applies to built-in extensions - all custom extensions
 * use COMPRESS handling, but that's not table-driven.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 *
 * These values may be better added as a field in ext_defs (in extensions.c).
 * TODO: merge those tables or not.
 */

/* possible values for handling field */
# define OSSL_ECH_HANDLING_CALL_BOTH 1 /* call constructor both times */
# define OSSL_ECH_HANDLING_COMPRESS  2 /* compress outer value into inner */
# define OSSL_ECH_HANDLING_DUPLICATE 3 /* same value in inner and outer */

/* defined in statem_local.h but also wanted here */
# ifndef TLSEXT_TYPE_cryptopro_bug
#  define TLSEXT_TYPE_cryptopro_bug 0xfde8
# endif

typedef struct {
    uint16_t type; /* the extension code point to record for compression */
    int handling; /* the handling to apply */
} ECH_EXT_HANDLING_DEF;

static const ECH_EXT_HANDLING_DEF ech_ext_handling[] = {
    { TLSEXT_TYPE_renegotiate, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_server_name, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_max_fragment_length, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_srp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_ec_point_formats, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_supported_groups, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_session_ticket, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_status_request, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_next_proto_neg, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_application_layer_protocol_negotiation,
      OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_use_srtp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_encrypt_then_mac, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_signed_certificate_timestamp, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_extended_master_secret, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_signature_algorithms_cert, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_post_handshake_auth, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_client_cert_type, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_server_cert_type, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_signature_algorithms, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_supported_versions, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_psk_kex_modes, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_key_share, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_cookie, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_cryptopro_bug, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_compress_certificate, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_early_data, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_certificate_authorities, OSSL_ECH_HANDLING_COMPRESS},
    { TLSEXT_TYPE_ech, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_outer_extensions, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_padding, OSSL_ECH_HANDLING_CALL_BOTH},
    { TLSEXT_TYPE_psk, OSSL_ECH_HANDLING_CALL_BOTH}
};

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

/* SECTION: Local functions */

/*
 * @brief Check if a key pair needs to be (re-)loaded or not
 * @param ctx is the SSL server context
 * @param pemfname is the PEM key filename
 * @param index is the index if we find a match
 * @return OSSL_ECH_KEYPAIR_*
 */
static int ech_check_filenames(SSL_CTX *ctx, const char *pemfname, int *index)
{
    struct stat pemstat;
    time_t pemmod;
    int ind = 0;
    size_t pemlen = 0;

    if (ctx == NULL || pemfname == NULL || index == NULL)
        return OSSL_ECH_KEYPAIR_ERROR;
    /* if we have none, then it is new */
    if (ctx->ext.ech == NULL || ctx->ext.nechs == 0)
        return OSSL_ECH_KEYPAIR_NEW;
    /*
     * if no file info, exit. That could happen if the disk fails hence
     * special return value - the application may be able to continue
     * anyway...
     */
    if (stat(pemfname, &pemstat) < 0)
        return OSSL_ECH_KEYPAIR_FILEMISSING;

    /* check the time info - we're only doing 1s precision on purpose */
# if defined(__APPLE__)
    pemmod = pemstat.st_mtimespec.tv_sec;
# elif defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
    pemmod = pemstat.st_mtime;
# else
    pemmod = pemstat.st_mtim.tv_sec;
# endif

    /*
     * search list of already loaded keys to see if we have
     * a macthing one already
     */
    pemlen = strlen(pemfname);
    for (ind = 0; ind != ctx->ext.nechs; ind++) {
        if (ctx->ext.ech[ind].pemfname == NULL)
            return OSSL_ECH_KEYPAIR_ERROR;
        if (pemlen == strlen(ctx->ext.ech[ind].pemfname)
            && !strncmp(ctx->ext.ech[ind].pemfname, pemfname, pemlen)) {
            /* matching files! */
            if (ctx->ext.ech[ind].loadtime < pemmod) {
                /* aha! load it up so */
                *index = ind;
                return OSSL_ECH_KEYPAIR_MODIFIED;
            } else {
                /* tell caller no need to bother */
                *index = -1; /* just in case:-> */
                return OSSL_ECH_KEYPAIR_UNMODIFIED;
            }
        }
    }
    *index = -1; /* just in case:-> */
    return OSSL_ECH_KEYPAIR_NEW;
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
static int local_decode_rdata_name(unsigned char **buf, size_t *remaining,
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
 * @param eklen is the length of rrval
 * @param rrval is encoded thing
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
static int ech_guess_fmt(size_t eklen, const unsigned char *rrval,
                         int *guessedfmt)
{
    size_t span = 0;
    char *dnsname = NULL;
    unsigned char *cp = NULL, *rdin = NULL;
    size_t remaining;

    /*
     * This could be more terse, but this is better for
     * debugging corner cases for now
     */
    if (guessedfmt == NULL || eklen == 0 || rrval == NULL)
        return 0;
    /*
     * check for binary encoding of an ECHConfigList that starts with a
     * two octet length and then our ECH extension codepoint
     */
    if (eklen <= 2)
        return 0;
    cp = OPENSSL_malloc(eklen + 1);
    if (cp == NULL)
        return 0;
    memcpy(cp, rrval, eklen);
    cp[eklen] = '\0'; /* make sure string funcs have a NUL terminator */
    /* TODO: replace * 256 with << 8 generally */
    if (eklen > 4
        && eklen == ((size_t)(cp[0]) * 256 + (size_t)(cp[1])) + 2
        && cp[3] == ((OSSL_ECH_RFCXXXX_VERSION / 256) & 0xff)
        && cp[4] == ((OSSL_ECH_RFCXXXX_VERSION % 256) & 0xff)) {
        *guessedfmt = OSSL_ECH_FMT_BIN;
        goto win;
    }
    if (eklen < strlen(unknownformat_telltale))
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
    if (eklen <= span) {
        *guessedfmt = OSSL_ECH_FMT_ASCIIHEX;
        goto win;
    }
    span = strspn((char *)cp, B64_alphabet);
    if (eklen <= span) {
        *guessedfmt = OSSL_ECH_FMT_B64TXT;
        goto win;
    }
    /*
     * check for HTTPS RR DNS wire format - we'll go with that if
     * the buffer starts with a two octet priority and then a
     * wire-format encoded DNS name
     */
    rdin = cp + 2;
    remaining = eklen - 2;
    if (local_decode_rdata_name(&rdin, &remaining, &dnsname) == 1) {
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
 * @brief decode ascii hex to a binary buffer
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 *
 * We skip spaces in the input, 'cause dig might put 'em there
 * We require that the input has an even number of nibbles i.e.
 * do left justify with a zero nibble if needed
 */
static int ah_decode(size_t ahlen, const char *ah,
                     size_t *blen, unsigned char **buf)
{
    size_t i = 0, j = 0;
    unsigned char *lbuf = NULL;

    if (ahlen < 2 || ah == NULL || blen == NULL || buf == NULL)
        return 0;
    lbuf = OPENSSL_malloc(ahlen / 2 + 1);
    if (lbuf == NULL)
        return 0;
    for (i = 0; i <= (ahlen - 1); i += 2) {
        if (ah[i] == ' ') {
            i--; /* because we increment by 2 */
            continue;
        }
        if (j >= (ahlen / 2 + 1)) {
            OPENSSL_free(lbuf);
            return 0;
        }
        lbuf[j++] = LOCAL_A2B(ah[i]) * 16 + LOCAL_A2B(ah[i + 1]);
    }
    *blen = j;
    *buf = lbuf;
    return 1;
}

/*
 * @brief encode binary buffer as ascii hex
 * @param out is an allocated buffer for the ascii hex string
 * @param outsize is the size of the buffer
 * @param in is the input binary buffer
 * @param inlen is the size of the binary buffer
 * @return 1 for good otherwise bad
 */
static int ah_encode(char *out, size_t outsize,
                     const unsigned char *in, size_t inlen)
{
    size_t i;

    if (outsize < 2 * inlen + 1)
        return 0;
    for (i = 0; i != inlen; i++) {
        uint8_t tn = (in[i] >> 4) & 0x0f;
        uint8_t bn = (in[i] & 0x0f);

        out[2 * i] = (tn < 10 ? tn + '0' : (tn - 10 + 'A'));
        out[2 * i + 1] = (bn < 10 ? bn + '0' : (bn - 10 + 'A'));
    }
    out[2 * i] = '\0';
    return 1;
}

/*
 * @brief helper to decode ECHConfig extensions
 * @param ec is the caller-allocated ECHConfig
 * @param exts is the binary form extensions
 * @return 1 for good, 0 for error
 *
 * On error, the caller will clean up ``ec`` so we don't do
 * all that here.
 */
static int ech_decode_echconfig_exts(ECHConfig *ec, PACKET *exts)
{
    unsigned int exttype = 0;
    unsigned int extlen = 0;
    unsigned char *extval = NULL;
    unsigned int *tip = NULL;
    unsigned int *lip = NULL;
    unsigned char **vip = NULL;

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
        tip = lip = NULL;
        vip = NULL;
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
        /* assign fields to lists, have to realloc */
        tip = (unsigned int *)OPENSSL_realloc(ec->exttypes, (ec->nexts + 1)
                                              * sizeof(ec->exttypes[0]));
        if (tip == NULL)
            goto err;
        ec->exttypes = tip;
        ec->exttypes[ec->nexts] = exttype;
        lip = (unsigned int *)OPENSSL_realloc(ec->extlens, (ec->nexts + 1)
                                              * sizeof(ec->extlens[0]));
        if (lip == NULL)
            goto err;
        ec->extlens = lip;
        ec->extlens[ec->nexts] = extlen;
        vip = (unsigned char **)OPENSSL_realloc(ec->exts, (ec->nexts + 1)
                                                * sizeof(unsigned char *));
        if (vip == NULL)
            goto err;
        ec->exts = vip;
        ec->exts[ec->nexts] = extval;
        ec->nexts += 1;
    }
    return 1;
err:
    OPENSSL_free(extval);
    return 0;
}

/*
 * @brief Check ECHConfig to see if locally supported
 * @param ec is the ECHConfig to check
 * @return 1 for yes, is supported, 0 otherwise
 */
static int ech_final_config_checks(ECHConfig *ec)
{
    OSSL_HPKE_SUITE hpke_suite;
    size_t ind = 0;
    int goodsuitefound = 0;
    unsigned char *es = NULL;
    uint16_t aead_id, kdf_id;

    /* check local support for some suite */
    hpke_suite.kem_id = ec->kem_id;
    for (ind = 0; ind != ec->nsuites; ind++) {
        es = (unsigned char *) &ec->ciphersuites[ind];
        kdf_id = es[0] * 256 + es[1];
        aead_id = es[2] * 256 + es[3];
        /*
         * suite_check says yes to the pseudo-aead for
         * export, but we don't want to see it here
         * coming from outside in an encoding
         */
        hpke_suite.aead_id = aead_id;
        hpke_suite.kdf_id = kdf_id;
        if (OSSL_HPKE_suite_check(hpke_suite) == 1
            && aead_id != OSSL_HPKE_AEAD_ID_EXPORTONLY) {
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
    for (ind = 0; ind != ec->nexts; ind++) {
        if (ec->exttypes[ind] & 0x8000) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ECH: Unsupported mandatory ECHConfig "
                           "extension (0x%04x)", ec->exttypes[ind]);
            } OSSL_TRACE_END(TLS);
            return 0;
        }
    }
    /* check public_name rules, as per draft section 4 */
    if (ec->public_name == NULL
        || ec->public_name_len == 0
        || ec->public_name[0] == '.'
        || ec->public_name[ec->public_name_len - 1] == '.')
        return 0;
    return 1;
}

/*
 * @brief Decode the first ECHConfigList from a binary buffer
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param ret_er NULL on error or no ECHConfig found, or a pointer to
 *         an ECHConfigList structure
 * @param new_echs returns the number of ECHConfig's found
 * @param leftover is the number of unused octets from the input
 * @return 1 for success, zero for error
 *
 * Note that new_echs can be zero at the end and that's not an error
 * if we got a well-formed ECHConfigList but that contained no
 * ECHConfig versions that we support
 */
static int ECHConfigList_from_binary(unsigned char *binbuf, size_t binblen,
                                     ECHConfigList **ret_er, int *new_echs,
                                     int *leftover)
{
    ECHConfigList *er = NULL; /* ECHConfigList record */
    ECHConfig *te = NULL; /* Array of ECHConfig to be embedded in that */
    int rind = 0, rv = 0;
    size_t remaining = 0, not_to_consume = 0;
    PACKET pkt;
    unsigned int olen = 0;
    unsigned char *skip = NULL;

    if (ret_er == NULL || new_echs == NULL || leftover == NULL
        || binbuf == NULL || binblen == 0
        || binblen < OSSL_ECH_MIN_ECHCONFIG_LEN
        || binblen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Overall length of this ECHConfigList (olen) still could be
     * less than the input buffer length, (binblen) if the caller has been
     * given a catenated set of binary buffers, which could happen
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
        ECHConfig *ec = NULL;
        unsigned int ech_content_length = 0;
        unsigned char *tmpecstart = NULL;
        const unsigned char *tmpecp = NULL;
        size_t tmpeclen = 0;

        te = OPENSSL_realloc(te, (rind + 1) * sizeof(ECHConfig));
        if (te == NULL)
            goto err;
        ec = &te[rind];
        memset(ec, 0, sizeof(ECHConfig));
        rind++;
        /* note start of encoding so we can make a copy later */
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1
            || !PACKET_get_net_2(&pkt, &ec->version)
            || !PACKET_get_net_2(&pkt, &ech_content_length)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
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
        switch (ec->version) {
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
            rind--;
            continue;
        }
        /*
         * This check's a bit redundant at the moment with only one version
         * But, when we (again) support >1 version, the indentation may end
         * up like this anyway so may as well keep it.
         */
        if (ec->version == OSSL_ECH_RFCXXXX_VERSION) {
            PACKET pub_pkt, cipher_suites, public_name_pkt, exts;
            int suiteoctets = 0, ci = 0;
            unsigned char cipher[OSSL_ECH_CIPHER_LEN], max_name_len;

            if (!PACKET_copy_bytes(&pkt, &ec->config_id, 1)
                || !PACKET_get_net_2(&pkt, &ec->kem_id)
                || !PACKET_get_length_prefixed_2(&pkt, &pub_pkt)
                || (ec->pub_len = PACKET_remaining(&pub_pkt)) == 0
                || (ec->pub = OPENSSL_malloc(ec->pub_len)) == NULL
                || !PACKET_copy_bytes(&pub_pkt, ec->pub, ec->pub_len)
                || !PACKET_get_length_prefixed_2(&pkt, &cipher_suites)
                || (suiteoctets = PACKET_remaining(&cipher_suites)) <= 0
                || (suiteoctets % 2) == 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->nsuites = suiteoctets / OSSL_ECH_CIPHER_LEN;
            ec->ciphersuites = OPENSSL_malloc(ec->nsuites
                                              * sizeof(ech_ciphersuite_t));
            if (ec->ciphersuites == NULL)
                goto err;
            while (PACKET_copy_bytes(&cipher_suites, cipher,
                                     OSSL_ECH_CIPHER_LEN))
                memcpy(ec->ciphersuites[ci++], cipher, OSSL_ECH_CIPHER_LEN);
            if (PACKET_remaining(&cipher_suites) > 0
                || !PACKET_copy_bytes(&pkt, &max_name_len, 1)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->maximum_name_length = max_name_len;
            if (!PACKET_get_length_prefixed_1(&pkt, &public_name_pkt)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ec->public_name_len = PACKET_remaining(&public_name_pkt);
            if (ec->public_name_len != 0) {
                if (ec->public_name_len < TLSEXT_MINLEN_host_name ||
                    ec->public_name_len > TLSEXT_MAXLEN_host_name) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ec->public_name = OPENSSL_malloc(ec->public_name_len + 1);
                if (ec->public_name == NULL)
                    goto err;
                if (PACKET_copy_bytes(&public_name_pkt, ec->public_name,
                                      ec->public_name_len) != 1) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                ec->public_name[ec->public_name_len] = '\0';
            }
            if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (PACKET_remaining(&exts) > 0
                && ech_decode_echconfig_exts(ec, &exts) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* do final checks on suites, exts, and skip this one if issues */
            if (ech_final_config_checks(ec) != 1) {
                ECHConfig_free(ec);
                rind--;
                continue;
            }
        }
        /* set length of encoding of this ECHConfig */
        ec->encoding_start = (unsigned char *)tmpecp;
        tmpeclen = PACKET_remaining(&pkt);
        if (PACKET_peek_bytes(&pkt, &tmpecp, tmpeclen) != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ec->encoding_length = tmpecp - ec->encoding_start;
        /* copy encoding_start as it might get free'd if a reduce happens */
        tmpecstart = OPENSSL_malloc(ec->encoding_length);
        if (tmpecstart == NULL) {
            ec->encoding_start = NULL; /* don't free twice in this case */
            goto err;
        }
        memcpy(tmpecstart, ec->encoding_start, ec->encoding_length);
        ec->encoding_start = tmpecstart;
        remaining = PACKET_remaining(&pkt);
    }
    /* Success - make up return value */
    *new_echs = rind;
    *leftover = PACKET_remaining(&pkt);
    if (rind == 0) {
        rv = 1; /* return success but free stuff */
        goto err;
    }
    er = (ECHConfigList *)OPENSSL_malloc(sizeof(ECHConfigList));
    if (er == NULL)
        goto err;
    memset(er, 0, sizeof(ECHConfigList));
    er->nrecs = rind;
    er->recs = te;
    te = NULL;
    er->encoded_len = binblen;
    er->encoded = OPENSSL_malloc(binblen);
    if (er->encoded == NULL)
        goto err;
    memcpy(er->encoded, binbuf, binblen);
    *ret_er = er;
    return 1;
err:
    ECHConfigList_free(er);
    OPENSSL_free(er);
    if (te != NULL) {
        int teind;

        for (teind = 0; teind != rind; teind++)
            ECHConfig_free(&te[teind]);
        OPENSSL_free(te);
    }
    return rv;
}

/*
 * @brief decode and flatten a binary encoded ECHConfigList
 * @param nechs_in in/out number of ECHConfig's in play
 * @param retech_in in/out array of SSL_ECH
 * @param binbuf binary encoded ECHConfigList (we hope)
 * @param binlen length of binbuf
 * @return 1 for success, 0 for error
 *
 * We may only get one ECHConfig, per list, but there can be more.
 * We want each element of the output SSL_ECH array to contain
 * exactly one ECHConfig so that a client could sensibly down
 * select to the one they prefer later, and so that we have the
 * specific encoded value of that ECHConfig for inclusion in the
 * HPKE info parameter when finally encrypting or decrypting an
 * inner ClientHello.
 */
static int ech_decode_and_flatten(int *nechs_in, SSL_ECH **retech_in,
                                  unsigned char *binbuf, size_t binlen)
{
    ECHConfigList *er = NULL;
    SSL_ECH *ts = NULL;
    int new_echs = 0;
    int leftover = 0;
    int cfgind;
    size_t nechs = *nechs_in;
    SSL_ECH *retech = *retech_in;

    if (ECHConfigList_from_binary(binbuf, binlen,
                                  &er, &new_echs, &leftover) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (new_echs == 0) {
        return 1;
    }
    ts = OPENSSL_realloc(retech, (nechs + er->nrecs) * sizeof(SSL_ECH));
    if (ts == NULL)
        goto err;
    retech = ts;
    for (cfgind = 0; cfgind != er->nrecs; cfgind++) {
        ECHConfig *ec = NULL;

        /*
         * inner and/or outer name and no_outer could have been set
         * via API as ECHConfigList values are being accumulated, e.g.
         * from a multivalued DNS RRset - that'd not be clever, or
         * common, but is possible, so we better copy such
         */
        if (nechs > 0 && retech[nechs - 1].inner_name != NULL) {
            retech[nechs + cfgind].inner_name =
                OPENSSL_strdup(retech[nechs - 1].inner_name);
            if (retech[nechs + cfgind].inner_name == NULL)
                goto err;
        } else {
            retech[nechs + cfgind].inner_name = NULL;
        }
        if (nechs > 0 && retech[nechs - 1].outer_name != NULL) {
            retech[nechs + cfgind].outer_name =
                OPENSSL_strdup(retech[nechs - 1].outer_name);
            if (retech[nechs + cfgind].outer_name == NULL)
                goto err;
        } else {
            retech[nechs + cfgind].outer_name = NULL;
        }
        if (nechs > 0) {
            retech[nechs + cfgind].no_outer = retech[nechs - 1].no_outer;
        } else {
            retech[nechs + cfgind].no_outer = 0;
        }
        /* next 3 fields are really only used when private key present */
        retech[nechs + cfgind].pemfname = NULL;
        retech[nechs + cfgind].loadtime = 0;
        retech[nechs + cfgind].for_retry = SSL_ECH_NOT_FOR_RETRY;
        retech[nechs + cfgind].keyshare = NULL;
        retech[nechs + cfgind].cfg =
            OPENSSL_malloc(sizeof(ECHConfigList));
        if (retech[nechs + cfgind].cfg == NULL)
            goto err;
        retech[nechs + cfgind].cfg->nrecs = 1;
        ec = OPENSSL_malloc(sizeof(ECHConfig));
        if (ec == NULL)
            goto err;
        *ec = er->recs[cfgind];
        /* avoid double free */
        memset(&er->recs[cfgind], 0, sizeof(ECHConfig));
        /* shallow copy is correct on next line */
        retech[nechs + cfgind].cfg->recs = ec;
        retech[nechs + cfgind].cfg->encoded_len =
            er->encoded_len;
        retech[nechs + cfgind].cfg->encoded =
            OPENSSL_malloc(er->encoded_len);
        if (retech[nechs + cfgind].cfg->encoded == NULL)
            goto err;
        memcpy(retech[nechs + cfgind].cfg->encoded,
               er->encoded, er->encoded_len);
    }
    *nechs_in += er->nrecs;
    *retech_in = retech;
    ECHConfigList_free(er);
    OPENSSL_free(er);
    return 1;
err:
    ECHConfigList_free(er);
    OPENSSL_free(er);
    return 0;
}

/*
 * @brief Decode/check the value from DNS (binary, base64 or ascii-hex encoded)
 * @param len length of the binary, base64 or ascii-hex encoded value from DNS
 * @param val is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_ech_add(int ekfmt, size_t len, const unsigned char *val,
                         int *num_echs, SSL_ECH **echs)
{
    int detfmt = OSSL_ECH_FMT_GUESS;
    int rv = 0;
    unsigned char *outbuf = NULL; /* sequence of ECHConfigList (binary) */
    size_t declen = 0; /* length of the above */
    char *ekptr = NULL;
    unsigned char *ekcpy = NULL;
    int nlens = 0;
    SSL_ECH *retechs = NULL;
    const unsigned char *ekval = val;
    size_t eklen = len;

    if (len == 0 || val == NULL || num_echs == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (eklen >= OSSL_ECH_MAX_ECHCONFIG_LEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ekfmt != OSSL_ECH_FMT_GUESS) {
        detfmt = ekfmt;
    } else {
        rv = ech_guess_fmt(eklen, ekval, &detfmt);
        if (rv == 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    switch (detfmt) {
    case OSSL_ECH_FMT_ASCIIHEX:
    case OSSL_ECH_FMT_B64TXT:
    case OSSL_ECH_FMT_BIN:
        break;
        /* not supported here */
    case OSSL_ECH_FMT_GUESS:
    case OSSL_ECH_FMT_HTTPSSVC:
    case OSSL_ECH_FMT_HTTPSSVC_NO_ECH:
    case OSSL_ECH_FMT_DIG_UNK:
    case OSSL_ECH_FMT_DNS_WIRE:
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Do the various decodes on a copy of ekval */
    ekcpy = OPENSSL_malloc(eklen + 1);
    if (ekcpy == NULL)
        return 0;
    memcpy(ekcpy, ekval, eklen);
    ekcpy[eklen] = 0x00; /* a NUL in case of string value */
    ekptr = (char *)ekcpy;

    if (detfmt == OSSL_ECH_FMT_B64TXT) {
        int tdeclen = 0;

        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        tdeclen = ech_helper_base64_decode(ekptr, eklen, &outbuf);
        if (tdeclen <= 0) { /* need an int to get -1 return */
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        declen = tdeclen;
    }
    if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
        int adr = 0;

        if (strlen((char *)ekcpy) != eklen) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        adr = ah_decode(eklen, ekptr, &declen, &outbuf);
        if (adr == 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (detfmt == OSSL_ECH_FMT_BIN) {
        /* just copy over the input to where we'd expect it */
        declen = eklen;
        outbuf = OPENSSL_malloc(declen);
        if (outbuf == NULL)
            goto err;
        memcpy(outbuf, ekptr, declen);
    }
    if (ech_decode_and_flatten(&nlens, &retechs, outbuf, declen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (nlens > 0 && *num_echs == 0) {
        *num_echs = nlens;
        *echs = retechs;
    } else if (nlens > 0) {
        SSL_ECH *tech = NULL;

        tech = OPENSSL_realloc(*echs, (nlens + *num_echs) * sizeof(SSL_ECH));
        if (tech == NULL)
            goto err;
        memcpy(*echs + *num_echs * sizeof(SSL_ECH),
               retechs, nlens * sizeof(SSL_ECH));
        *num_echs += nlens;
    }
    OPENSSL_free(ekcpy);
    OPENSSL_free(outbuf);
    ekcpy = NULL;
    return 1;
err:
    OPENSSL_free(outbuf);
    OPENSSL_free(ekcpy);
    SSL_ECH_free(retechs);
    OPENSSL_free(retechs);
    return 0;
}

/*
 * @brief find ECH values inside various encodings
 * @param num_echs (ptr to) number of ECHConfig values found
 * @param echs (ptr to) array if ECHConfig values
 * @param len is the length of the encoding
 * @param val is the encoded value
 *
 * We support the various OSSL_ECH_FMT_* type formats
 */
static int ech_finder(int *num_echs, SSL_ECH **echs,
                      size_t len, const unsigned char *val)
{
    int rv = 0, detfmt = OSSL_ECH_FMT_GUESS, origfmt;
    int multiline = 0, linesdone = 0, nechs = 0, nonehere = 0, tdeclen = 0;
    unsigned char *lval = (unsigned char *)val, *binbuf = NULL;
    size_t llen = len, binlen = 0, linelen = 0, slen = 0, ldiff = 0;
    SSL_ECH *retech = NULL, *tech = NULL;
    char *dnsname = NULL, *tmp = NULL, *lstr = NULL;

    if (ech_guess_fmt(len, val, &detfmt) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC_NO_ECH)
        return 1;
    origfmt = detfmt;
    if (detfmt == OSSL_ECH_FMT_HTTPSSVC || detfmt == OSSL_ECH_FMT_DIG_UNK)
        multiline = 1;
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
            binbuf = OPENSSL_malloc(len); /* copy buffer if binary format */
            if (binbuf == NULL)
                goto err;
            memcpy(binbuf, val, len);
            binlen = len;
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
                || ah_decode(llen - ldiff, (char *)lval + ldiff,
                             &binlen, &binbuf) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            detfmt = OSSL_ECH_FMT_DNS_WIRE;
        }
        if (detfmt == OSSL_ECH_FMT_ASCIIHEX) {
            /* AH decode and fall throught to DNS wire or binary */
            if (ah_decode(llen, (char *)lval, &binlen, &binbuf) != 1
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
            if (local_decode_rdata_name(&cp, &remaining, &dnsname) != 1) {
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
            char *ekstart = NULL; /* find telltale and fall through to b64 */

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
            tdeclen = ech_helper_base64_decode((char *)lval, llen, &binbuf);
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
            if (ech_decode_and_flatten(&nechs, &retech, binbuf, binlen) != 1) {
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
    if (*num_echs == 0) {
        *num_echs = nechs;
        *echs = retech;
    } else {
        tech = OPENSSL_realloc(*echs, (nechs + *num_echs) * sizeof(SSL_ECH));
        if (tech == NULL)
            goto err;
        memcpy(*echs + *num_echs * sizeof(SSL_ECH), retech,
               nechs * sizeof(SSL_ECH));
        *num_echs += nechs;
    }
    rv = 1;
err:
    OPENSSL_free(dnsname);
    OPENSSL_free(binbuf);
    if (rv == 0) {
        SSL_ECH_free_arr(retech, nechs);
        OPENSSL_free(retech);
    }
    return rv;
}

/*
 * @brief add GREASEy ECHConfig values to a set loaded by a server
 * @param ctx is the SSL context
 * @param num_echs is the number of SSL_ECH in the array
 * @return 1 for good zero for error
 */
static int ech_grease_retry_configs(SSL_CTX *ctx, int num_echs, SSL_ECH **sechs)
{
    /*
     * we'll start simple and just add a fixed bogus ECHConfig
     * with an unknown version to the start of the encoded value
     * of each of the real ECHConfig values.
     */
    SSL_ECH *se = NULL;
    int i;
    size_t encilen = 0;
    unsigned char *tmp = NULL;
    unsigned char firstcut[] = {
        0xfe, 0x09, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x0E, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    for (i = 0; i != num_echs; i++) {
        se = sechs[i];
        if (se != NULL && se->cfg != NULL) {
            encilen = se->cfg->encoded_len;
            if (encilen < 2)
                goto err;
            tmp = (unsigned char *)OPENSSL_realloc(se->cfg->encoded,
                                                   sizeof(firstcut) + encilen);
            if (tmp == NULL)
                goto err;
            se->cfg->encoded = tmp;
            memcpy(se->cfg->encoded + 2 + sizeof(firstcut),
                   se->cfg->encoded + 2, encilen - 2);
            memcpy(se->cfg->encoded + 2, firstcut, sizeof(firstcut));
            se->cfg->encoded_len = encilen + sizeof(firstcut);
            se->cfg->encoded[0] = (se->cfg->encoded_len % 0xffff) >> 8;
            se->cfg->encoded[1] = se->cfg->encoded_len % 0xff;
        }
    }
    return 1;
err:
    return 0;
}

/*
 * @brief read ECHConfigList (with only 1 entry) and private key from a file
 * @param pemfile is the name of the file
 * @param ctx is the SSL context
 * @param inputIsFile is 1 if input a filename, 0 if a buffer
 * @param input is the filename or buffer
 * @param inlen is the length of input
 * @param sechs an (output) pointer to the SSL_ECH output
 * @return 1 for success, otherwise error
 *
 * The file content should look as below. Note that as github barfs
 * if I provide an actual private key in PEM format, I've reversed
 * the string PRIVATE in the PEM header and added a line-feed;-)
 *
 * -----BEGIN ETAVRIP KEY-----
 * MC4CAQAwBQYDK2VuBCIEIEiVgUq4FlrMNX3lH5osEm1yjqtVcQfeu3hY8VOFortE
 * -----END ETAVRIP KEY-----
 * -----BEGIN ECHCONFIG-----
 * AEP/CQBBAAtleGFtcGxlLmNvbQAkAB0AIF8i/TRompaA6Uoi1H3xqiqzq6IuUqFT
 * 2GNT4wzWmF6ACAABAABAAEAAAAA
 * -----END ECHCONFIG-----
 *
 * There are two sensible ways to call this, either supply just a
 * filename (and inputIsFile=1) or else provide a pesudo-filename,
 * a buffer and the buffer length with inputIsFile=0. The buffer
 * should have contents like the PEM strings above.
 *
 */
static int ech_readpemfile(SSL_CTX *ctx, int inputIsFile, const char *pemfile,
                           const unsigned char *input, size_t inlen,
                           SSL_ECH **sechs, int for_retry)
{
    BIO *pem_in = NULL;
    char *pname = NULL;
    char *pheader = NULL;
    unsigned char *pdata = NULL;
    long plen = 0;
    EVP_PKEY *priv = NULL;
    int num_echs = 0;

    if (ctx == NULL || sechs == NULL)
        return 0;
    switch (inputIsFile) {
    case 1:
        if (pemfile == NULL || strlen(pemfile) == 0)
            return 0;
        break;
    case 0:
        if (input == NULL || inlen == 0)
            return 0;
        break;
    default:
        return 0;
    }
    if (inputIsFile == 1) {
        pem_in = BIO_new(BIO_s_file());
        if (pem_in == NULL)
            goto err;
        if (BIO_read_filename(pem_in, pemfile) <= 0)
            goto err;
    } else {
        pem_in = BIO_new(BIO_s_mem());
        if (pem_in == NULL)
            goto err;
        if (BIO_write(pem_in, (void *)input, (int)inlen) <= 0)
            goto err;
    }
    /* Now check and parse inputs */
    if (PEM_read_bio_PrivateKey(pem_in, &priv, NULL, NULL) == 0)
        goto err;
    if (priv == NULL)
        goto err;
    if (PEM_read_bio(pem_in, &pname, &pheader, &pdata, &plen) <= 0)
        goto err;
    if (pname == NULL || strlen(pname) == 0)
        goto err;
    if (strncmp(PEM_STRING_ECHCONFIG, pname, strlen(pname)))
        goto err;
    OPENSSL_free(pname);
    pname = NULL;
    OPENSSL_free(pheader);
    pheader = NULL;
    if (plen >= OSSL_ECH_MAX_ECHCONFIG_LEN || plen < OSSL_ECH_MIN_ECHCONFIG_LEN)
        goto err;
    BIO_free(pem_in);
    pem_in = NULL;
    /* Now decode that ECHConfigList */
    if (local_ech_add(OSSL_ECH_FMT_GUESS, plen, pdata, &num_echs, sechs) != 1)
        goto err;
    /* if the server is set to GREASE retry_configs then we do that now */
    if (ctx->options & SSL_OP_ECH_GREASE_RETRY_CONFIG
        && for_retry
        && ech_grease_retry_configs(ctx, num_echs, sechs) != 1)
            goto err;
    (*sechs)->pemfname = OPENSSL_strdup(pemfile);
    (*sechs)->loadtime = time(0);
    (*sechs)->for_retry = for_retry;
    (*sechs)->keyshare = priv;
    OPENSSL_free(pheader);
    OPENSSL_free(pname);
    OPENSSL_free(pdata);
    return 1;

err:
    EVP_PKEY_free(priv);
    OPENSSL_free(pheader);
    OPENSSL_free(pname);
    OPENSSL_free(pdata);
    BIO_free(pem_in);
    SSL_ECH_free(*sechs);
    OPENSSL_free(*sechs);
    return 0;
}

/*
 * @brief utility field-copy fnc used by ECHFDUP macro and ECHConfig_dup
 * @param old is the source buffer
 * @param len is the source buffer size
 * @return is NULL or the copied buffer
 *
 * Copy a field old->foo based on old->foo_len to new->foo
 * We allocate one extra octet in case the value is a
 * string and NUL that out.
 */
static void *ech_len_field_dup(void *old, unsigned int len)
{
    void *new = NULL;

    if (old == NULL || len == 0)
        return NULL;
    new = (void *)OPENSSL_malloc(len + 1);
    if (new == NULL)
        return NULL;
    memcpy(new, old, len);
    memset((unsigned char *)new + len, 0, 1);
    return new;
}

/*
 * @brief deep copy an ECHConfig
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfig_dup(ECHConfig *old, ECHConfig *new)
{
    unsigned int i = 0;

    if (new == NULL || old == NULL)
        return 0;
    *new = *old; /* shallow copy, followed by deep copies */
    /* but before deep copy make sure we don't free twice */
    new->ciphersuites = NULL;
    new->exttypes = NULL;
    new->extlens = NULL;
    new->exts = NULL;
    ECHFDUP(pub, pub_len, unsigned char *);
    ECHFDUP(public_name, public_name_len, unsigned char *);
    new->config_id = old->config_id;
    ECHFDUP(encoding_start, encoding_length, unsigned char *);
    if (old->ciphersuites) {
        new->ciphersuites = OPENSSL_malloc(old->nsuites
                                           * sizeof(ech_ciphersuite_t));
        if (new->ciphersuites == NULL)
            goto err;
        memcpy(new->ciphersuites, old->ciphersuites,
               old->nsuites * sizeof(ech_ciphersuite_t));
    }
    if (old->nexts != 0) {
        new->exttypes = OPENSSL_malloc(old->nexts * sizeof(old->exttypes[0]));
        if (new->exttypes == NULL)
            goto err;
        memcpy(new->exttypes, old->exttypes,
               old->nexts * sizeof(old->exttypes[0]));
        new->extlens = OPENSSL_malloc(old->nexts * sizeof(old->extlens[0]));
        if (new->extlens == NULL)
            goto err;
        memcpy(new->extlens, old->extlens,
               old->nexts * sizeof(old->extlens[0]));
        new->exts = OPENSSL_zalloc(old->nexts * sizeof(old->exts[0]));
        if (new->exts == NULL)
            goto err;
    }
    for (i = 0; i != old->nexts; i++) {
        /* old extension might have no value */
        if (old->extlens[i] > 0) {
            new->exts[i] = OPENSSL_malloc(old->extlens[i]);
            if (new->exts[i] == NULL)
                goto err;
            memcpy(new->exts[i], old->exts[i], old->extlens[i]);
        } else {
            new->exts[i] = NULL;
        }
    }
    return 1;
err:
    ECHConfig_free(new);
    return 0;
}

/*
 * @brief deep copy an ECHConfigList
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfigList_dup(ECHConfigList *old, ECHConfigList *new)
{
    int i = 0;

    if (new == NULL || old == NULL)
        return 0;
    if (old->encoded_len != 0) {
        new->encoded = (unsigned char *)ech_len_field_dup((void *)old->encoded,
                                                          old->encoded_len);
        if (new->encoded == NULL)
            return 0;
        new->encoded_len = old->encoded_len;
    }
    new->recs = OPENSSL_malloc(old->nrecs * sizeof(ECHConfig));
    if (new->recs == NULL)
        return 0;
    new->nrecs = old->nrecs;
    memset(new->recs, 0, old->nrecs * sizeof(ECHConfig));
    for (i = 0; i != old->nrecs; i++)
        if (ECHConfig_dup(&old->recs[i], &new->recs[i]) != 1)
            return 0;
    return 1;
}

/*
 * @brief return a printable form of alpn
 * @param alpn is the buffer with alpns
 * @param len is the length of the above
 * @return buffer with string-form (caller has to free)
 *
 * ALPNs are multi-valued, with lengths between, we
 * map that to a comma-sep list
 */
static char *alpn_print(unsigned char *alpn, size_t len)
{
    size_t ind = 0;
    char *vstr = NULL;

    if (alpn == NULL || len == 0)
        return NULL;
    if (len > OSSL_ECH_MAX_ALPNLEN)
        return NULL;
    vstr = OPENSSL_malloc(len + 1);
    if (vstr == NULL)
        return NULL;
    while (ind < len) {
        size_t vlen = alpn[ind];

        if (ind + vlen > (len - 1))
            return NULL;
        memcpy(&vstr[ind], &alpn[ind + 1], vlen);
        vstr[ind + vlen] = ',';
        ind += (vlen + 1);
    }
    vstr[len - 1] = '\0';
    return vstr;
}

/*
 * @brief produce a printable string-form of an ECHConfigList
 * @param out is where we print
 * @param c is the ECHConfigList
 * @return 1 for good, 0 for fail
 */
static int ECHConfigList_print(BIO *out, ECHConfigList *c)
{
    int i;
    unsigned int j;

    if (out == NULL || c == NULL || c->recs == NULL)
        return 0;
    for (i = 0; i != c->nrecs; i++) {
        if (c->recs[i].version != OSSL_ECH_RFCXXXX_VERSION) {
            /* just note we don't support that one today */
            BIO_printf(out, "[Unsupported version (%04x)]", c->recs[i].version);
            continue;
        }
        /* version, config_id, public_name, and kem */
        BIO_printf(out, "[%04x,%02x,%s,%04x,[", c->recs[i].version,
                   c->recs[i].config_id,
                   c->recs[i].public_name != NULL
                       ? (char *)c->recs[i].public_name
                       : "NULL",
                   c->recs[i].kem_id);
        /* ciphersuites */
        for (j = 0; j != c->recs[i].nsuites; j++) {
            unsigned char *es = (unsigned char *)&c->recs[i].ciphersuites[j];
            uint16_t kdf_id = es[0] * 256 + es[1];
            uint16_t aead_id = es[2] * 256 + es[3];

            BIO_printf(out, "%04x,%04x", kdf_id, aead_id);
            if (j < (c->recs[i].nsuites - 1)) {
                BIO_printf(out, ",");
            }
        }
        BIO_printf(out, "],");
        /* public key */
        for (j = 0; j != c->recs[i].pub_len; j++)
            BIO_printf(out, "%02x", c->recs[i].pub[j]);
        /* max name length and (only) number of extensions */
        BIO_printf(out, ",%02x,%02x]", c->recs[i].maximum_name_length,
                   c->recs[i].nexts);
    }
    return 1;
}

/*!
 * @brief Given a CH find the offsets of the session id, extensions and ECH
 * @param: s is the SSL connection
 * @param: pkt is the CH
 * @param: sessid points to offset of session_id length
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @param: inner 1 if the ECH is marked as an inner, 0 for outer
 * @param: snioffset points to offset of (outer) SNI
 * @return 1 for success, other otherwise
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * Note: input here is untrusted!
 */
int ech_get_ch_offsets(SSL_CONNECTION *s, PACKET *pkt, size_t *sessid,
                       size_t *exts, size_t *echoffset, uint16_t *echtype,
                       int *inner, size_t *snioffset)
{
    const unsigned char *ch = NULL;
    size_t ch_len = 0, extlens = 0, snilen = 0, echlen = 0;

    if (s == NULL || pkt == NULL || sessid == NULL || exts == NULL
        || echoffset == NULL || echtype == NULL || inner == NULL
        || snioffset == NULL)
        return 0;
    *sessid = 0;
    *exts = 0;
    *echoffset = 0;
    *echtype = TLSEXT_TYPE_ech_unknown;
    *snioffset = 0;
    ch_len = PACKET_remaining(pkt);
    if (PACKET_peek_bytes(pkt, &ch, ch_len) != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (ech_helper_get_ch_offsets(ch, ch_len, sessid, exts, &extlens,
                                  echoffset, echtype, &echlen,
                                  snioffset, &snilen, inner) != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "orig CH/ECH type: %4x\n", *echtype);
    } OSSL_TRACE_END(TLS);
    ech_pbuf("orig CH", (unsigned char *)ch, ch_len);
    ech_pbuf("orig CH exts", (unsigned char *)ch + *exts, extlens);
    ech_pbuf("orig CH/ECH", (unsigned char *)ch + *echoffset, echlen);
    ech_pbuf("orig CH SNI", (unsigned char *)ch + *snioffset, snilen);
# endif
    return 1;
}

/*!
 * Given a SH (or HRR) find the offsets of the ECH (if any)
 * @param: sh is the SH buffer
 * @paramL sh_len is the length of the SH
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @return 1 for success, other otherwise
 *
 * Offsets are returned to the type or length field in question.
 * Offsets are set to zero if relevant thing not found.
 *
 * Note: input here is untrusted!
 */
static int ech_get_sh_offsets(const unsigned char *sh, size_t sh_len,
                              size_t *exts, size_t *echoffset,
                              uint16_t *echtype)
{
    return ech_helper_get_sh_offsets(sh, sh_len, exts, echoffset, echtype);
}

/*
 * @brief find outers if any, and do initial checks
 * @param s is the SSL connection
 * @param pkt is the encoded inner
 * @param outers is the array of outer ext types
 * @param n_outers is the number of outers found
 * @return 1 for good, 0 for error
 *
 * recall we're dealing with recovered ECH plaintext here so
 * the content must be a TLSv1.3 ECH encoded inner
 */
static int ech_find_outers(SSL_CONNECTION *s, PACKET *pkt,
                           uint16_t *outers, size_t *n_outers)
{
    const unsigned char *pp_tmp;
    unsigned int pi_tmp, extlens, etype, elen, olen;
    int outers_found = 0;
    size_t i;
    PACKET op;

    PACKET_null_init(&op);
    /* chew up the packet to extensions */
    if (!PACKET_get_net_2(pkt, &pi_tmp)
        || pi_tmp != TLS1_2_VERSION
        || !PACKET_get_bytes(pkt, &pp_tmp, SSL3_RANDOM_SIZE)
        || !PACKET_get_1(pkt, &pi_tmp)
        || pi_tmp != 0x00 /* zero'd session id */
        || !PACKET_get_net_2(pkt, &pi_tmp) /* ciphersuite len */
        || !PACKET_get_bytes(pkt, &pp_tmp, pi_tmp) /* suites */
        || !PACKET_get_1(pkt, &pi_tmp) /* compression meths */
        || pi_tmp != 0x01 /* 1 octet of comressions */
        || !PACKET_get_1(pkt, &pi_tmp) /* compression meths */
        || pi_tmp != 0x00 /* 1 octet of no comressions */
        || !PACKET_get_net_2(pkt, &extlens) /* len(extensions) */
        || extlens == 0) { /* no extensions! */
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    while (PACKET_remaining(pkt) > 0 && outers_found == 0) {
        if (!PACKET_get_net_2(pkt, &etype)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (etype == TLSEXT_TYPE_outer_extensions) {
            outers_found = 1;
            if (!PACKET_get_length_prefixed_2(pkt, &op)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        } else { /* skip over */
            if (!PACKET_get_net_2(pkt, &elen)
                || !PACKET_get_bytes(pkt, &pp_tmp, elen)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        }
    }

    if (outers_found == 0) { /* which is fine! */
        *n_outers = 0;
        return 1;
    }
    /*
     * outers has a silly internal length as well and that betterk
     * be one less than the extension length and an even number
     * and we only support a certain max of outers
     */
    if (!PACKET_get_1(&op, &olen)
        || olen % 2 == 1
        || olen / 2 > OSSL_ECH_OUTERS_MAX) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    *n_outers = olen / 2;
    for (i = 0; i != *n_outers; i++) {
        if (!PACKET_get_net_2(&op, &pi_tmp)
            || pi_tmp == TLSEXT_TYPE_outer_extensions) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        outers[i] = (uint16_t) pi_tmp;
    }
    return 1;
err:
    return 0;
}

/*
 * @brief copy one extension from outer to inner
 * @param s is the SSL connection
 * @param di is the reconstituted inner CH
 * @param type2copy is the outer type to copy
 * @param extsbuf is the outer extensions buffer
 * @param extslen is the outer extensions buffer length
 * @return 1 for good 0 for error
 */
static int ech_copy_ext(SSL_CONNECTION *s, WPACKET *di, uint16_t type2copy,
                        const unsigned char *extsbuf, size_t extslen)
{
    PACKET exts;
    unsigned int etype, elen;
    const unsigned char *eval;

    if (PACKET_buf_init(&exts, extsbuf, extslen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    while (PACKET_remaining(&exts) > 0) {
        if (!PACKET_get_net_2(&exts, &etype)
            || !PACKET_get_net_2(&exts, &elen)
            || !PACKET_get_bytes(&exts, &eval, elen)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (etype == type2copy) {
            if (!WPACKET_put_bytes_u16(di, etype)
                || !WPACKET_put_bytes_u16(di, elen)
                || !WPACKET_memcpy(di, eval, elen)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
            return 1;
        }
    }
    /* we didn't find such an extension - that's an error */
    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
err:
    return 0;
}

/*
 * @brief reconstitute the inner CH from encoded inner and outers
 * @param s is the SSL connection
 * @param di is the reconstituted inner CH
 * @param ei is the encoded inner
 * @param ob is the outer CH as a buffer
 * @param ob_len is the size of the above
 * @param outers is the array of outer ext types
 * @param n_outers is the number of outers found
 * @return 1 for good, 0 for error
 */
static int ech_reconstitute_inner(SSL_CONNECTION *s, WPACKET *di, PACKET *ei,
                                  const unsigned char *ob, size_t ob_len,
                                  uint16_t *outers, size_t n_outers)
{
    const unsigned char *pp_tmp, *eval, *outer_exts;
    unsigned int pi_tmp, etype, elen, outer_extslen;
    PACKET outer, session_id;
    size_t i;

    if (PACKET_buf_init(&outer, ob, ob_len) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* read/write from encoded inner to decoded inner with help from outer */
    if (/* version */
        !PACKET_get_net_2(&outer, &pi_tmp)
        || !PACKET_get_net_2(ei, &pi_tmp)
        || !WPACKET_put_bytes_u16(di, pi_tmp)

        /* client random */
        || !PACKET_get_bytes(&outer, &pp_tmp, SSL3_RANDOM_SIZE)
        || !PACKET_get_bytes(ei, &pp_tmp, SSL3_RANDOM_SIZE)
        || !WPACKET_memcpy(di, pp_tmp, SSL3_RANDOM_SIZE)

        /* session ID */
        || !PACKET_get_1(ei, &pi_tmp)
        || !PACKET_get_length_prefixed_1(&outer, &session_id)
        || !WPACKET_start_sub_packet_u8(di)
        || (PACKET_remaining(&session_id) != 0
            && !WPACKET_memcpy(di, PACKET_data(&session_id),
               PACKET_remaining(&session_id)))
        || !WPACKET_close(di)

        /* ciphersuites */
        || !PACKET_get_net_2(&outer, &pi_tmp) /* ciphersuite len */
        || !PACKET_get_bytes(&outer, &pp_tmp, pi_tmp) /* suites */
        || !PACKET_get_net_2(ei, &pi_tmp) /* ciphersuite len */
        || !PACKET_get_bytes(ei, &pp_tmp, pi_tmp) /* suites */
        || !WPACKET_put_bytes_u16(di, pi_tmp)
        || !WPACKET_memcpy(di, pp_tmp, pi_tmp)

        /* compression len & meth */
        || !PACKET_get_net_2(ei, &pi_tmp)
        || !PACKET_get_net_2(&outer, &pi_tmp)
        || !WPACKET_put_bytes_u16(di, pi_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /* handle simple, but unlikely, case first */
    if (n_outers == 0) {
        if (PACKET_remaining(ei) == 0)
            return 1; /* no exts is theoretically possible */
        if (!PACKET_get_net_2(ei, &pi_tmp) /* len(extensions) */
            || !PACKET_get_bytes(ei, &pp_tmp, pi_tmp)
            || !WPACKET_put_bytes_u16(di, pi_tmp)
            || !WPACKET_memcpy(di, pp_tmp, pi_tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        WPACKET_close(di);
        return 1;
    }
    /*
     * general case, copy one by one from inner, 'till we hit
     * the outers extension, then copy one by one from outer
     */
    if (!PACKET_get_net_2(ei, &pi_tmp) /* len(extensions) */
        || !PACKET_get_net_2(&outer, &outer_extslen)
        || !PACKET_get_bytes(&outer, &outer_exts, outer_extslen)
        || !WPACKET_start_sub_packet_u16(di)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    while (PACKET_remaining(ei) > 0) {
        if (!PACKET_get_net_2(ei, &etype)
            || !PACKET_get_net_2(ei, &elen)
            || !PACKET_get_bytes(ei, &eval, elen)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (etype == TLSEXT_TYPE_outer_extensions) {
            for (i = 0; i != n_outers; i++) {
                if (ech_copy_ext(s, di, outers[i],
                                 outer_exts, outer_extslen) != 1)
                    goto err;
            }
        } else {
            if (!WPACKET_put_bytes_u16(di, etype)
                || !WPACKET_put_bytes_u16(di, elen)
                || !WPACKET_memcpy(di, eval, elen)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        }
    }
    WPACKET_close(di);
    return 1;
err:
    WPACKET_cleanup(di);
    return 0;
}

/*
 * @brief After successful ECH decrypt, we decode, decompress etc.
 * @param s is the SSL connection
 * @param ob is the outer CH as a buffer
 * @param ob_len is the size of the above
 * @return 1 for success, error otherwise
 *
 * We need the outer CH as a buffer (ob, below) so we can
 * ECH-decompress.
 * The plaintext we start from is in encoded_innerch
 * and our final decoded, decompressed buffer will end up
 * in innerch (which'll then be further processed).
 * That further processing includes all existing decoding
 * checks so we should be fine wrt fuzzing without having
 * to make all checks here (e.g. we can assume that the
 * protocol version, NULL compression etc are correct here -
 * if not, those'll be caught later).
 * Note: there are a lot of literal values here, but it's
 * not clear that changing those to #define'd symbols will
 * help much - a change to the length of a type or from a
 * 2 octet length to longer would seem unlikely.
 */
static int ech_decode_inner(SSL_CONNECTION *s, const unsigned char *ob,
                            size_t ob_len)
{
    int rv = 0;
    PACKET ei; /* encoded inner */
    BUF_MEM *di_mem = NULL;
    uint16_t outers[OSSL_ECH_OUTERS_MAX]; /* compressed extension types */
    size_t n_outers = 0;
    WPACKET di;

    if (s->ext.ech.encoded_innerch == NULL || ob == NULL || ob_len == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((di_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(di_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&di, di_mem)
        || !WPACKET_put_bytes_u8(&di, SSL3_MT_CLIENT_HELLO)
        || !WPACKET_start_sub_packet_u24(&di)
        || !PACKET_buf_init(&ei, s->ext.ech.encoded_innerch,
                            s->ext.ech.encoded_innerch_len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    memset(outers, -1, sizeof(outers)); /* fill with known values for debug */
# endif

    /* 1. check for outers and make inital checks of those */
    if (ech_find_outers(s, &ei, outers, &n_outers) != 1)
        goto err; /* SSLfatal called already */

    /* 2. reconstitute inner CH */
    /* reset ei */
    if (PACKET_buf_init(&ei, s->ext.ech.encoded_innerch,
                        s->ext.ech.encoded_innerch_len) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ech_reconstitute_inner(s, &di, &ei, ob, ob_len, outers, n_outers) != 1)
        goto err; /* SSLfatal called already */
    /* 3. store final inner CH in connection */
    /* handle HRR case where we (temporarily) store the old inner CH */
    if (s->ext.ech.innerch != NULL) {
        OPENSSL_free(s->ext.ech.innerch1);
        s->ext.ech.innerch1 = s->ext.ech.innerch;
        s->ext.ech.innerch1_len = s->ext.ech.innerch_len;
    }
    WPACKET_close(&di);
    if (!WPACKET_get_length(&di, &s->ext.ech.innerch_len))
        goto err;
    s->ext.ech.innerch = OPENSSL_malloc(s->ext.ech.innerch_len);
    if (s->ext.ech.innerch == NULL)
        goto err;
    memcpy(s->ext.ech.innerch, di_mem->data, s->ext.ech.innerch_len);
    /* clean up */
    OPENSSL_free(s->ext.ech.encoded_innerch);
    s->ext.ech.encoded_innerch = NULL;
    s->ext.ech.encoded_innerch_len = 0;
    rv = 1;
err:
    WPACKET_cleanup(&di);
    BUF_MEM_free(di_mem);
    return rv;
}

/*
 * @brief wrapper for hpke_dec just to save code repetition
 * @param s is the SSL connection
 * @param ech is the selected ECHConfig
 * @param the_ech is the value sent by the client
 * @param aad_len is the length of the AAD to use
 * @param aad is the AAD to use
 * @param forhrr is 0 if not hrr, 1 if this is for 2nd CH
 * @param innerlen points to the size of the recovered plaintext
 * @return pointer to plaintext or NULL (if error)
 *
 * The plaintext returned is allocated here and must
 * be freed by the caller later.
 */
static unsigned char *hpke_decrypt_encch(SSL_CONNECTION *s, SSL_ECH *ech,
                                         OSSL_ECH_ENCCH *the_ech,
                                         size_t aad_len, unsigned char *aad,
                                         int forhrr, size_t *innerlen)
{
    size_t cipherlen = 0;
    unsigned char *cipher = NULL;
    size_t senderpublen = 0;
    unsigned char *senderpub = NULL;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char info[SSL3_RT_MAX_PLAIN_LENGTH];
    size_t info_len = SSL3_RT_MAX_PLAIN_LENGTH;
    int rv = 0;
    OSSL_HPKE_CTX *hctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    size_t publen = 0;
    unsigned char *pub = NULL;
# endif

    cipherlen = the_ech->payload_len;
    cipher = the_ech->payload;
    senderpublen = the_ech->enc_len;
    senderpub = the_ech->enc;
    hpke_suite.aead_id = the_ech->aead_id;
    hpke_suite.kdf_id = the_ech->kdf_id;
    clearlen = cipherlen; /* small overestimate */
    clear = OPENSSL_malloc(clearlen);
    if (clear == NULL)
        return NULL;
    /*
     * We only support one ECHConfig for now on the server side
     * The calling code looks after matching the ECH.config_id
     * and/or trial decryption.
     */
    hpke_suite.kem_id = ech->cfg->recs[0].kem_id;
# ifdef OSSL_ECH_SUPERVERBOSE
    publen = ech->cfg->recs[0].pub_len;
    pub = ech->cfg->recs[0].pub;
    ech_pbuf("aad", aad, aad_len);
    ech_pbuf("my local pub", pub, publen);
    ech_pbuf("senderpub", senderpub, senderpublen);
    ech_pbuf("cipher", cipher, cipherlen);
# endif
    if (ech_helper_make_enc_info(ech->cfg->recs->encoding_start,
                                 ech->cfg->recs->encoding_length,
                                 info, &info_len) != 1) {
        OPENSSL_free(clear);
        return NULL;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("info", info, info_len);
# endif
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,
                   "hpke_dec suite: kem: %04x, kdf: %04x, aead: %04x\n",
                   hpke_suite.kem_id, hpke_suite.kdf_id, hpke_suite.aead_id);
    } OSSL_TRACE_END(TLS);
    /*
     * We may generate externally visible OpenSSL errors
     * if decryption fails (which is normal) but we'll
     * ignore those as we might be dealing with a GREASEd
     * ECH. The way to do that is to consume all
     * errors generated internally during the attempt
     * to decrypt. Failing to clear those errors can
     * trigger an application to consider TLS session
     * establishment has failed when someone just
     * GREASEd or used an old key.  But to do that we
     * first need to know there are no other errors in
     * the queue that we ought not consume as the application
     * really should know about those.
     */
    if (ERR_peek_error() != 0) {
        OPENSSL_free(clear);
        return NULL;
    }
    /* Use OSSL_HPKE_* APIs */
    hctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, OSSL_HPKE_ROLE_RECEIVER,
                             NULL, NULL);
    if (hctx == NULL)
        goto clearerrs;
    rv = OSSL_HPKE_decap(hctx, senderpub, senderpublen, ech->keyshare,
                         info, info_len);
    if (rv != 1)
        goto clearerrs;
    if (forhrr == 1) {
        rv = OSSL_HPKE_CTX_set_seq(hctx, 1);
        if (rv != 1) {
            /* don't clear this error - GREASE can't cause it */
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto end;
        }
    }
    rv = OSSL_HPKE_open(hctx, clear, &clearlen, aad, aad_len,
                        cipher, cipherlen);
    if (rv != 1)
        goto clearerrs;

clearerrs:
    /*
     * clear errors from failed decryption as per the above
     * we do this before checking the result from hpke_dec
     * then return, or carry on
     */
    while (ERR_get_error() != 0);
end:
    OSSL_HPKE_CTX_free(hctx);
    if (rv != 1) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "HPKE decryption failed somehow\n");
        } OSSL_TRACE_END(TLS);
        OPENSSL_free(clear);
        return NULL;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("padded clear", clear, clearlen);
# endif
    /* we need to remove possible (actually, v. likely) padding */
    *innerlen = clearlen;
    if (ech->cfg->recs[0].version == OSSL_ECH_RFCXXXX_VERSION) {
        /* draft-13 pads after the encoded CH with zeros */
        size_t extsoffset = 0;
        size_t extslen = 0;
        size_t ch_len = 0;
        size_t startofsessid = 0;
        size_t echoffset = 0; /* offset of start of ECH within CH */
        uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
        size_t outersnioffset = 0; /* offset to SNI in outer */
        int innerflag = -1;
        PACKET innerchpkt;

        if (PACKET_buf_init(&innerchpkt, clear, clearlen) != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        rv = ech_get_ch_offsets(s, &innerchpkt, &startofsessid, &extsoffset,
                                &echoffset, &echtype, &innerflag,
                                &outersnioffset);
        if (rv != 1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        /* odd form of check below just for emphasis */
        if ((extsoffset + 1) > clearlen) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        extslen = (unsigned char)(clear[extsoffset]) * 256
            + (unsigned char)(clear[extsoffset + 1]);
        ch_len = extsoffset + 2 + extslen;
        /* the check below protects us from bogus data */
        if (ch_len > clearlen) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            OPENSSL_free(clear);
            return NULL;
        }
        /*
         * The RFC calls for that padding to be all zeros. I'm not so
         * keen on that being a good idea to enforce, so we'll make it
         * easy to not do so (but check by default)
         */
# define CHECKZEROS
# ifdef CHECKZEROS
        {
            size_t zind = 0;
            size_t nonzeros = 0;
            size_t zeros = 0;

            if (*innerlen < ch_len) {
                OPENSSL_free(clear);
                return NULL;
            }
            for (zind = ch_len; zind != *innerlen; zind++) {
                if (clear[zind] == 0x00) {
                    zeros++;
                } else {
                    nonzeros++;
                }
            }
            if (nonzeros > 0 || zeros != (*innerlen - ch_len)) {
                OPENSSL_free(clear);
                return NULL;
            }
        }
# endif
        *innerlen = ch_len;
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("unpadded clear", clear, *innerlen);
# endif
        return clear;
    }
    OPENSSL_free(clear);
    return NULL;
}

/*
 * @brief figure out how much padding for cleartext (on client)
 * @param s is the SSL connection
 * @param tc is the chosen ECHConfig
 * @return is the overall length to use including padding or zero on error
 *
 * "Recommended" inner SNI padding scheme as per spec
 * (section 6.1.3)
 * Might remove the mnl stuff later - overall message padding seems
 * better really, BUT... we might want to keep this if others (e.g.
 * browsers) do it so as to not stand out compared to them.
 *
 * The "+ 9" constant below is from the specifiation and is the
 * expansion comparing a string length to an encoded SNI extension.
 * Same is true of the 31/32 formula below.
 *
 * Note that the AEAD tag will be added later, so if we e.g. have
 * a padded cleartext of 128 octets, the ciphertext will be 144
 * octets.
 */
static size_t ech_calc_padding(SSL_CONNECTION *s, ECHConfig *tc)
{
    int length_of_padding = 0;
    int length_with_snipadding = 0;
    int length_with_padding = 0;
    int innersnipadding = 0;
    size_t mnl = 0;
    size_t clear_len = 0;
    size_t isnilen = 0;

    if (s == NULL || tc == NULL)
        return 0;
    mnl = tc->maximum_name_length;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: ECHConfig had max name len of %zu\n", mnl);
    } OSSL_TRACE_END(TLS);
    if (mnl != 0) {
        /* do weirder padding if SNI present in inner */
        if (s->ext.hostname != NULL) {
            isnilen = strlen(s->ext.hostname) + 9;
            innersnipadding = mnl - isnilen;
        } else {
            innersnipadding = mnl + 9;
        }
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EAAE: innersnipadding of %d\n",
                       innersnipadding);
        } OSSL_TRACE_END(TLS);
        if (innersnipadding < 0) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "EAAE: innersnipadding zero'd\n");
            } OSSL_TRACE_END(TLS);
            innersnipadding = 0;
        }
    }
    /* draft-13 padding is after the encoded client hello */
    length_with_snipadding = innersnipadding
        + s->ext.ech.encoded_innerch_len;
    length_of_padding = 31 - ((length_with_snipadding - 1) % 32);
    length_with_padding = s->ext.ech.encoded_innerch_len
        + length_of_padding + innersnipadding;
    /*
     * Finally - make sure final result is longer than padding target
     * and a multiple of our padding increment.
     * This is a local addition - might take it out if it makes
     * us stick out; or if we take out the above more complicated
     * scheme, we may only need this in the end (and that'd maybe
     * be better overall:-)
     */
    if (length_with_padding % OSSL_ECH_PADDING_INCREMENT)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT
            - (length_with_padding % OSSL_ECH_PADDING_INCREMENT);
    while (length_with_padding < OSSL_ECH_PADDING_TARGET)
        length_with_padding += OSSL_ECH_PADDING_INCREMENT;
    clear_len = length_with_padding;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: padding: mnl: %zu, lws: %d "
                   "lop: %d, lwp: %d, clear_len: %zu, orig: %zu\n",
                   mnl, length_with_snipadding, length_of_padding,
                   length_with_padding, clear_len,
                   s->ext.ech.encoded_innerch_len);
    } OSSL_TRACE_END(TLS);
    return clear_len;
}

/*
 * @brief decode outer sni value so we can trace it
 * @param s is the SSL connection
 * @param osni_str is the string-form of the SNI
 * @param opd is the outer CH buffer
 * @param opl is the length of the above
 * @param snioffset is where we find the outer SNI
 *
 * The caller doesn't have to free the osni_str.
 */
static int ech_get_outer_sni(SSL_CONNECTION *s, char **osni_str,
                             const unsigned char *opd, size_t opl,
                             size_t snioffset)
{
    PACKET wrap, osni;
    unsigned int type, osnilen;

    if (snioffset >= opl
        || !PACKET_buf_init(&wrap, opd + snioffset, opl - snioffset)
        || !PACKET_get_net_2(&wrap, &type)
        || type != 0
        || !PACKET_get_net_2(&wrap, &osnilen)
        || !PACKET_get_sub_packet(&wrap, &osni, osnilen)
        || tls_parse_ctos_server_name(s, &osni, 0, NULL, 0) != 1)
        return 0;
    OPENSSL_free(s->ext.ech.cfgs->outer_name);
    *osni_str = s->ext.ech.cfgs->outer_name = s->ext.hostname;
    /* clean up what the ECH-unaware parse func above left behind */
    s->ext.hostname = NULL;
    s->servername_done = 0;
    return 1;
}

/*
 * @brief decode EncryptedClientHello extension value
 * @param s is the SSL connection
 * @param pkt contains the ECH value as a PACKET
 * @param extval is the returned decoded structure
 * @param payload_offset is the offset to the ciphertext
 * @return 1 for good, 0 for bad
 *
 * SSLfatal called from inside, as needed
 */
static int ech_decode_inbound_ech(SSL_CONNECTION *s, PACKET *pkt,
                                  OSSL_ECH_ENCCH **retext,
                                  size_t *payload_offset)
{
    unsigned char innerorouter = 0xff;
    unsigned int pval_tmp; /* tmp placeholder of value from packet */
    OSSL_ECH_ENCCH *extval = NULL;
    const unsigned char *startofech = NULL;

    /*
     * Decode the inbound ECH value.
     * For draft-13, we're concerned with the "inner"
     * form here:
     *  enum { outer(0), inner(1) } ECHClientHelloType;
     *  struct {
     *     ECHClientHelloType type;
     *     select (ECHClientHello.type) {
     *         case outer:
     *             HpkeSymmetricCipherSuite cipher_suite;
     *             uint8 config_id;
     *             opaque enc<0..2^16-1>;
     *             opaque payload<1..2^16-1>;
     *         case inner:
     *             Empty;
     *     };
     *  } ECHClientHello;
     */
    startofech = PACKET_data(pkt);
    extval = OPENSSL_zalloc(sizeof(OSSL_ECH_ENCCH));
    if (extval == NULL)
        goto err;
    if (!PACKET_copy_bytes(pkt, &innerorouter, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (innerorouter != OSSL_ECH_OUTER_CH_TYPE) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->kdf_id = pval_tmp & 0xffff;
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->aead_id = pval_tmp & 0xffff;
    /* config id */
    if (!PACKET_copy_bytes(pkt, &extval->config_id, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EARLY config id", &extval->config_id, 1);
# endif
    s->ext.ech.attempted_cid = extval->config_id;
    /* enc - the client's public share */
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > OSSL_ECH_MAX_GREASE_PUB) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp == 0 && s->hello_retry_request != SSL_HRR_PENDING) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    } else if (pval_tmp > 0 && s->hello_retry_request == SSL_HRR_PENDING) {
        unsigned char *tmpenc = NULL;
        /*
         * if doing HRR, client should only send this when GREASEing
         * and it should be the same value as 1st time, so we'll check
         * that
         */
        if (s->ext.ech.pub == NULL || s->ext.ech.pub_len == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (pval_tmp != s->ext.ech.pub_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        tmpenc = OPENSSL_malloc(pval_tmp);
        if (tmpenc == NULL)
            goto err;
        if (!PACKET_copy_bytes(pkt, tmpenc, pval_tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (memcmp(tmpenc, s->ext.ech.pub, pval_tmp)) {
            OPENSSL_free(tmpenc);
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        OPENSSL_free(tmpenc);
    } else if (pval_tmp == 0 && s->hello_retry_request == SSL_HRR_PENDING) {
        if (s->ext.ech.pub == NULL || s->ext.ech.pub_len == 0) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        extval->enc_len = s->ext.ech.pub_len;
        extval->enc = OPENSSL_malloc(extval->enc_len);
        if (extval->enc == NULL)
            goto err;
        memcpy(extval->enc, s->ext.ech.pub, extval->enc_len);
    } else {
        extval->enc_len = pval_tmp;
        extval->enc = OPENSSL_malloc(pval_tmp);
        if (extval->enc == NULL)
            goto err;
        if (!PACKET_copy_bytes(pkt, extval->enc, pval_tmp)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        /* squirrel away that value in case of future HRR */
        OPENSSL_free(s->ext.ech.pub);
        s->ext.ech.pub_len = extval->enc_len;
        s->ext.ech.pub = OPENSSL_malloc(extval->enc_len);
        if (s->ext.ech.pub == NULL)
            goto err;
        memcpy(s->ext.ech.pub, extval->enc, extval->enc_len);
    }
    /* payload - the encrypted CH */
    *payload_offset = PACKET_data(pkt) - startofech;
    if (!PACKET_get_net_2(pkt, &pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (pval_tmp > PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->payload_len = pval_tmp;
    extval->payload = OPENSSL_malloc(pval_tmp);
    if (extval->payload == NULL)
        goto err;
    if (!PACKET_copy_bytes(pkt, extval->payload, pval_tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    *retext = extval;
    return 1;
err:
    if (extval != NULL) {
        OSSL_ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval = NULL;
    }
    return 0;
}

/*
 * @brief return the h/s hash from the connection of ServerHello
 * @param s is the SSL connection
 * @param rmd is the returned h/s hash
 * @param shbuf is the ServerHello
 * @param shlen is the length of the ServerHello
 * @return 1 for good, 0 for error
 */
static int get_md_from_hs(SSL_CONNECTION *s, EVP_MD **rmd,
                          const unsigned char *shbuf, const size_t shlen)
{
    int rv;
    size_t extoffset = 0, echoffset = 0, cipheroffset = 0;
    uint16_t echtype;
    const SSL_CIPHER *c = NULL;
    const unsigned char *cipherchars = NULL;
    EVP_MD *md = NULL;

    /* this branch works for the server */
    md = (EVP_MD *)ssl_handshake_md(s);
    if (md != NULL) {
        *rmd = md;
        return 1;
    }
    /* if we're a client we'll fallback to hash from the chosen ciphersuite */
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "finding ECH confirm MD from ServerHello\n");
    } OSSL_TRACE_END(TLS);
    rv = ech_get_sh_offsets(shbuf, shlen, &extoffset, &echoffset, &echtype);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        return 0;
    }
    if (extoffset < 3) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        return 0;
    }
    cipheroffset = extoffset - 3;
    cipherchars = &shbuf[cipheroffset];
    c = ssl_get_cipher_by_char(s, cipherchars, 0);
    if (c == NULL) { /* fuzzer fix */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
        return 0;
    }
    md = (EVP_MD *)ssl_md(s->ssl.ctx, c->algorithm2);
    if (md == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *rmd = md;
    return 1;
}

/*
 * @brief do the HKDF for ECH acceptannce checking
 * @param s is the SSL connection
 * @param md is the h/s hash
 * @param for_hrr is 1 if we're doing a HRR
 * @return 1 for good, 0 for error
 */
static int ech_hkdf_extract_wrap(SSL_CONNECTION *s, EVP_MD *md, int for_hrr,
                                 unsigned char *hashval, size_t hashlen,
                                 unsigned char *hoval)
{
    int rv = 0;
    unsigned char notsecret[EVP_MAX_MD_SIZE], zeros[EVP_MAX_MD_SIZE];
    size_t retlen = 0, labellen = 0;
    EVP_PKEY_CTX *pctx = NULL;
    const char *label = NULL;
    unsigned char *p = NULL;

    if (for_hrr == 1) {
        label = OSSL_ECH_HRR_CONFIRM_STRING;
    } else {
        label = OSSL_ECH_ACCEPT_CONFIRM_STRING;
    }
    labellen = strlen(label);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: label", (unsigned char *)label, labellen);
# endif
    memset(zeros, 0, EVP_MAX_MD_SIZE);
    /* We still don't have an hkdf-extract that's exposed by libcrypto */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_init(pctx) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx,
                               EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* pick correct client_random */
    if (s->server)
        p = s->s3.client_random;
    else
        p = s->ext.ech.client_random;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: client_random", p, SSL3_RANDOM_SIZE);
# endif
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, p, SSL3_RANDOM_SIZE) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, zeros, hashlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* get the right size set first - new in latest upstream */
    if (EVP_PKEY_derive(pctx, NULL, &retlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hashlen != retlen) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, notsecret, &retlen) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cc: notsecret", notsecret, hashlen);
# endif
    if (hashlen < 8) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!tls13_hkdf_expand(s, md, notsecret,
                           (const unsigned char *)label, labellen,
                           hashval, hashlen,
                           hoval, 8, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return rv;
}

static int ech_read_hrrtoken(SSL_CONNECTION *sc, unsigned char **hrrtok,
                             size_t *toklen)
{
    PACKET pkt_hrrtok;
    unsigned int pi_tmp;
    const unsigned char *pp_tmp;

    /*
     * invented TLS presentation form packet format for this is:
     *  struct {
     *     opaque enc<0..2^16-1>;
     *  }
     *
     *  Note that enc is public having been visible on the n/w
     *  when CH1 was sent.
     */
    if (PACKET_buf_init(&pkt_hrrtok, *hrrtok, *toklen) != 1
        || !PACKET_get_net_2(&pkt_hrrtok, &pi_tmp)
        || !PACKET_get_bytes(&pkt_hrrtok, &pp_tmp, pi_tmp)
        || PACKET_remaining(&pkt_hrrtok) > 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    sc->ext.ech.pub = OPENSSL_malloc(pi_tmp);
    if (sc->ext.ech.pub == NULL)
        return 0;
    memcpy(sc->ext.ech.pub, pp_tmp, pi_tmp);
    sc->ext.ech.pub_len = pi_tmp;
    /* also set this to get calculations right */
    sc->hello_retry_request = SSL_HRR_PENDING;
    return 1;
}

static int ech_write_hrrtoken(SSL_CONNECTION *sc, unsigned char **hrrtok,
                              size_t *toklen)
{
    WPACKET hpkt;
    BUF_MEM *hpkt_mem = NULL;

    /* invented TLS presentation form packet format as above */
    if ((hpkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(hpkt_mem, OSSL_ECH_MAX_ECHCONFIG_LEN)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_init(&hpkt, hpkt_mem)
        || !WPACKET_put_bytes_u16(&hpkt, sc->ext.ech.pub_len)
        || !WPACKET_memcpy(&hpkt, sc->ext.ech.pub,
                           sc->ext.ech.pub_len)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        WPACKET_cleanup(&hpkt);
        BUF_MEM_free(hpkt_mem);
        return 0;
    }
    WPACKET_get_total_written(&hpkt, toklen);
    *hrrtok = OPENSSL_malloc(*toklen);
    if (*hrrtok == NULL) {
        WPACKET_cleanup(&hpkt);
        BUF_MEM_free(hpkt_mem);
        return 0;
    }
    memcpy(*hrrtok, WPACKET_get_curr(&hpkt) - *toklen, *toklen);
    WPACKET_cleanup(&hpkt);
    BUF_MEM_free(hpkt_mem);
    return 1;
}

/* SECTION: Non-public functions used elsewhere in the library */

# ifdef OSSL_ECH_SUPERVERBOSE
/*
 * @brief ascii-hex print a buffer nicely for debug/interop purposes
 * @param msg pre-pend to trace lines
 * @param buf points to the buffer to print
 * @param blen is the length of buffer to print
 */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{
    OSSL_TRACE_BEGIN(TLS) {
        if (msg == NULL) {
            BIO_printf(trc_out, "msg is NULL\n");
        } else if (buf == NULL || blen == 0) {
            BIO_printf(trc_out, "%s: buf is %p\n", msg, (void *)buf);
            BIO_printf(trc_out, "%s: blen is %lu\n", msg, (unsigned long)blen);
        } else {
            size_t i;

            BIO_printf(trc_out, "%s (%lu):\n    ", msg, (unsigned long)blen);
            for (i = 0; i < blen; i++) {
                if ((i != 0) && (i % 16 == 0))
                    BIO_printf(trc_out, "\n    ");
                BIO_printf(trc_out, "%02x:", (unsigned)(buf[i]));
            }
            BIO_printf(trc_out, "\n");
        }
    } OSSL_TRACE_END(TLS);
    return;
}

/*
 * @brief trace out transcript
 * @param msg pre-pend to trace lines
 * @param s is the SSL connection
 */
void ech_ptranscript(const char *msg, SSL_CONNECTION *s)
{
    size_t hdatalen = 0;
    unsigned char *hdata = NULL;
    unsigned char ddata[1000];
    size_t ddatalen;

    if (s == NULL)
        return;
    hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
    ech_pbuf(msg, hdata, hdatalen);
    if (s->s3.handshake_dgst != NULL) {
        if (ssl_handshake_hash(s, ddata, 1000, &ddatalen) == 0) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "ssl_handshake_hash failed\n");
            } OSSL_TRACE_END(TLS);
        }
        ech_pbuf(msg, ddata, ddatalen);
    } else {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "handshake_dgst is NULL\n");
        } OSSL_TRACE_END(TLS);
    }
    return;
}
# endif

/*
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be freed
 */
void ECHConfig_free(ECHConfig *tbf)
{
    unsigned int i = 0;

    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->public_name);
    OPENSSL_free(tbf->pub);
    OPENSSL_free(tbf->ciphersuites);
    OPENSSL_free(tbf->exttypes);
    OPENSSL_free(tbf->extlens);
    for (i = 0; i != tbf->nexts; i++)
        OPENSSL_free(tbf->exts[i]);
    OPENSSL_free(tbf->exts);
    OPENSSL_free(tbf->encoding_start);
    return;
}

/*
 * @brief Free an ECHConfigList structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfigList_free(ECHConfigList *tbf)
{
    int i;

    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->encoded);
    for (i = 0; i != tbf->nrecs; i++)
        ECHConfig_free(&tbf->recs[i]);
    OPENSSL_free(tbf->recs);
    return;
}

/*
 * @brief free an OSSL_ECH_ENCCH
 * @param tbf is the thing to be free'd
 */
void OSSL_ECH_ENCCH_free(OSSL_ECH_ENCCH *tbf)
{
    if (tbf == NULL)
        return;
    OPENSSL_free(tbf->enc);
    OPENSSL_free(tbf->payload);
    return;
}

/*
 * @brief free an SSL_ECH
 * @param tbf is the thing to be free'd
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to free the top level SSL_ECH, IOW the
 * pattern here is:
 *      SSL_ECH_free(tbf);
 *      OPENSSL_free(tbf);
 */
void SSL_ECH_free(SSL_ECH *tbf)
{
    if (tbf == NULL)
        return;
    if (tbf->cfg != NULL) {
        ECHConfigList_free(tbf->cfg);
        OPENSSL_free(tbf->cfg);
    }
    OPENSSL_free(tbf->inner_name);
    OPENSSL_free(tbf->outer_name);
    OPENSSL_free(tbf->pemfname);
    EVP_PKEY_free(tbf->keyshare);
    memset(tbf, 0, sizeof(SSL_ECH));
    return;
}

/*
 * @brief Free an array of SSL_ECH
 * @param tbf is the thing to be free'd
 * @param elems is the number of elements to free
 */
void SSL_ECH_free_arr(SSL_ECH *tbf, size_t elems)
{
    size_t i;

    if (tbf == NULL)
        return;
    for (i = 0; i != elems; i++)
        SSL_ECH_free(&tbf[i]);
    return;
}

/**
 * @brief print info about the ECH-status of an SSL connection
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param ssl is an SSL session strucutre
 * @param selector OSSL_ECH_SELECT_ALL or just one of the SSL_ECH values
 * @return 1 for success, anything else for failure
 */
int SSL_ech_print(BIO *out, SSL *ssl, int selector)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "SSL_ech_print\n");
    BIO_printf(out, "s=%p\n", (void *)s);
# endif
    BIO_printf(out, "ech_attempted=%d\n", s->ext.ech.attempted);
    BIO_printf(out, "ech_attempted_type=0x%4x\n",
               s->ext.ech.attempted_type);
    if (s->ext.ech.attempted_cid == TLSEXT_TYPE_ech_config_id_unset)
        BIO_printf(out, "ech_atttempted_cid is unset\n");
    else
        BIO_printf(out, "ech_atttempted_cid=0x%02x\n",
                   s->ext.ech.attempted_cid);
    BIO_printf(out, "ech_done=%d\n", s->ext.ech.done);
    BIO_printf(out, "ech_grease=%d\n", s->ext.ech.grease);
# ifdef OSSL_ECH_SUPERVERBOSE
    BIO_printf(out, "HRR=%d\n", s->hello_retry_request);
    BIO_printf(out, "ech_returned=%p\n",
               (void *)s->ext.ech.returned);
# endif
    BIO_printf(out, "ech_returned_len=%ld\n",
               (long)s->ext.ech.returned_len);
    BIO_printf(out, "ech_backend=%d\n", s->ext.ech.backend);
    BIO_printf(out, "ech_success=%d\n", s->ext.ech.success);
    if (s->ext.ech.cfgs != NULL) {
        int i = 0;

        if (s->ext.ech.ncfgs == 1) {
            BIO_printf(out, "1 ECHConfig value loaded\n");
        } else {
            BIO_printf(out, "%d ECHConfig values loaded\n",
                       s->ext.ech.ncfgs);
        }
        for (i = 0; i != s->ext.ech.ncfgs; i++) {
            if (selector == OSSL_ECH_SELECT_ALL || selector == i) {
                BIO_printf(out, "cfg(%d): ", i);
                if (ECHConfigList_print(out, s->ext.ech.cfgs[i].cfg) == 1)
                    BIO_printf(out, "\n");
                else
                    BIO_printf(out, "NULL (huh?)\n");
                if (s->ext.ech.cfgs[i].keyshare != NULL) {
# define OSSL_ECH_TIME_STR_LEN 32 /* apparently 26 is all we need */
                    struct tm local, *local_p = NULL;
                    char lstr[OSSL_ECH_TIME_STR_LEN];
# if defined(OPENSSL_SYS_WINDOWS)
                    errno_t grv;
# endif

# if !defined(OPENSSL_SYS_WINDOWS)
                    local_p = gmtime_r(&s->ext.ech.cfgs[i].loadtime, &local);
                    if (local_p != &local) {
                        strcpy(lstr, "sometime");
                    } else {
                        int srv = strftime(lstr, OSSL_ECH_TIME_STR_LEN,
                                           "%c", &local);

                        if (srv == 0)
                            strcpy(lstr, "sometime");
                    }
# else
                    grv = gmtime_s(&local, &s->ext.ech.cfgs[i].loadtime);
                    if (grv != 0) {
                        strcpy(lstr, "sometime");
                    } else {
                        int srv = strftime(lstr, OSSL_ECH_TIME_STR_LEN,
                                           "%c", &local);

                        if (srv == 0)
                            strcpy(lstr, "sometime");
                    }
# endif
                    BIO_printf(out, "\tpriv=%s, loaded at %s\n",
                               s->ext.ech.cfgs[i].pemfname, lstr);
                }
            }
        }
    } else {
        BIO_printf(out, "cfg=NONE\n");
    }
    if (s->ext.ech.returned) {
        size_t i = 0;

        BIO_printf(out, "ret=");
        for (i = 0; i != s->ext.ech.returned_len; i++) {
            if ((i != 0) && (i % 16 == 0))
                BIO_printf(out, "\n    ");
            BIO_printf(out, "%02x:", (unsigned)(s->ext.ech.returned[i]));
        }
        BIO_printf(out, "\n");
    }
    return 1;
}

/*
 * @brief deep-copy an array of SSL_ECH
 * @param orig is the input array of SSL_ECH to be deep-copied
 * @param nech is the number of elements in the array
 * @param selector means dup all (if OSSL_ECH_SELECT_ALL==-1) or just the
 *        one nominated
 * @return a deep-copy same-sized array or NULL if errors occur
 *
 * This is needed to handle the SSL_CTX->SSL factory model.
 */
SSL_ECH *SSL_ECH_dup(SSL_ECH *orig, size_t nech, int selector)
{
    SSL_ECH *new_se = NULL;
    int min_ind = 0;
    int max_ind = nech;
    int i = 0;

    if ((selector != OSSL_ECH_SELECT_ALL) && selector < 0)
        return NULL;
    if (selector != OSSL_ECH_SELECT_ALL) {
        if ((unsigned int)selector >= nech)
            goto err;
        min_ind = selector;
        max_ind = selector + 1;
    }
    new_se = OPENSSL_malloc((max_ind - min_ind) * sizeof(SSL_ECH));
    if (new_se == NULL)
        goto err;
    memset(new_se, 0, (max_ind - min_ind) * sizeof(SSL_ECH));
    for (i = min_ind; i != max_ind; i++) {
        new_se[i].cfg = OPENSSL_malloc(sizeof(ECHConfigList));
        if (new_se[i].cfg == NULL)
            goto err;
        if (ECHConfigList_dup(orig[i].cfg, new_se[i].cfg) != 1)
            goto err;
        if (orig[i].inner_name != NULL) {
            new_se[i].inner_name = OPENSSL_strdup(orig[i].inner_name);
            if (new_se[i].inner_name == NULL)
                goto err;
        }
        if (orig[i].outer_name != NULL) {
            new_se[i].outer_name = OPENSSL_strdup(orig[i].outer_name);
            if (new_se[i].outer_name == NULL)
                goto err;
        }
        new_se[i].no_outer = orig[i].no_outer;
        if (orig[i].pemfname != NULL) {
            new_se[i].pemfname = OPENSSL_strdup(orig[i].pemfname);
            if (new_se[i].pemfname == NULL)
                goto err;
        }
        new_se[i].loadtime = orig[i].loadtime;
        new_se[i].for_retry = orig[i].for_retry;
        if (orig[i].keyshare != NULL) {
            new_se[i].keyshare = orig[i].keyshare;
            EVP_PKEY_up_ref(orig[i].keyshare);
        }
    }
    return new_se;
err:
    SSL_ECH_free(new_se);
    OPENSSL_free(new_se);
    return NULL;
}

/**
 * @brief say if extension at index i in ext_defs is to be ECH compressed
 * @param ind is the index of this extension in ext_defs (and ech_ext_handling)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind)
{
    int nexts = OSSL_NELEM(ech_ext_handling);

    if (!ossl_assert(TLSEXT_IDX_num_builtins == nexts)) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "ECH extension table differs in size from base");
        } OSSL_TRACE_END(TLS);
        return -1;
    }
# ifdef DUPEMALL
    return 0;
# endif
    if (ind < 0 || ind >= nexts)
        return -1;
    return ech_ext_handling[ind].handling == OSSL_ECH_HANDLING_COMPRESS;
}

/**
 * @brief as needed, repeat extension from inner in outer handling compression
 * @param s is the SSL connection
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL_CONNECTION *s, WPACKET *pkt)
{
    unsigned int type = 0;
    size_t tind = 0, nexts = 0;
    int depth = 0;

# ifdef DUPEMALL
    return OSSL_ECH_SAME_EXT_CONTINUE;
# endif

    if (s == NULL || s->ext.ech.cfgs == NULL)
        return OSSL_ECH_SAME_EXT_CONTINUE; /* nothing to do */
    depth = s->ext.ech.ch_depth;
    nexts = OSSL_NELEM(ech_ext_handling);
    tind = s->ext.ech.ext_ind;
    if (tind < 0 || tind >= nexts)
        return OSSL_ECH_SAME_EXT_ERR;
    type = ech_ext_handling[tind].type;
    /* If this index'd extension won't be compressed, we're done */
    if (tind >= nexts)
        return OSSL_ECH_SAME_EXT_ERR;
    if (depth == 1) {
        /* inner CH - just note compression as configured */
        if (ech_ext_handling[tind].handling != OSSL_ECH_HANDLING_COMPRESS)
            return OSSL_ECH_SAME_EXT_CONTINUE;
        /* mark this one to be "compressed" */
        if (s->ext.ech.n_outer_only >= OSSL_ECH_OUTERS_MAX)
            return OSSL_ECH_SAME_EXT_ERR;
        s->ext.ech.outer_only[s->ext.ech.n_outer_only] = type;
        s->ext.ech.n_outer_only++;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "ech_same_ext: Marking (type %d, ind %d "
                       "tot-comp %d) for compression\n", (int) type, (int) tind,
                       (int) s->ext.ech.n_outer_only);
        } OSSL_TRACE_END(TLS);
        return OSSL_ECH_SAME_EXT_CONTINUE;
    }

    /* Copy value from inner to outer, or indicate a new value needed */
    if (depth == 0) {
        if (s->clienthello == NULL || pkt == NULL)
            return OSSL_ECH_SAME_EXT_ERR;
        if (ech_ext_handling[tind].handling == OSSL_ECH_HANDLING_CALL_BOTH)
            return OSSL_ECH_SAME_EXT_CONTINUE;
        else
            return ech_copy_inner2outer(s, type, pkt);
    }
    /* just in case - shouldn't happen */
    return OSSL_ECH_SAME_EXT_ERR;
}

/**
 * @brief check if we're using the same/different key shares
 * @return 1 if same key share in inner and outer, 0 otherwise
 */
int ech_same_key_share(void)
{
# ifdef DUPEMALL
    return 0;
# endif
    return ech_ext_handling[TLSEXT_IDX_key_share].handling
        != OSSL_ECH_HANDLING_CALL_BOTH;
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 * @param s is the SSL connection
 * @return 1 for success, error otherwise
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffers
 */
int ech_encode_inner(SSL_CONNECTION *s)
{
    int rv = 0;
    unsigned char *innerch_full = NULL;
    WPACKET inner; /* "fake" pkt for inner */
    BUF_MEM *inner_mem = NULL;
    int mt = SSL3_MT_CLIENT_HELLO;
    RAW_EXTENSION *raws = NULL;
    size_t nraws = 0;
    size_t ind = 0;
    size_t innerinnerlen = 0;
    size_t builtins = OSSL_NELEM(ech_ext_handling);

    /* basic checks */
    if (s == NULL || s->ext.ech.cfgs == NULL)
        return 0;
    if ((inner_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(inner_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&inner, inner_mem)
        || !ssl_set_handshake_header(s, &inner, mt)
        /* Add ver/rnd/sess-id/suites to buffer */
        || !WPACKET_put_bytes_u16(&inner, s->client_version)
        || !WPACKET_memcpy(&inner, s->ext.ech.client_random, SSL3_RANDOM_SIZE)
        /* Session ID is forced to zero in the encoded inner */
        || !WPACKET_start_sub_packet_u8(&inner)
        || !WPACKET_close(&inner)
        /* Ciphers supported */
        || !WPACKET_start_sub_packet_u16(&inner)
        || !ssl_cipher_list_to_bytes(s, SSL_get_ciphers(&s->ssl), &inner)
        || !WPACKET_close(&inner)
        /* COMPRESSION */
        || !WPACKET_start_sub_packet_u8(&inner)
        /* Add the NULL compression method */
        || !WPACKET_put_bytes_u8(&inner, 0) || !WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Now handle extensions */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Grab a pointer to the already constructed extensions */
    raws = s->clienthello->pre_proc_exts;
    nraws = s->clienthello->pre_proc_exts_len;
    if (nraws < builtins) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*  We put ECH-compressed stuff first (if any), because we can */
    if (s->ext.ech.n_outer_only > 0) {
        if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions)
            || !WPACKET_put_bytes_u16(&inner, 2 * s->ext.ech.n_outer_only + 1)
            /* redundant encoding of more-or-less the same thing */
            || !WPACKET_put_bytes_u8(&inner, 2 * s->ext.ech.n_outer_only)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* add the types for each of the compressed extensions now */
        for (ind = 0; ind != s->ext.ech.n_outer_only; ind++) {
            if (!WPACKET_put_bytes_u16(&inner, s->ext.ech.outer_only[ind])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* now copy the rest, as "proper" exts, into encoded inner */
    for (ind = 0; ind < builtins; ind++) {
        if (raws[ind].present == 0)
            continue;
        if (ech_2bcompressed(ind) == 1)
            continue;
        if (PACKET_data(&raws[ind].data) != NULL) {
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_sub_memcpy_u16(&inner, PACKET_data(&raws[ind].data),
                                           PACKET_remaining(&raws[ind].data))) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* empty extension */
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_put_bytes_u16(&inner, 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* close the exts sub packet */
    if (!WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* close the inner CH */
    if (!WPACKET_close(&inner))
        goto err;
    /* Set pointer/len for inner CH */
    if (!WPACKET_get_length(&inner, &innerinnerlen))
        goto err;
    innerch_full = OPENSSL_malloc(innerinnerlen);
    if (innerch_full == NULL)
        goto err;
    /* Finally ditch the type and 3-octet length */
    memcpy(innerch_full, inner_mem->data + 4, innerinnerlen - 4);
    OPENSSL_free(s->ext.ech.encoded_innerch);
    s->ext.ech.encoded_innerch = innerch_full;
    s->ext.ech.encoded_innerch_len = innerinnerlen - 4;
    /* and clean up */
    rv = 1;
err:
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    return rv;
}

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 * @param ssl is the session
 * @param buf is the data to put into the transcript (usually inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL_CONNECTION *s, const unsigned char *buf,
                        size_t blen)
{
# ifdef OSSL_ECH_SUPERVERBOSE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Adding this to transcript: RESET!\n");
    } OSSL_TRACE_END(TLS);
    ech_pbuf("Adding this to transcript", buf, blen);
# endif
    if (s->s3.handshake_buffer != NULL) {
        (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer = NULL;
    }
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
    s->s3.handshake_buffer = BIO_new(BIO_s_mem());
    if (s->s3.handshake_buffer == NULL) {
        return 0;
    }
    if (buf != NULL || blen > 0) {
        /* providing nothing at all is a real use (mid-HRR) */
        BIO_write(s->s3.handshake_buffer, (void *)buf, (int)blen);
    }
    return 1;
}

/*
 * @brief make up a buffer to use to reset transcript
 * @param s is the SSL connection
 * @param for_hrr says if the we include an HRR or not
 * @param shbuf is the output buffer
 * @param shlen is the length of that buffer
 * @param tbuf is the output buffer
 * @param tlen is the length of that buffer
 * @param chend returns the offset of the end of the last CH in the buffer
 * @param fixedshbuf_len returns the fixed up length of the SH
 * @return 1 for good, 0 otherwise
 */
int ech_make_transcript_buffer(SSL_CONNECTION *s, int for_hrr,
                               const unsigned char *shbuf, size_t shlen,
                               unsigned char **tbuf, size_t *tlen,
                               size_t *chend, size_t *fixedshbuf_len)
{
    unsigned char *fixedshbuf = NULL, *hashin = NULL, hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen = 0, hashin_len = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    WPACKET tpkt, shpkt;
    BUF_MEM *tpkt_mem = NULL, *shpkt_mem = NULL;

    /*
     * store SH for later, preamble has bad length at this point on server
     * and is missing on client so we'll fix
     */
    if ((shpkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(shpkt_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&shpkt, shpkt_mem)) {
        BUF_MEM_free(shpkt_mem);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!WPACKET_put_bytes_u8(&shpkt, SSL3_MT_SERVER_HELLO)
        || (s->server == 1 && !WPACKET_put_bytes_u24(&shpkt, shlen - 4))
        || (s->server == 1 && !WPACKET_memcpy(&shpkt, shbuf + 4, shlen -4))
        || (s->server == 0 && !WPACKET_put_bytes_u24(&shpkt, shlen))
        || (s->server == 0 && !WPACKET_memcpy(&shpkt, shbuf, shlen))
        || !WPACKET_get_length(&shpkt, fixedshbuf_len)) {
        BUF_MEM_free(shpkt_mem);
        WPACKET_cleanup(&shpkt);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fixedshbuf = OPENSSL_malloc(*fixedshbuf_len);
    if (fixedshbuf == NULL) {
        BUF_MEM_free(shpkt_mem);
        WPACKET_cleanup(&shpkt);
        goto err;
    }
    memcpy(fixedshbuf, WPACKET_get_curr(&shpkt) - *fixedshbuf_len,
           *fixedshbuf_len);
    BUF_MEM_free(shpkt_mem);
    WPACKET_cleanup(&shpkt);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: fixed sh buf", fixedshbuf, *fixedshbuf_len);
# endif
    if ((tpkt_mem = BUF_MEM_new()) == NULL
        || !BUF_MEM_grow(tpkt_mem, SSL3_RT_MAX_PLAIN_LENGTH)
        || !WPACKET_init(&tpkt, tpkt_mem)) {
        BUF_MEM_free(tpkt_mem);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->hello_retry_request == SSL_HRR_NONE) {
        if (!WPACKET_memcpy(&tpkt, s->ext.ech.innerch,
                            s->ext.ech.innerch_len)
            || !WPACKET_get_length(&tpkt, chend)
            || !WPACKET_memcpy(&tpkt, fixedshbuf, *fixedshbuf_len)
            || !WPACKET_get_length(&tpkt, tlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(fixedshbuf);
        *tbuf = OPENSSL_malloc(*tlen);
        if (*tbuf == NULL)
            goto err;
        memcpy(*tbuf, WPACKET_get_curr(&tpkt) - *tlen, *tlen);
        WPACKET_cleanup(&tpkt);
        BUF_MEM_free(tpkt_mem);
        return 1;
    }
    /* SH here has outer type/24-bit length */
    if (*fixedshbuf_len <= 5
        || get_md_from_hs(s, &md, fixedshbuf + 4, *fixedshbuf_len - 4) != 1
        || (hashlen = EVP_MD_size(md)) > EVP_MAX_MD_SIZE)
        goto err;
    if (for_hrr == 0) {
        hashin = s->ext.ech.innerch1;
        hashin_len = s->ext.ech.innerch1_len;
    } else {
        hashin = s->ext.ech.innerch;
        hashin_len = s->ext.ech.innerch_len;
        /* stash this SH/HRR for later */
        OPENSSL_free(s->ext.ech.kepthrr);
        s->ext.ech.kepthrr = fixedshbuf;
        s->ext.ech.kepthrr_len = *fixedshbuf_len;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: ch2hash", hashin, hashin_len);
# endif
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, hashin, hashin_len) <= 0
        || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
    if (!WPACKET_put_bytes_u8(&tpkt, SSL3_MT_MESSAGE_HASH)
        || !WPACKET_put_bytes_u24(&tpkt, hashlen)
        || !WPACKET_memcpy(&tpkt, hashval, hashlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (for_hrr == 0) {
        if (!WPACKET_memcpy(&tpkt, s->ext.ech.kepthrr,
                            s->ext.ech.kepthrr_len)
            || !WPACKET_memcpy(&tpkt, s->ext.ech.innerch,
                               s->ext.ech.innerch_len)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (!WPACKET_get_length(&tpkt, chend)
        || !WPACKET_memcpy(&tpkt, fixedshbuf, *fixedshbuf_len)
        || !WPACKET_get_length(&tpkt, tlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *tbuf = OPENSSL_malloc(*tlen);
    if (*tbuf == NULL)
        goto err;
    memcpy(*tbuf, WPACKET_get_curr(&tpkt) - *tlen, *tlen);
    /* don't double-free */
    if (for_hrr == 0 && s->ext.ech.kepthrr != fixedshbuf)
        OPENSSL_free(fixedshbuf);
    WPACKET_cleanup(&tpkt);
    BUF_MEM_free(tpkt_mem);
    return 1;
err:
    if (s->ext.ech.kepthrr != fixedshbuf) /* don't double-free */
        OPENSSL_free(fixedshbuf);
    WPACKET_cleanup(&tpkt);
    BUF_MEM_free(tpkt_mem);
    EVP_MD_CTX_free(ctx);
    return 0;
}

/*
 * @brief ECH accept_confirmation calculation
 * @param s is the SSL inner context
 * @oaram for_hrr is 1 if this is for an HRR, otherwise for SH
 * @param ac is (a caller allocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 *
 * This is a magic value in the ServerHello.random lower 8 octets
 * that is used to signal that the inner worked.
 *
 * In draft-13:
 *
 * accept_confirmation = HKDF-Expand-Label(
 *         HKDF-Extract(0, ClientHelloInner.random),
 *         "ech accept confirmation",
 *         transcript_ech_conf,
 *         8)
 *
 * transcript_ech_conf = ClientHelloInner..ServerHello
 *         with last 8 octets of ServerHello.random==0x00
 *
 * and with differences due to HRR
 *
 * We can re-factor this some more (e.g. make one call for
 * SH offsets) but we'll hold on that a bit 'till we get to
 * refactoring transcripts generally.
 */
int ech_calc_confirm(SSL_CONNECTION *s, int for_hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen)
{
    int rv = 0;
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *tbuf = NULL, *conf_loc = NULL;
    unsigned char *fixedshbuf = NULL;
    size_t fixedshbuf_len = 0, tlen = 0, chend = 0;
    size_t shoffset = 6 + 24, extoffset = 0, echoffset = 0;
    uint16_t echtype;
    unsigned int hashlen = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE], hoval[EVP_MAX_MD_SIZE];

    if (get_md_from_hs(s, &md, shbuf, shlen) != 1
        || (hashlen = EVP_MD_size(md)) > EVP_MAX_MD_SIZE)
        goto err;
    if (ech_make_transcript_buffer(s, for_hrr, shbuf, shlen, &tbuf, &tlen,
                                   &chend, &fixedshbuf_len) != 1)
        goto err; /* SSLfatal called already */
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: tbuf b4", tbuf, tlen);
# endif
    /* put zeros in correct place */
    if (for_hrr == 0) { /* zap magic octets at fixed place for SH */
        conf_loc = tbuf + chend + shoffset;
    } else {
        if (s->server == 1) { /* we get to say where we put ECH:-) */
            conf_loc = tbuf + tlen - 8;
        } else {
            if (ech_get_sh_offsets(shbuf, shlen, &extoffset,
                                   &echoffset, &echtype) != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
                goto err;
            }
            if (echoffset == 0 || extoffset == 0 || echtype == 0
                || tlen < (chend + 4 + echoffset + 4 + 8)) {
                /* No ECH found so we'll exit, but set random output */
                if (RAND_bytes_ex(s->ssl.ctx->libctx, acbuf, 8,
                                  RAND_DRBG_STRENGTH) <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_ECH_REQUIRED);
                    goto err;
                }
                rv = 1;
                goto err;
            }
            conf_loc = tbuf + chend + 4 + echoffset + 4;
        }
    }
    memset(conf_loc, 0, 8);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: tbuf after", tbuf, tlen);
# endif
    hashlen = EVP_MD_size(md);
    if ((ctx = EVP_MD_CTX_new()) == NULL
        || EVP_DigestInit_ex(ctx, md, NULL) <= 0
        || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
        || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(ctx);
    ctx = NULL;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: hashval", hashval, hashlen);
# endif
    if (ech_hkdf_extract_wrap(s, md, for_hrr, hashval, hashlen, hoval) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(acbuf, hoval, 8); /* Finally, set the output */
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("cx: result", acbuf, 8);
# endif
    /* put confirm value back into transcript vars */
    if (s->hello_retry_request != SSL_HRR_NONE && s->ext.ech.kepthrr != NULL
        && for_hrr == 1 && s->server == 1)
        memcpy(s->ext.ech.kepthrr + s->ext.ech.kepthrr_len - 8, acbuf, 8);
    memcpy(conf_loc, acbuf, 8);
    /* on a server, we need to reset the hs buffer now */
    if (s->server && s->hello_retry_request == SSL_HRR_NONE)
        ech_reset_hs_buffer(s, s->ext.ech.innerch, s->ext.ech.innerch_len);
    if (s->server && s->hello_retry_request == SSL_HRR_COMPLETE)
        ech_reset_hs_buffer(s, tbuf, tlen - fixedshbuf_len);
    rv = 1;
err:
    OPENSSL_free(fixedshbuf);
    OPENSSL_free(tbuf);
    EVP_MD_CTX_free(ctx);
    return rv;
}

/*
 * @brief Find ECH acceptance signal in a SH
 * @param s is the SSL inner context
 * @oaram for_hrr is 1 if this is for an HRR, otherwise for SH
 * @param ac is (preallocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 */
int ech_find_confirm(SSL_CONNECTION *s, int hrr, unsigned char *acbuf,
                     const unsigned char *shbuf, const size_t shlen)
{
    const unsigned char *acp = NULL;

    if (hrr == 0) {
        if (shlen < CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE)
            return 0;
        acp = shbuf + CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE - 8;
        memcpy(acbuf, acp, 8);
        return 1;
    }
    if (hrr == 1) {
        PACKET pkt;
        const unsigned char *pp_tmp;
        unsigned int pi_tmp, etype, elen;
        int done = 0;

        if (!PACKET_buf_init(&pkt, shbuf, shlen)
            || !PACKET_get_net_2(&pkt, &pi_tmp)
            || !PACKET_get_bytes(&pkt, &pp_tmp, SSL3_RANDOM_SIZE)
            || !PACKET_get_1(&pkt, &pi_tmp) /* sessid len */
            || !PACKET_get_bytes(&pkt, &pp_tmp, pi_tmp) /* sessid */
            || !PACKET_get_net_2(&pkt, &pi_tmp) /* ciphersuite */
            || !PACKET_get_1(&pkt, &pi_tmp) /* compression */
            || !PACKET_get_net_2(&pkt, &pi_tmp)) /* len(extensions) */
            return 0;
        while (PACKET_remaining(&pkt) > 0 && done < 1) {
            if (!PACKET_get_net_2(&pkt, &etype)
                || !PACKET_get_net_2(&pkt, &elen))
                return 0;
            if (etype == TLSEXT_TYPE_ech) {
                if (elen != 8
                    || !PACKET_get_bytes(&pkt, &acp, elen))
                    return 0;
                memcpy(acbuf, acp, elen);
                done++;
            } else {
                if (!PACKET_get_bytes(&pkt, &pp_tmp, elen))
                    return 0;
            }
        }
        return done;
    }
    return 0;
}

/*
 * @brief Swap the inner and outer
 * @param s is the SSL connection to swap about
 * @return 0 for error, 1 for success
 *
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 */
int ech_swaperoo(SSL_CONNECTION *s)
{
    unsigned char *curr_buf = NULL;
    size_t curr_buflen = 0;
    unsigned char *new_buf = NULL;
    size_t new_buflen = 0;
    size_t outer_chlen = 0;
    size_t other_octets = 0;

# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, b4", s);
# endif

    /* Make some checks */
    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* un-stash inner key share */
    if (s->ext.ech.tmp_pkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_PKEY_free(s->s3.tmp.pkey);
    s->s3.tmp.pkey = s->ext.ech.tmp_pkey;
    s->s3.group_id = s->ext.ech.group_id;
    s->ext.ech.tmp_pkey = NULL;

    /*
     * When not doing HRR...
     * Fix up the transcript to reflect the inner CH
     * If there's a cilent hello at the start of the buffer, then
     * it's likely that's the outer CH and we want to replace that
     * with the inner. We need to be careful that there could be a
     * server hello following and can't lose that.
     * I don't think the outer client hello can be anwhere except
     * at the start of the buffer.
     *
     * For HRR... we'll try leave it alone as (I think)
     * the HRR processing code has already fixed up the
     * buffer.
     */
    if (s->hello_retry_request == 0) {
        curr_buflen = BIO_get_mem_data(s->s3.handshake_buffer,
                                       &curr_buf);
        if (curr_buflen > 4 && curr_buf[0] == SSL3_MT_CLIENT_HELLO) {
            /* It's a client hello, presumably the outer */
            outer_chlen = 1 + curr_buf[1] * 256 * 256
                + curr_buf[2] * 256 + curr_buf[3];
            if (outer_chlen > curr_buflen) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            other_octets = curr_buflen - outer_chlen;
            if (other_octets > 0) {
                new_buflen = s->ext.ech.innerch_len + other_octets;
                new_buf = OPENSSL_malloc(new_buflen);
                if (new_buf == NULL)
                    return 0;
                if (s->ext.ech.innerch != NULL) /* asan check added */
                    memcpy(new_buf, s->ext.ech.innerch,
                           s->ext.ech.innerch_len);
                memcpy(new_buf + s->ext.ech.innerch_len,
                       &curr_buf[outer_chlen], other_octets);
            } else {
                new_buf = s->ext.ech.innerch;
                new_buflen = s->ext.ech.innerch_len;
            }
        } else {
            new_buf = s->ext.ech.innerch;
            new_buflen = s->ext.ech.innerch_len;
        }
        /*
         * And now reset the handshake transcript to our buffer
         * Note ssl3_finish_mac isn't that great a name - that one just
         * adds to the transcript but doesn't actually "finish" anything
         */
        if (ssl3_init_finished_mac(s) == 0) {
            if (other_octets > 0) {
                OPENSSL_free(new_buf);
            }
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (ssl3_finish_mac(s, new_buf, new_buflen) == 0) {
            if (other_octets > 0) {
                OPENSSL_free(new_buf);
            }
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (other_octets > 0) {
            OPENSSL_free(new_buf);
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_ptranscript("ech_swaperoo, after", s);
# endif
    /*
     * Finally! Declare victory - in both contexts.
     * The outer's ech_attempted will have been set already
     * but not the rest of 'em.
     */
    s->ext.ech.attempted = 1;
    s->ext.ech.success = 1;
    s->ext.ech.done = 1;
    s->ext.ech.grease = OSSL_ECH_NOT_GREASE;

    /* call ECH callback */
    if (s->ext.ech.cfgs != NULL && s->ext.ech.done == 1
        && s->hello_retry_request != SSL_HRR_PENDING
        && s->ext.ech.cb != NULL) {
        char pstr[OSSL_ECH_PBUF_SIZE + 1];
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv = 0;

        memset(pstr, 0, OSSL_ECH_PBUF_SIZE + 1);
        SSL_ech_print(biom, &s->ssl, OSSL_ECH_SELECT_ALL);
        BIO_read(biom, pstr, OSSL_ECH_PBUF_SIZE);
        cbrv = s->ext.ech.cb(&s->ssl, pstr);
        BIO_free(biom);
        if (cbrv != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    return 1;
}

/*
 * @brief send a GREASy ECH
 * @param s is the SSL connection
 * @param pkt is the in-work CH packet
 * @return 1 for success, 0 otherwise
 *
 * We send some random stuff that we hope looks like a real ECH
 * The unused parameters are just to match tls_construct_ctos_ech
 * which calls this - that's in case we need 'em later.
 */
int ech_send_grease(SSL_CONNECTION *s, WPACKET *pkt)
{
    OSSL_HPKE_SUITE hpke_suite_in = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE *hpke_suite_in_p = NULL;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    size_t cid_len = 1;
    unsigned char cid;
    size_t senderpub_len = OSSL_ECH_MAX_GREASE_PUB;
    unsigned char senderpub[OSSL_ECH_MAX_GREASE_PUB];
    size_t cipher_len = OSSL_ECH_DEF_CIPHER_LEN_SMALL;
    size_t cipher_len_jitter = OSSL_ECH_DEF_CIPHER_LEN_JITTER;
    unsigned char cipher[OSSL_ECH_MAX_GREASE_CT];
    /* stuff for copying to ech_sent */
    unsigned char *pp = WPACKET_get_curr(pkt);
    size_t pp_at_start = 0;
    size_t pp_at_end = 0;

    if (s == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ech_same_key_share() == 0)
        cipher_len = OSSL_ECH_DEF_CIPHER_LEN_LARGE;
    WPACKET_get_total_written(pkt, &pp_at_start);
    /* generate a random (1 octet) client id */
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, cid_len,
                      RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->ext.ech.attempted_cid = cid;
    /*
     * if adding jitter, we adjust cipher length by some random
     * number between +/- cipher_len_jitter
     */
    if (cipher_len_jitter != 0) {
        cipher_len_jitter = cipher_len_jitter % OSSL_ECH_MAX_CIPHER_LEN_JITTER;
        if (cipher_len < cipher_len_jitter) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        cipher_len -= cipher_len_jitter;
        /* the cid is random enough */
        cipher_len += 2 * (cid % cipher_len_jitter);
    }
    if (s->ext.ech.grease_suite != NULL) {
        if (OSSL_HPKE_str2suite(s->ext.ech.grease_suite, &hpke_suite_in) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        hpke_suite_in_p = &hpke_suite_in;
    }
    if (OSSL_HPKE_get_grease_value(hpke_suite_in_p, &hpke_suite,
                                   senderpub, &senderpub_len,
                                   cipher, cipher_len,
                                   s->ssl.ctx->libctx, NULL) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->ext.ech.attempted_type == TLSEXT_TYPE_ech) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech.attempted_type)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_memcpy(pkt, &cid, cid_len)
            || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
            || !WPACKET_close(pkt)
            ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* record the ECH sent so we can re-tx same if we hit an HRR */
    OPENSSL_free(s->ext.ech.sent);
    WPACKET_get_total_written(pkt, &pp_at_end);
    s->ext.ech.sent_len = pp_at_end - pp_at_start;
    s->ext.ech.sent = OPENSSL_malloc(s->ext.ech.sent_len);
    if (s->ext.ech.sent == NULL)
        return 0;
    memcpy(s->ext.ech.sent, pp, s->ext.ech.sent_len);
    s->ext.ech.grease = OSSL_ECH_IS_GREASE;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "ECH - sending DRAFT-13 GREASE\n");
    } OSSL_TRACE_END(TLS);
    return 1;
}

/*
 * @brief pick an ECHConfig to use
 * @param s is the SSL connection
 * @param tc is the ECHConfig to use (if found)
 * @param suite is the HPKE suite to use (if found)
 *
 * Search through the ECHConfigList for one that's a best
 * match in terms of outer_name vs. public_name.
 * If no public_name was set via API then we
 * just take the 1st match where we locally support
 * the HPKE suite.
 * If OTOH, a public_name was provided via API then
 * we prefer the first that matches that. We only try
 * for case-insensitive exact matches.
 * If no outer was provided, any will do.
 */
int ech_pick_matching_cfg(SSL_CONNECTION *s, ECHConfig **tc,
                          OSSL_HPKE_SUITE *suite)
{
    int namematch = 0;
    int nameoverride = 0;
    int suitematch = 0;
    int cind = 0;
    unsigned int csuite = 0;
    ECHConfig *ltc = NULL;
    ECHConfigList *cfgs = NULL;
    unsigned char *es = NULL;
    char *hn = NULL;
    unsigned int hnlen = 0;

    if (s == NULL || s->ext.ech.cfgs == NULL || tc == NULL || suite == NULL)
        return 0;
    cfgs = s->ext.ech.cfgs->cfg;
    if (cfgs == NULL || cfgs->nrecs == 0) {
        return 0;
    }
    /* allow API-set pref to override */
    hn = s->ext.ech.cfgs->outer_name;
    hnlen = (hn == NULL ? 0 : strlen(hn));
    if (hnlen != 0)
        nameoverride = 1;
    if (hnlen == 0 && s->ext.ech.cfgs->no_outer != 1) {
        /* fallback to outer hostname, if set */
        hn = s->ext.ech.outer_hostname;
        hnlen = (hn == NULL ? 0 : strlen(hn));
    }
    for (cind = 0;
         cind != cfgs->nrecs && suitematch == 0 && namematch == 0;
         cind++) {
        ltc = &cfgs->recs[cind];
        if (ltc->version != OSSL_ECH_RFCXXXX_VERSION)
            continue;
        if (nameoverride == 1) {
            namematch = 1;
        } else {
            namematch = 0;
            if (hnlen == 0
                || (ltc->public_name != NULL
                    && ltc->public_name_len == hnlen
                    && !OPENSSL_strncasecmp(hn, (char *)ltc->public_name,
                                            hnlen))) {
                namematch = 1;
            }
        }
        suite->kem_id = ltc->kem_id;
        suitematch = 0;
        for (csuite = 0;
             csuite != ltc->nsuites && suitematch == 0;
             csuite++) {
            es = (unsigned char *)&ltc->ciphersuites[csuite];
            suite->kdf_id = es[0] * 256 + es[1];
            suite->aead_id = es[2] * 256 + es[3];
            if (OSSL_HPKE_suite_check(*suite) == 1) {
                suitematch = 1;
                /* pick this one if both "fit" */
                if (namematch == 1) {
                    *tc = ltc;
                    break;
                }
            }
        }
    }
    if (namematch == 0 || suitematch == 0) {
        return 0;
    }
    if (*tc == NULL || (*tc)->pub_len == 0 || (*tc)->pub == NULL)
        return 0;
    return 1;
}

/**
 * @brief Calculate AAD and then do ECH encryption
 * @param s is the SSL connection
 * @param pkt is the packet to send
 * @return 1 for success, other otherwise
 *
 * 1. Make up the AAD:
 *        For draft-13: the encoded outer, with ECH ciphertext octets zero'd
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 */
int ech_aad_and_encrypt(SSL_CONNECTION *s, WPACKET *pkt)
{
    int rv = 0, hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char *clear = NULL, *cipher = NULL, *aad = NULL;
    size_t cipherlen = 0, aad_len = 0, lenclen = 0, mypub_len = 0;
    unsigned char config_id_to_use = 0x00;
    unsigned char *mypub = NULL; /* client's ephemeral public */
    ECHConfig *tc = NULL; /* matching server public key (if one exists) */
    unsigned char info[SSL3_RT_MAX_PLAIN_LENGTH];
    size_t info_len = SSL3_RT_MAX_PLAIN_LENGTH;
    size_t clear_len = 0;

    if (s == NULL || s->ext.ech.cfgs == NULL
        || pkt == NULL || s->ssl.ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    rv = ech_pick_matching_cfg(s, &tc, &hpke_suite);
    if (rv != 1 || tc == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    s->ext.ech.attempted_type = tc->version;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EAAE: selected: version: %4x, config %2x\n",
                   tc->version, tc->config_id);
    } OSSL_TRACE_END(TLS);
    config_id_to_use = tc->config_id;
    /* if requested, use a random config_id instead */
    if (s->ssl.ctx->options & SSL_OP_ECH_IGNORE_CID
        || s->options & SSL_OP_ECH_IGNORE_CID) {
        if (RAND_bytes_ex(s->ssl.ctx->libctx, &config_id_to_use, 1,
                          RAND_DRBG_STRENGTH) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE: random config_id", &config_id_to_use, 1);
# endif
    }
    s->ext.ech.attempted_cid = config_id_to_use;
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: peer pub", tc->pub, tc->pub_len);
    ech_pbuf("EAAE: clear", s->ext.ech.encoded_innerch,
             s->ext.ech.encoded_innerch_len);
    ech_pbuf("EAAE: ECHConfig", tc->encoding_start, tc->encoding_length);
# endif
    /*
     * For draft-13 the AAD is the full outer client hello but
     * with the correct number of zeros for where the ECH ciphertext
     * octets will later be placed. So we add the ECH extension to
     * the |pkt| but with zeros for ciphertext - that'll form up the
     * AAD for us, then after we've encrypted, we'll splice in the
     * actual ciphertext
     * Watch out for the "4" offsets that remove the type
     * and 3-octet length from the encoded CH as per the spec.
     */
    clear_len = ech_calc_padding(s, tc);
    if (clear_len == 0)
        goto err;
    lenclen = OSSL_HPKE_get_public_encap_size(hpke_suite);
    if (s->ext.ech.hpke_ctx == NULL) {
        if (ech_helper_make_enc_info(tc->encoding_start, tc->encoding_length,
                                     info, &info_len) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
# ifdef OSSL_ECH_SUPERVERBOSE
        ech_pbuf("EAAE info", info, info_len);
# endif
        s->ext.ech.hpke_ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                                OSSL_HPKE_ROLE_SENDER,
                                                NULL, NULL);
        if (s->ext.ech.hpke_ctx == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mypub = OPENSSL_malloc(lenclen);
        if (mypub == NULL)
            goto err;
        mypub_len = lenclen;
        rv = OSSL_HPKE_encap(s->ext.ech.hpke_ctx, mypub, &mypub_len,
                             tc->pub, tc->pub_len, info, info_len);
        if (rv != 1) {
            OPENSSL_free(mypub);
            mypub = NULL;
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        s->ext.ech.pub = mypub;
        s->ext.ech.pub_len = mypub_len;
    } else {
        /* retrieve public */
        mypub = s->ext.ech.pub;
        mypub_len = s->ext.ech.pub_len;
        if (mypub == NULL || mypub_len == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: mypub", mypub, mypub_len);
    /* re-use aad_len for tracing */
    WPACKET_get_total_written(pkt, &aad_len);
    ech_pbuf("EAAE pkt b4", WPACKET_get_curr(pkt) - aad_len, aad_len);
# endif
    cipherlen = OSSL_HPKE_get_ciphertext_size(hpke_suite, clear_len);
    if (cipherlen <= clear_len
        || cipherlen > OSSL_ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    cipher = OPENSSL_zalloc(cipherlen);
    if (cipher == NULL)
        goto err;
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, OSSL_ECH_OUTER_CH_TYPE)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
        || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
        || (s->hello_retry_request == SSL_HRR_PENDING
            && !WPACKET_put_bytes_u16(pkt, 0x00)) /* no pub */
        || (s->hello_retry_request != SSL_HRR_PENDING
            && !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len))
        || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
        || !WPACKET_close(pkt)
        || !WPACKET_get_total_written(pkt, &aad_len)
        || aad_len < 4) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aad_len -= 4; /* aad starts after type + 3-octet len */
    aad = WPACKET_get_curr(pkt) - aad_len;
    /*
     * close the extensions of the CH - we skipped doing this
     * earler when encoding extensions, to allow for adding the
     * ECH here (when doing ECH) - see tls_construct_extensions()
     * towards the end
     */
    if (!WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: aad", aad, aad_len);
# endif
    clear = OPENSSL_zalloc(clear_len); /* zeros incl. padding */
    if (clear == NULL)
        goto err;
    memcpy(clear, s->ext.ech.encoded_innerch, s->ext.ech.encoded_innerch_len);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: draft-13 padded clear", clear, clear_len);
# endif
    rv = OSSL_HPKE_seal(s->ext.ech.hpke_ctx, cipher, &cipherlen,
                        aad, aad_len, clear, clear_len);
    OPENSSL_free(clear);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EAAE: cipher", cipher, cipherlen);
    ech_pbuf("EAAE: hpke mypub", mypub, mypub_len);
# endif
    /* splice real ciphertext back in now */
    memcpy(aad + aad_len - cipherlen, cipher, cipherlen);
# ifdef OSSL_ECH_SUPERVERBOSE
    /* re-use aad_len for tracing */
    WPACKET_get_total_written(pkt, &aad_len);
    ech_pbuf("EAAE pkt aftr", WPACKET_get_curr(pkt) - aad_len, aad_len);
# endif
    OPENSSL_free(cipher);
    return 1;
err:
    OPENSSL_free(cipher);
    return 0;
}

/*
 * @brief If an ECH is present, attempt decryption
 * @param s SSL connection
 * @prarm outerpkt is the packet with the outer CH
 * @prarm newpkt is the packet with the decrypted inner CH
 * @return 1 for success, other otherwise
 *
 * If decryption succeeds, the caller can swap the inner and outer
 * CHs so that all further processing will only take into account
 * the inner CH.
 *
 * The fact that decryption worked is signalled to the caller
 * via s->ext.ech.success
 *
 * This function is called early, (hence then name:-), before
 * the outer CH decoding has really started, so we need to be
 * careful peeking into the packet
 *
 * The plan:
 * 1. check if there's an ECH
 * 2. trial-decrypt or check if config matches one loaded
 * 3. if decrypt fails tee-up GREASE
 * 4. if decrypt worked, decode and de-compress cleartext to
 *    make up real inner CH for later processing
 */
int ech_early_decrypt(SSL_CONNECTION *s, PACKET *outerpkt, PACKET *newpkt)
{
    int rv = 0, cfgind = -1, foundcfg = 0, forhrr = 0, innerflag = -1;
    OSSL_ECH_ENCCH *extval = NULL;
    PACKET echpkt;
    const unsigned char *startofech = NULL, *opd = NULL;
    size_t echlen = 0, clearlen = 0, aad_len = SSL3_RT_MAX_PLAIN_LENGTH;
    unsigned char *clear = NULL, aad[SSL3_RT_MAX_PLAIN_LENGTH];
    /* offsets of things within CH */
    size_t startofsessid = 0, startofexts = 0, echoffset = 0;
    size_t outersnioffset = 0, startofciphertext = 0;
    size_t lenofciphertext = 0, opl = 0;
    uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
    char *osni_str = NULL;

    if (s == NULL || outerpkt == NULL || newpkt == NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
    /* find offsets - on success, outputs are safe to use */
    rv = ech_get_ch_offsets(s, outerpkt, &startofsessid, &startofexts,
                            &echoffset, &echtype, &innerflag, &outersnioffset);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (echoffset == 0 || echtype != TLSEXT_TYPE_ech)
        return 1; /* ECH not present or wrong version */
    if (innerflag == 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
    s->ext.ech.attempted = 1; /* Remember that we got an ECH */
    s->ext.ech.attempted_type = echtype;
    if (s->hello_retry_request == SSL_HRR_PENDING)
        forhrr = 1; /* set forhrr if that's correct */
    opl = PACKET_remaining(outerpkt);
    opd = PACKET_data(outerpkt);
    s->tmp_session_id_len = opd[startofsessid]; /* grab the session id */
    if (s->tmp_session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH
        || startofsessid + 1 + s->tmp_session_id_len > opl) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(s->tmp_session_id, &opd[startofsessid + 1],
           s->tmp_session_id_len);
    if (outersnioffset > 0) { /* Grab the outer SNI for tracing */
        if (ech_get_outer_sni(s, &osni_str, opd, opl, outersnioffset) != 1
            || osni_str == NULL) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: outer SNI of %s\n", osni_str);
        } OSSL_TRACE_END(TLS);
    } else {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "EARLY: no sign of an outer SNI\n");
        } OSSL_TRACE_END(TLS);
    }
    /* trial-decrypt or check if config matches one loaded */
    if (echoffset > opl - 4)
        goto err;
    startofech = &opd[echoffset + 4];
    echlen = opd[echoffset + 2] * 256 + opd[echoffset + 3];
    if (echlen > opl - echoffset - 4)
        goto err;
    if (PACKET_buf_init(&echpkt, startofech, echlen) != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (ech_decode_inbound_ech(s, &echpkt, &extval, &startofciphertext) != 1)
        goto err; /* SSLfatal already called if needed */
    /*
     * startofciphertext so far is within the ECH value and after the
     * length of the ciphertext, so we need to bump it by the offset
     * of ECH within the CH plus the ECH type (2 octets) and
     * length (also 2 octets) and that ciphertext length (another
     * 2 octets) for a total of 6 octets
     */
    startofciphertext += echoffset + 6;
    lenofciphertext = extval->payload_len;
    aad_len = opl;
    memcpy(aad, opd, aad_len);
    memset(aad + startofciphertext, 0, lenofciphertext);
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("EARLY aad", aad, aad_len);
# endif
    /* See if any of our configs match, or trial decrypt if needed */
    s->ext.ech.grease = OSSL_ECH_GREASE_UNKNOWN;
    if (s->ext.ech.cfgs->cfg == NULL || s->ext.ech.cfgs->cfg->nrecs == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    for (cfgind = 0; cfgind != s->ext.ech.ncfgs; cfgind++) {
        ECHConfig *e = &s->ext.ech.cfgs[cfgind].cfg->recs[0];

        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                       "EARLY: rx'd config id (%x) ==? %d-th configured (%x)\n",
                       extval->config_id, cfgind, e->config_id);
        } OSSL_TRACE_END(TLS);
        if (extval->config_id == e->config_id) {
            foundcfg = 1;
            break;
        }
    }
    if (s->ext.ech.encoded_innerch != NULL) { /* this happens with HRR */
        OPENSSL_free(s->ext.ech.encoded_innerch);
        s->ext.ech.encoded_innerch = NULL;
        s->ext.ech.encoded_innerch_len = 0;
    }
    if (foundcfg == 1) {
        clear = hpke_decrypt_encch(s, &s->ext.ech.cfgs[cfgind], extval,
                                   aad_len, aad, forhrr, &clearlen);
        if (clear == NULL) {
            s->ext.ech.grease = OSSL_ECH_IS_GREASE;
        }
    }
    /* if still needed, trial decryptions */
    if (clear == NULL && (s->options & SSL_OP_ECH_TRIALDECRYPT)) {
        foundcfg = 0; /* reset as we're trying again */
        for (cfgind = 0; cfgind != s->ext.ech.ncfgs; cfgind++) {
            clear = hpke_decrypt_encch(s, &s->ext.ech.cfgs[cfgind], extval,
                                       aad_len, aad, forhrr, &clearlen);
            if (clear != NULL) {
                foundcfg = 1;
                s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
                break;
            }
        }
    }
    /* decrypting worked or not, but we're done with that now  */
    s->ext.ech.done = 1;
    /* 3. if decrypt fails tee-up GREASE */
    s->ext.ech.grease = OSSL_ECH_IS_GREASE;
    s->ext.ech.success = 0;
    if (clear != NULL) {
        s->ext.ech.grease = OSSL_ECH_NOT_GREASE;
        s->ext.ech.success = 1;
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "EARLY: success: %d, assume_grease: %d, "
                   "foundcfg: %d, cfgind: %d, clearlen: %zd, clear %p\n",
                   s->ext.ech.success, s->ext.ech.grease, foundcfg,
                   cfgind, clearlen, (void *)clear);
    } OSSL_TRACE_END(TLS);
# ifdef OSSL_ECH_SUPERVERBOSE
    if (foundcfg == 1 && clear != NULL) { /* Bit more logging */
        SSL_ECH *se = &s->ext.ech.cfgs[cfgind];
        ECHConfigList *seg = se->cfg;
        ECHConfig *e = &seg->recs[0];

        ech_pbuf("local config_id", &e->config_id, 1);
        ech_pbuf("remote config_id", &extval->config_id, 1);
        ech_pbuf("clear", clear, clearlen);
    }
# endif
    if (extval != NULL) {
        OSSL_ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval = NULL;
    }
    if (s->ext.ech.grease == OSSL_ECH_IS_GREASE)
        return 1;
    /* 4. if decrypt worked, de-compress cleartext to make up real inner CH */
    s->ext.ech.encoded_innerch = clear;
    s->ext.ech.encoded_innerch_len = clearlen;
    if (ech_decode_inner(s, opd, opl) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
# ifdef OSSL_ECH_SUPERVERBOSE
    ech_pbuf("Inner CH (decoded)", s->ext.ech.innerch, s->ext.ech.innerch_len);
# endif
    /*
     * The +4 below is because tls_process_client_hello doesn't
     * want to be given the message type & length, so the buffer should
     * start with the version octets (0x03 0x03)
     */
    if (PACKET_buf_init(newpkt, s->ext.ech.innerch + 4,
                        s->ext.ech.innerch_len - 4) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* we may need to fix up the overall 3-octet CH length */
    if (s->init_buf != NULL && s->init_buf->data != NULL) {
        unsigned char *rwm = (unsigned char *)s->init_buf->data;
        size_t olen = s->ext.ech.innerch_len - 4;

        rwm[1] = (olen >> 16) % 256;
        rwm[2] = (olen >> 8) % 256;
        rwm[3] = olen % 256;
    }
    return 1;
err:
    if (extval != NULL) {
        OSSL_ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval = NULL;
    }
    return 0;
}

/*
 * @brief copy an inner extension value to outer
 * @param s is the SSL connection
 * @param ext_type is the extension type
 * @param pkt is the outer packet being encoded
 * @return the relevant OSSL_ECH_SAME_EXT_* value
 *
 * We assume the inner CH has been pre-decoded into
 * s->clienthello->pre_proc_exts already
 *
 * The extension value could be empty (i.e. zero length)
 * but that's ok.
 */
int ech_copy_inner2outer(SSL_CONNECTION *s, uint16_t ext_type, WPACKET *pkt)
{
    size_t ind = 0;
    RAW_EXTENSION *myext = NULL;
    RAW_EXTENSION *raws = s->clienthello->pre_proc_exts;
    size_t nraws = 0;

    if (s == NULL || s->clienthello == NULL)
        return OSSL_ECH_SAME_EXT_ERR;
    raws = s->clienthello->pre_proc_exts;
    if (raws == NULL)
        return OSSL_ECH_SAME_EXT_ERR;
    nraws = s->clienthello->pre_proc_exts_len;
    /* copy inner to outer */
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "inner2outer: Copying ext type %d to outer\n",
                   ext_type);
    } OSSL_TRACE_END(TLS);
    for (ind = 0; ind != nraws; ind++) {
        if (raws[ind].type == ext_type) {
            myext = &raws[ind];
            break;
        }
    }
    if (myext == NULL) {
        /* This one wasn't in inner, so re-do processing */
        return OSSL_ECH_SAME_EXT_CONTINUE;
    }
    /* copy inner value to outer */
    if (PACKET_data(&myext->data) != NULL
        && PACKET_remaining(&myext->data) > 0) {
        if (!WPACKET_put_bytes_u16(pkt, ext_type)
            || !WPACKET_sub_memcpy_u16(pkt, PACKET_data(&myext->data),
                                       PACKET_remaining(&myext->data)))
            return OSSL_ECH_SAME_EXT_ERR;
    } else {
        /* empty extension */
        if (!WPACKET_put_bytes_u16(pkt, ext_type)
            || !WPACKET_put_bytes_u16(pkt, 0))
            return OSSL_ECH_SAME_EXT_ERR;
    }
    return 1;
}

/*
 * @brief assemble the set of ECHConfig values to return as a retry-config
 * @param s is the SSL connection
 * @param rcfgs is a list of ECHConfig's
 * @param rcfgslen is the length of rcfgs
 * @return 1 for success, anything else for failure
 *
 * The caller needs to OPENSSL_free the rcfgs.
 * The rcfgs itself is missing the outer length to make it an ECHConfigList
 * so that caller has to add that.
 */
int ech_get_retry_configs(SSL_CONNECTION *s, unsigned char **rcfgs,
                          size_t *rcfgslen)
{
    unsigned char *rets = NULL;
    size_t retslen = 0;
    int i;
    SSL_ECH *se = NULL;
    unsigned char *tmp = NULL;
    unsigned char *enci = NULL;
    size_t encilen = 0;

    for (i = 0; i != s->ext.ech.ncfgs; i++) {
        se = &s->ext.ech.cfgs[i];
        if (se != NULL && se->for_retry == SSL_ECH_USE_FOR_RETRY
            && se->cfg != NULL) {
            encilen = se->cfg->encoded_len;
            if (encilen < 2)
                goto err;
            encilen -= 2;
            enci = se->cfg->encoded + 2;
            tmp = (unsigned char *)OPENSSL_realloc(rets, retslen + encilen);
            if (tmp == NULL)
                goto err;
            rets = tmp;
            memcpy(rets + retslen, enci, encilen);
            retslen += encilen;
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "retry-config: ECHConfig loaded at %lu "
                           "from %s\n",
                           (unsigned long)se->loadtime, se->pemfname);
            } OSSL_TRACE_END(TLS);
        }
    }

    *rcfgs = rets;
    *rcfgslen = retslen;
    return 1;
err:
    OPENSSL_free(rets);
    *rcfgs = NULL;
    *rcfgslen = 0;
    return 0;
}

/* SECTION: Public APIs */

/* Documentation in doc/man3/SSL_ech_set1_echconfig.pod */

void OSSL_ECH_INFO_free(OSSL_ECH_INFO *in, int size)
{
    int i = 0;

    if (in == NULL)
        return;
    for (i = 0; i != size; i++) {
        OPENSSL_free(in[i].public_name);
        OPENSSL_free(in[i].inner_name);
        OPENSSL_free(in[i].outer_alpns);
        OPENSSL_free(in[i].inner_alpns);
        OPENSSL_free(in[i].echconfig);
    }
    OPENSSL_free(in);
    return;
}

int OSSL_ECH_INFO_print(BIO *out, OSSL_ECH_INFO *se, int count)
{
    int i = 0;

    if (out == NULL || se == NULL || count == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    BIO_printf(out, "ECH details (%d configs total)\n", count);
    for (i = 0; i != count; i++) {
        BIO_printf(out, "index: %d: SNI (inner:%s;outer:%s), "
                   "ALPN (inner:%s;outer:%s)\n\t%s\n",
                   i,
                   se[i].inner_name != NULL ? se[i].inner_name : "NULL",
                   se[i].public_name != NULL ? se[i].public_name : "NULL",
                   se[i].inner_alpns != NULL ? se[i].inner_alpns : "NULL",
                   se[i].outer_alpns != NULL ? se[i].outer_alpns : "NULL",
                   se[i].echconfig != NULL ? se[i].echconfig : "NULL");
    }
    return 1;
}

int SSL_ech_set1_echconfig(SSL *ssl, const unsigned char *val, size_t len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    SSL_ECH *echs = NULL;
    SSL_ECH *tmp = NULL;
    int num_echs = 0;

    if (s == NULL || val == NULL || len == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(OSSL_ECH_FMT_GUESS, len, val, &num_echs, &echs) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_echs == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.cfgs == NULL) {
        s->ext.ech.cfgs = echs;
        s->ext.ech.ncfgs = num_echs;
        s->ext.ech.attempted = 1;
        s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
        s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(s->ext.ech.cfgs,
                          (s->ext.ech.ncfgs + num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL) {
        SSL_ECH_free_arr(echs, num_echs);
        OPENSSL_free(echs);
        return 0;
    }
    s->ext.ech.cfgs = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&s->ext.ech.cfgs[s->ext.ech.ncfgs], echs,
           num_echs * sizeof(SSL_ECH));
    s->ext.ech.ncfgs += num_echs;
    OPENSSL_free(echs);
    return 1;
}

int SSL_CTX_ech_set1_echconfig(SSL_CTX *ctx, const unsigned char *val,
                               size_t len)
{
    SSL_ECH *echs = NULL;
    SSL_ECH *tmp = NULL;
    int num_echs = 0;

    if (ctx == NULL || val == NULL || len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (local_ech_add(OSSL_ECH_FMT_GUESS, len, val, &num_echs, &echs) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_echs == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->ext.ech == NULL) {
        ctx->ext.ech = echs;
        ctx->ext.nechs = num_echs;
        return 1;
    }
    /* otherwise accumulate */
    tmp = OPENSSL_realloc(ctx->ext.ech,
                          (ctx->ext.nechs + num_echs) * sizeof(SSL_ECH));
    if (tmp == NULL) {
        SSL_ECH_free_arr(echs, num_echs);
        OPENSSL_free(echs);
        return 0;
    }
    ctx->ext.ech = tmp;
    /* shallow copy top level, keeping lower levels */
    memcpy(&ctx->ext.ech[ctx->ext.nechs], echs, num_echs * sizeof(SSL_ECH));
    ctx->ext.nechs += num_echs;
    /* top level can now be free'd */
    OPENSSL_free(echs);
    return 1;
}

int SSL_ech_set_server_names(SSL *ssl, const char *inner_name,
                             const char *outer_name, int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /*
     * Note: we could not require s->ext.ech.cfgs to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ext.ech.cfgs array.)
     * Same applies to SSL_ech_set_outer_server_name()
     */
    if (s->ext.ech.cfgs == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    OPENSSL_free(s->ext.hostname);
    s->ext.hostname = OPENSSL_strdup(inner_name);
    if (s->ext.hostname == NULL)
        return 0;
    for (nind = 0; nind != s->ext.ech.ncfgs; nind++) {
        OPENSSL_free(s->ext.ech.cfgs[nind].inner_name);
        s->ext.ech.cfgs[nind].inner_name = NULL;
        if (inner_name != NULL && strlen(inner_name) > 0)
            s->ext.ech.cfgs[nind].inner_name = OPENSSL_strdup(inner_name);
        OPENSSL_free(s->ext.ech.cfgs[nind].outer_name);
        s->ext.ech.cfgs[nind].outer_name = NULL;
        s->ext.ech.cfgs[nind].no_outer = no_outer;
        if (no_outer == 0 && outer_name != NULL && strlen(outer_name) > 0) {
            s->ext.ech.cfgs[nind].outer_name = OPENSSL_strdup(outer_name);
        }
    }
    s->ext.ech.attempted = 1;
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    return 1;
}

int SSL_ech_set_outer_server_name(SSL *ssl, const char *outer_name,
                                  int no_outer)
{
    int nind = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /*
     * Note: we could not require s->ext.ech.cfgs to be set already here but
     * seems just as reasonable to impose an ordering on the sequence
     * of calls. (And it means we don't need somewhere to stash the
     * names outside of the s->ext.ech.cfgs array.)
     * Same applies to SSL_ech_set_server_names()
     */
    if (s->ext.ech.cfgs == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    for (nind = 0; nind != s->ext.ech.ncfgs; nind++) {
        OPENSSL_free(s->ext.ech.cfgs[nind].outer_name);
        s->ext.ech.cfgs[nind].outer_name = NULL;
        s->ext.ech.cfgs[nind].no_outer = no_outer;
        if (no_outer == 0 && outer_name != NULL && strlen(outer_name) > 0) {
            s->ext.ech.cfgs[nind].outer_name = OPENSSL_strdup(outer_name);
        }
        /* if this is called and an SNI is set already we copy that to inner */
        if (s->ext.hostname != NULL) {
            OPENSSL_free(s->ext.ech.cfgs[nind].inner_name);
            s->ext.ech.cfgs[nind].inner_name = OPENSSL_strdup(s->ext.hostname);
        }
    }
    s->ext.ech.attempted = 1;
    s->ext.ech.attempted_type = TLSEXT_TYPE_ech_unknown;
    s->ext.ech.attempted_cid = TLSEXT_TYPE_ech_config_id_unset;
    return 1;
}

int SSL_ech_get_info(SSL *ssl, OSSL_ECH_INFO **out, int *nindices)
{
    OSSL_ECH_INFO *rdiff = NULL;
    int i = 0;
    int indices = 0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    BIO *tbio = NULL;

    if (s == NULL || out == NULL || nindices == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    indices = s->ext.ech.ncfgs;
    if (s->ext.ech.cfgs == NULL || s->ext.ech.ncfgs <= 0) {
        *out = NULL;
        *nindices = 0;
        return 1;
    }
    rdiff = OPENSSL_zalloc(s->ext.ech.ncfgs * sizeof(OSSL_ECH_INFO));
    if (rdiff == NULL)
        goto err;
    for (i = 0; i != s->ext.ech.ncfgs; i++) {
        OSSL_ECH_INFO *inst = &rdiff[i];

        if (s->ext.ech.cfgs->inner_name != NULL) {
            inst->inner_name = OPENSSL_strdup(s->ext.ech.cfgs->inner_name);
            if (inst->inner_name == NULL)
                goto err;
        }
        if (s->ext.ech.cfgs->outer_name != NULL) {
            inst->public_name = OPENSSL_strdup(s->ext.ech.cfgs->outer_name);
            if (inst->public_name == NULL)
                goto err;
        }
        if (s->ext.alpn != NULL) {
            inst->inner_alpns = alpn_print(s->ext.alpn, s->ext.alpn_len);
        }
        if (s->ext.ech.alpn_outer != NULL) {
            inst->outer_alpns = alpn_print(s->ext.ech.alpn_outer,
                                           s->ext.ech.alpn_outer_len);
        }
        /* Now "print" the ECHConfigList */
        if (s->ext.ech.cfgs[i].cfg != NULL) {
            size_t ehlen;
            unsigned char *ignore = NULL;

            tbio = BIO_new(BIO_s_mem());
            if (tbio == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (ECHConfigList_print(tbio, s->ext.ech.cfgs[i].cfg) != 1) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ehlen = BIO_get_mem_data(tbio, &ignore);
            inst->echconfig = OPENSSL_malloc(ehlen + 1);
            if (inst->echconfig == NULL)
                goto err;
            if (BIO_read(tbio, inst->echconfig, ehlen) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            inst->echconfig[ehlen] = '\0';
            BIO_free(tbio);
            tbio = NULL;
        }
    }
    *nindices = indices;
    *out = rdiff;
    return 1;

err:
    BIO_free(tbio);
    OSSL_ECH_INFO_free(rdiff, indices);
    return 0;
}

int SSL_ech_reduce(SSL *ssl, int index)
{
    SSL_ECH *new = NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || index < 0 || s->ext.ech.cfgs == NULL
        || s->ext.ech.ncfgs <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.ncfgs <= index) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /*
     * Copy the one to keep, then zap the pointers at that element in the array
     * free the array and fix s back up
     */
    new = OPENSSL_malloc(sizeof(SSL_ECH));
    if (new == NULL)
        return 0;
    *new = s->ext.ech.cfgs[index];
    memset(&s->ext.ech.cfgs[index], 0, sizeof(SSL_ECH));
    SSL_ECH_free_arr(s->ext.ech.cfgs, s->ext.ech.ncfgs);
    OPENSSL_free(s->ext.ech.cfgs);
    s->ext.ech.cfgs = new;
    s->ext.ech.ncfgs = 1;
    return 1;
}

int SSL_CTX_ech_server_get_key_status(SSL_CTX *s, int *numkeys)
{
    if (s == NULL || numkeys == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech)
        *numkeys = s->ext.nechs;
    else
        *numkeys = 0;
    return 1;
}

int SSL_CTX_ech_server_flush_keys(SSL_CTX *ctx, unsigned int age)
{
    time_t now = time(0);
    int i = 0;
    int deleted = 0; /* number deleted */
    int orig = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* it's not a failure if nothing loaded yet */
    if (ctx->ext.ech == NULL || ctx->ext.nechs == 0)
        return 1;
    orig = ctx->ext.nechs;
    if (age == 0) {
        SSL_ECH_free_arr(ctx->ext.ech, ctx->ext.nechs);
        OPENSSL_free(ctx->ext.ech);
        ctx->ext.ech = NULL;
        ctx->ext.nechs = 0;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Flushed all %d ECH keys at %lu\n", orig,
                       (long unsigned int)now);
        } OSSL_TRACE_END(TLS);
        return 1;
    }
    /* Otherwise go through them and delete as needed */
    for (i = 0; i != ctx->ext.nechs; i++) {
        SSL_ECH *ep = &ctx->ext.ech[i];

        if ((ep->loadtime + (time_t) age) <= now) {
            SSL_ECH_free(ep);
            deleted++;
            continue;
        }
        ctx->ext.ech[i - deleted] = ctx->ext.ech[i]; /* struct copy! */
    }
    ctx->ext.nechs -= deleted;
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out, "Flushed %d (of %d) ECH keys more than %u "
                   "seconds old at %lu\n", deleted, orig, age,
                   (long unsigned int)now);
    } OSSL_TRACE_END(TLS);
    return 1;
}

int SSL_CTX_ech_server_enable_file(SSL_CTX *ctx, const char *pemfile,
                                   int for_retry)
{
    int index = -1;
    int fnamestat = 0;
    SSL_ECH *sechs = NULL;
    int rv = 1;

    if (ctx == NULL || pemfile == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Check if we already loaded that one etc.  */
    fnamestat = ech_check_filenames(ctx, pemfile, &index);
    switch (fnamestat) {
    case OSSL_ECH_KEYPAIR_NEW:
        /* fall through */
    case OSSL_ECH_KEYPAIR_MODIFIED:
        /* processed below */
        break;
    case OSSL_ECH_KEYPAIR_UNMODIFIED:
        /* nothing to do */
        return 1;
    case OSSL_ECH_KEYPAIR_FILEMISSING:
        /* nothing to do, but trace this and let caller handle it */
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Returning OSSL_ECH_FILEMISSING from "
                       "SSL_CTX_ech_server_enable_file for %s\n", pemfile);
            BIO_printf(trc_out, "That's unexpected and likely indicates a "
                       "problem, but the application might be able to "
                       "continue\n");
        } OSSL_TRACE_END(TLS);
        ERR_raise(ERR_LIB_SSL, SSL_R_FILE_OPEN_FAILED);
        return SSL_R_FILE_OPEN_FAILED;
    case OSSL_ECH_KEYPAIR_ERROR:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Load up the file content */
    rv = ech_readpemfile(ctx, 1, pemfile, NULL, 0, &sechs, for_retry);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file.
     * (Well, simplification would be more accurate than restriction:-)
     */
    if (sechs == NULL || sechs->cfg == NULL || sechs->cfg->nrecs != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* Now store the keypair in a new or current slot */
    if (fnamestat == OSSL_ECH_KEYPAIR_MODIFIED) {
        SSL_ECH *curr_ec = NULL;

        if (index < 0 || index >= ctx->ext.nechs) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        curr_ec = &ctx->ext.ech[index];
        SSL_ECH_free(curr_ec);
        memset(curr_ec, 0, sizeof(SSL_ECH));
        *curr_ec = *sechs; /* struct copy */
        OPENSSL_free(sechs);
        return 1;
    }
    if (fnamestat == OSSL_ECH_KEYPAIR_NEW) {
        SSL_ECH *re_ec =
            OPENSSL_realloc(ctx->ext.ech,
                            (ctx->ext.nechs + 1) * sizeof(SSL_ECH));
        SSL_ECH *new_ec = NULL;

        if (re_ec == NULL) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ctx->ext.ech = re_ec;
        new_ec = &ctx->ext.ech[ctx->ext.nechs];
        memset(new_ec, 0, sizeof(SSL_ECH));
        *new_ec = *sechs;
        ctx->ext.nechs++;
        OPENSSL_free(sechs);
        return 1;
    }
    /* shouldn't ever happen, but hey... */
    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
    return 0;
}

int SSL_CTX_ech_server_enable_buffer(SSL_CTX *ctx, const unsigned char *buf,
                                     const size_t blen, int for_retry)
{
    SSL_ECH *sechs = NULL;
    int rv = 1;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    int j = 0;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    char ah_hash[2 * EVP_MAX_MD_SIZE + 1];
    SSL_ECH *re_ec = NULL;
    SSL_ECH *new_ec = NULL;

    if (ctx == NULL || buf == NULL || blen == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Pseudo-filename is hash of input buffer */
    md = ctx->ssl_digest_methods[SSL_HANDSHAKE_MAC_SHA256];
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (EVP_DigestInit_ex(mdctx, md, NULL) <= 0
        || EVP_DigestUpdate(mdctx, buf, blen) <= 0
        || EVP_DigestFinal_ex(mdctx, hashval, &hashlen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);
    /* AH encode hashval to be a string, as replacement for file name */
    if (ah_encode(ah_hash, sizeof(ah_hash), hashval, hashlen) != 1)
        return 0;
    /* Check if we have that buffer loaded already, if we did, we're done */
    for (j = 0; j != ctx->ext.nechs; j++) {
        SSL_ECH *se = &ctx->ext.ech[j];

        if (se->pemfname != NULL
            && strlen(se->pemfname) == strlen(ah_hash)
            && !memcpy(se->pemfname, ah_hash, strlen(ah_hash))) {
            /* we're done here */
            return 1;
        }
    }
    /* Load up the buffer content */
    rv = ech_readpemfile(ctx, 0, ah_hash, buf, blen, &sechs, for_retry);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file
     */
    if (sechs == NULL || sechs->cfg == NULL || sechs->cfg->nrecs != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Now store the keypair in a new or current place */
    re_ec = OPENSSL_realloc(ctx->ext.ech,
                            (ctx->ext.nechs + 1) * sizeof(SSL_ECH));
    if (re_ec == NULL) {
        SSL_ECH_free(sechs);
        OPENSSL_free(sechs);
        return 0;
    }
    ctx->ext.ech = re_ec;
    new_ec = &ctx->ext.ech[ctx->ext.nechs];
    memset(new_ec, 0, sizeof(SSL_ECH));
    *new_ec = *sechs;
    ctx->ext.nechs++;
    OPENSSL_free(sechs);
    return 1;
}

/* 
 * TODO: check there are no file-locking issues related to loading these
 * with multi-threading or with other multi-threading environments.
 */
int SSL_CTX_ech_server_enable_dir(SSL_CTX *ctx, int *number_loaded,
                                  const char *echdir, int for_retry)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;

    if (ctx == NULL || echdir == NULL || number_loaded == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *number_loaded = 0;
    while ((filename = OPENSSL_DIR_read(&d, echdir))) {
        char echname[PATH_MAX];
        size_t nlen = 0;
        int r;
        const char *last4 = NULL;
        struct stat thestat;

        if (strlen(echdir) + strlen(filename) + 2 > sizeof(echname)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name too long: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
# ifdef OPENSSL_SYS_VMS
        r = BIO_snprintf(echname, sizeof(echname), "%s%s", echdir, filename);
# else
        r = BIO_snprintf(echname, sizeof(echname), "%s/%s", echdir, filename);
# endif
        if (r <= 0 || r >= (int)sizeof(echname)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name oddity: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        nlen = strlen(filename);
        if (nlen <= 4) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out, "name too short: %s/%s - skipping it \r\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        last4 = filename + nlen - 4;
        if (strncmp(last4, ".pem", 4) && strncmp(last4, ".ech", 4)) {
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                           "name doesn't end in .pem or .ech:"
                           " %s/%s - skipping it\n",
                           echdir, filename);
            } OSSL_TRACE_END(TLS);
            continue;
        }
        if (stat(echname, &thestat) == 0) {
            if (SSL_CTX_ech_server_enable_file(ctx, echname, for_retry) == 1) {
                *number_loaded = *number_loaded + 1;
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Added %d-th ECH key pair from: %s\n",
                               *number_loaded, echname);
                } OSSL_TRACE_END(TLS);
            } else {
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Failed to set ECH parameters for %s\n",
                               echname);
                } OSSL_TRACE_END(TLS);
            }
        }
    }
    if (d)
        OPENSSL_DIR_end(&d);
    return 1;
}

int SSL_ech_get_status(SSL *ssl, char **inner_sni, char **outer_sni)
{
    char *sinner = NULL;
    char *souter = NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || outer_sni == NULL || inner_sni == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return SSL_ECH_STATUS_FAILED;
    }
    *outer_sni = NULL;
    *inner_sni = NULL;
    if (s->ext.ech.grease == OSSL_ECH_IS_GREASE) {
        if (s->ext.ech.returned != NULL) {
            return SSL_ECH_STATUS_GREASE_ECH;
        }
        return SSL_ECH_STATUS_GREASE;
    }
    if (s->ext.ech.backend == 1) {
        if (s->ext.hostname != NULL
            && (*inner_sni = OPENSSL_strdup(s->ext.hostname)) == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
        return SSL_ECH_STATUS_BACKEND;
    }
    if (s->ext.ech.cfgs == NULL) {
        return SSL_ECH_STATUS_NOT_CONFIGURED;
    }
    /* Set output vars - note we may be pointing to NULL which is fine  */
    if (s->server == 0) {
        sinner = s->ext.hostname;
        if (s->ext.ech.attempted == 1 && s->ext.ech.success == 0)
            sinner = s->ext.ech.former_inner;
        if (s->ext.ech.cfgs->no_outer == 0)
            souter = s->ext.ech.outer_hostname;
        else
            souter = NULL;
    } else {
        if (s->ext.ech.cfgs != NULL && s->ext.ech.success == 1) {
            sinner = s->ext.ech.cfgs->inner_name;
            souter = s->ext.ech.cfgs->outer_name;
        }
    }
    if (s->ext.ech.cfgs != NULL && s->ext.ech.attempted == 1
        && s->ext.ech.grease != OSSL_ECH_IS_GREASE) {
        long vr = X509_V_OK;

        vr = SSL_get_verify_result(ssl);
        if (sinner != NULL
            && (*inner_sni = OPENSSL_strdup(sinner)) == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
        if (souter != NULL
            && (*outer_sni = OPENSSL_strdup(souter)) == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
        if (s->ext.ech.success == 1) {
            if (vr == X509_V_OK) {
                return SSL_ECH_STATUS_SUCCESS;
            } else {
                return SSL_ECH_STATUS_BAD_NAME;
            }
        } else {
            if (vr == X509_V_OK && s->ext.ech.returned != NULL) {
                return SSL_ECH_STATUS_FAILED_ECH;
            } else if (vr != X509_V_OK && s->ext.ech.returned != NULL) {
                return SSL_ECH_STATUS_FAILED_ECH_BAD_NAME;
            }
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return SSL_ECH_STATUS_FAILED;
        }
    } else if (s->ext.ech.grease == OSSL_ECH_IS_GREASE) {
        return SSL_ECH_STATUS_GREASE;
    }
    return SSL_ECH_STATUS_NOT_TRIED;
}

void SSL_ech_set_callback(SSL *ssl, SSL_ech_cb_func f)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL || f == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
    s->ext.ech.cb = f;
}

void SSL_CTX_ech_set_callback(SSL_CTX *s, SSL_ech_cb_func f)
{
    if (s == NULL || f == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return;
    }
    s->ext.ech_cb = f;
}

int SSL_ech_set_grease_suite(SSL *ssl, const char *suite)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Just stash the value for now and interpret when/if we do GREASE */
    OPENSSL_free(s->ext.ech.grease_suite);
    s->ext.ech.grease_suite = OPENSSL_strdup(suite);
    return 1;
}

int SSL_ech_set_grease_type(SSL *ssl, uint16_t type)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    /* Just stash the value for now and interpret when/if we do GREASE */
    s->ext.ech.attempted_type = type;
    return 1;
}

int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            int *decrypted_ok,
                            char **inner_sni, char **outer_sni,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            unsigned char **hrrtok, size_t *toklen)
{
    SSL *s = NULL;
    PACKET pkt_outer, pkt_inner;
    unsigned char *inner_buf = NULL;
    size_t inner_buf_len = 0;
    int rv = 0, innerflag = -1;
    size_t startofsessid = 0; /* offset of session id within Ch */
    size_t startofexts = 0; /* offset of extensions within CH */
    size_t echoffset = 0; /* offset of start of ECH within CH */
    uint16_t echtype = TLSEXT_TYPE_ech_unknown; /* type of ECH seen */
    size_t innersnioffset = 0; /* offset to SNI in inner */
    SSL_CONNECTION *sc = NULL;

    if (ctx == NULL || outer_ch == NULL || outer_len == 0
        || inner_ch == NULL || inner_len == NULL || *inner_len == 0
        || inner_sni == NULL || outer_sni == NULL || decrypted_ok == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    inner_buf_len = *inner_len;
    s = SSL_new(ctx);
    if (s == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* sanity checks on record layer and preamble */
    if (outer_len <= 9
        || outer_ch[0] != SSL3_RT_HANDSHAKE
        || outer_ch[1] != TLS1_2_VERSION_MAJOR
        || (outer_ch[2] != TLS1_VERSION_MINOR
            && outer_ch[2] != TLS1_2_VERSION_MINOR)
        || (size_t)((outer_ch[3] << 8) + outer_ch[4]) != (size_t)(outer_len - 5)
        || outer_ch[5] != SSL3_MT_CLIENT_HELLO
        || (size_t)((outer_ch[6] << 16) + (outer_ch[7] << 8) + outer_ch[8])
        != (size_t)(outer_len - 9)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (PACKET_buf_init(&pkt_outer, outer_ch + 9, outer_len - 9) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    inner_buf = OPENSSL_malloc(inner_buf_len);
    if (inner_buf == NULL)
        goto err;
    if (PACKET_buf_init(&pkt_inner, inner_buf, inner_buf_len) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    sc = SSL_CONNECTION_FROM_SSL(s);
    if (sc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hrrtok != NULL && toklen != NULL
        && *hrrtok != NULL && *toklen != 0
        && ech_read_hrrtoken(sc, hrrtok, toklen) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    /*
     * Check if there's any ECH and if so, whether it's an outer
     * (that might need decrypting) or an inner
     */
    rv = ech_get_ch_offsets(sc, &pkt_outer, &startofsessid, &startofexts,
                            &echoffset, &echtype, &innerflag, &innersnioffset);
    if (rv != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (echoffset == 0) {
        /* no ECH present */
        SSL_free(s);
        OPENSSL_free(inner_buf);
        *decrypted_ok = 0;
        return 1;
    }
    /* If we're asked to decrypt an inner, that's not ok */
    if (innerflag == 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        SSL_free(s);
        OPENSSL_free(inner_buf);
        *decrypted_ok = 0;
        return 0;
    }

    rv = ech_early_decrypt(sc, &pkt_outer, &pkt_inner);
    if (rv != 1) {
        /* that could've been GREASE, but we've no idea */
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    if (sc->ext.ech.cfgs != NULL && sc->ext.ech.cfgs->outer_name != NULL) {
        *outer_sni = OPENSSL_strdup(sc->ext.ech.cfgs->outer_name);
        if (*outer_sni == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (sc->ext.ech.success == 0) {
        *decrypted_ok = 0;
        OPENSSL_free(*outer_sni);
        *outer_sni = NULL;
    } else {
        size_t ilen = PACKET_remaining(&pkt_inner);
        const unsigned char *iptr = NULL;

        /* make sure there's space */
        if ((ilen + 9) > inner_buf_len) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        if ((iptr = PACKET_data(&pkt_inner)) == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            goto err;
        }
        /* Fix up header and length of inner CH */
        inner_ch[0] = SSL3_RT_HANDSHAKE;
        inner_ch[1] = outer_ch[1];
        inner_ch[2] = outer_ch[2];
        inner_ch[3] = ((ilen + 4) >> 8) & 0xff;
        inner_ch[4] = (ilen + 4) & 0xff;
        inner_ch[5] = SSL3_MT_CLIENT_HELLO;
        inner_ch[6] = (ilen >> 16) & 0xff;
        inner_ch[7] = (ilen >> 8) & 0xff;
        inner_ch[8] = ilen & 0xff;
        memcpy(inner_ch + 9, iptr, ilen);
        *inner_len = ilen + 9;
        /* Grab the inner SNI (if it's there) */
        rv = ech_get_ch_offsets(sc, &pkt_inner, &startofsessid, &startofexts,
                                &echoffset, &echtype, &innerflag,
                                &innersnioffset);
        if (rv != 1) {
            ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
            return rv;
        }
        if (innersnioffset > 0) {
            PACKET isni;
            size_t plen;
            const unsigned char *isnipeek = NULL;
            const unsigned char *isnibuf = NULL;
            size_t isnilen = 0;

            plen = PACKET_remaining(&pkt_inner);
            if (PACKET_peek_bytes(&pkt_inner, &isnipeek, plen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (plen <= 4) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            isnibuf = &(isnipeek[innersnioffset + 4]);
            isnilen = isnipeek[innersnioffset + 2] * 256
                + isnipeek[innersnioffset + 3];
            if (isnilen >= plen - 4) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (PACKET_buf_init(&isni, isnibuf, isnilen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (tls_parse_ctos_server_name(sc, &isni, 0, NULL, 0) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            }
            if (sc->ext.hostname != NULL) {
                *inner_sni = OPENSSL_strdup(sc->ext.hostname);
                if (*inner_sni == NULL) {
                    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            }
        }

        /* stash client's ephemeral ECH pub in case of HRR */
        if (hrrtok != NULL && toklen != NULL) {
            if (*hrrtok != NULL)
                OPENSSL_free(*hrrtok);
            if (ech_write_hrrtoken(sc, hrrtok, toklen) != 1) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        /* Declare success to caller */
        *decrypted_ok = 1;
    }
    SSL_free(s);
    OPENSSL_free(inner_buf);
    return 1;
err:
    SSL_free(s);
    OPENSSL_free(inner_buf);
    return 0;
}

int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                                      const size_t protos_len)
{
    if (ctx == NULL || protos == NULL || protos_len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    OPENSSL_free(ctx->ext.alpn_outer);
    ctx->ext.alpn_outer = OPENSSL_memdup(protos, protos_len);
    if (ctx->ext.alpn_outer == NULL) {
        return 0;
    }
    ctx->ext.alpn_outer_len = protos_len;
    return 1;
}

int SSL_ech_get_retry_config(SSL *ssl, unsigned char **ec, size_t *eclen)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    unsigned char *rt = NULL;

    if (s == NULL || eclen == NULL || ec == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (s->ext.ech.returned != NULL) {
        /*
         * Before we return these, parse 'em just in case the application
         * isn't good at that
         */
        ECHConfigList *ecl = NULL;
        int n_ecls = 0, leftover = 0;

        if (ECHConfigList_from_binary(s->ext.ech.returned,
                                      s->ext.ech.returned_len,
                                      &ecl, &n_ecls, &leftover) != 1)
            return 0;
        ECHConfigList_free(ecl);
        OPENSSL_free(ecl);
        rt = OPENSSL_malloc(s->ext.ech.returned_len);
        if (rt == NULL)
            return 0;
        *eclen = s->ext.ech.returned_len;
        memcpy(rt, s->ext.ech.returned, *eclen);
        *ec = rt;
    } else {
        *eclen = 0;
        *ec = NULL;
    }
    return 1;
}

int OSSL_ech_make_echconfig(unsigned char *echconfig, size_t *echconfiglen,
                            unsigned char *priv, size_t *privlen,
                            uint16_t ekversion, uint16_t max_name_length,
                            const char *public_name, OSSL_HPKE_SUITE suite,
                            const unsigned char *extvals, size_t extlen)
{
    size_t pnlen = 0;
    size_t publen = OSSL_ECH_CRYPTO_VAR_SIZE;
    unsigned char pub[OSSL_ECH_CRYPTO_VAR_SIZE];
    int rv = 0;
    unsigned char *bp = NULL;
    size_t bblen = 0;
    unsigned int b64len = 0;
    EVP_PKEY *privp = NULL;
    BIO *bfp = NULL;
    size_t lprivlen = 0;
    uint8_t config_id = 0;
    WPACKET epkt;
    BUF_MEM *epkt_mem = NULL;

    /* basic checks */
    if (echconfig == NULL || echconfiglen == NULL
        || priv == NULL || privlen == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    pnlen = (public_name == NULL ? 0 : strlen(public_name));
    if (pnlen > OSSL_ECH_MAX_PUBLICNAME) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (max_name_length > OSSL_ECH_MAX_MAXNAMELEN) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* this used have more versions and will again in future */
    switch (ekversion) {
    case OSSL_ECH_RFCXXXX_VERSION:
        break;
    default:
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* so WPAKCET_cleanup() won't go wrong */
    memset(&epkt, 0, sizeof(epkt));

    /* random config_id */
    if (RAND_bytes((unsigned char *)&config_id, 1) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (OSSL_HPKE_keygen(suite, pub, &publen, &privp, NULL, 0, NULL, NULL)
        != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    bfp = BIO_new(BIO_s_mem());
    if (bfp == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, privp, NULL, NULL, 0, NULL, NULL)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lprivlen = BIO_read(bfp, priv, *privlen);
    if (lprivlen <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lprivlen > *privlen) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    /*
     * if we can, add a NUL to the end of the private key string, just
     * to be nice to users
     */
    if (lprivlen < *privlen)
        priv[lprivlen] = 0x00;
    *privlen = lprivlen;

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
        || !WPACKET_put_bytes_u16(&epkt, ekversion)
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
        || !WPACKET_memcpy(&epkt, extvals, extlen)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)
        || !WPACKET_close(&epkt)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    WPACKET_get_total_written(&epkt, &bblen);
    b64len = EVP_EncodeBlock((unsigned char *)echconfig,
                             (unsigned char *)bp, bblen);
    if (b64len >= (*echconfiglen - 1)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    echconfig[b64len] = '\0';
    *echconfiglen = b64len;
    rv = 1;

err:
    EVP_PKEY_free(privp);
    BIO_free_all(bfp);
    WPACKET_cleanup(&epkt);
    BUF_MEM_free(epkt_mem);
    return rv;
}

int OSSL_ech_find_echconfigs(int *num_echs,
                             unsigned char ***echconfigs, size_t **echlens,
                             const unsigned char *val, size_t len)
{
    SSL_ECH *new_echs = NULL;
    int rv = 0, i, j, num_new = 0, num_ecs = 0;
    unsigned char **ebufs = NULL, *ep = NULL;
    size_t *elens = NULL;

    if (num_echs == NULL || echconfigs == NULL || echlens == NULL
        || val == NULL || len == 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ech_finder(&num_new, &new_echs, len, val) != 1) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (num_new == 0) {
        /* that's not a fail, just an empty set result */
        *num_echs = 0;
        return 1;
    }
    /*
     * Go through the SSL_ECH array, and each of the ECHConfig
     * records in each element and make a singleton ECHConfigList
     * from each ECHConfig we found
     */
    for (i = 0; i != num_new; i++) {
        for (j = 0; j != new_echs[i].cfg->nrecs; j++) {
            unsigned char **tebufs;
            size_t *telens, thislen;

            num_ecs++;
            tebufs = OPENSSL_realloc(ebufs, num_ecs * sizeof(unsigned char *));
            if (tebufs == NULL)
                goto err;
            ebufs = tebufs;
            telens = OPENSSL_realloc(elens, num_ecs * sizeof(size_t));
            if (telens == NULL)
                goto err;
            elens = telens;
            thislen = new_echs[i].cfg->recs[j].encoding_length;
            ep = OPENSSL_malloc(thislen + 2);
            if (ep == NULL)
                goto err;
            ep[0] = (thislen & 0xff) >> 8;
            ep[1] = thislen & 0xff;
            memcpy(ep + 2, new_echs[i].cfg->recs[j].encoding_start, thislen);
            elens[num_ecs - 1] = thislen + 2;
            ebufs[num_ecs - 1] = ep;
            ep = NULL;
        }
    }
    *echconfigs = ebufs;
    *echlens = elens;
    *num_echs = num_ecs;
    rv = 1;
err:
    if (rv == 0) {
        for (i = 0; i != num_ecs; i++)
            OPENSSL_free(ebufs[i]);
        OPENSSL_free(ebufs);
        OPENSSL_free(elens);
        OPENSSL_free(ep);
    }
    SSL_ECH_free_arr(new_echs, num_new);
    OPENSSL_free(new_echs);
    return rv;
}

#endif
