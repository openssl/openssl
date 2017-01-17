/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_locl.h"
#include "statem_locl.h"

static int final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al);
static int init_server_name(SSL *s, unsigned int context);
static int final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al);
#ifndef OPENSSL_NO_EC
static int final_ec_pt_formats(SSL *s, unsigned int context, int sent,
                                       int *al);
#endif
static int init_session_ticket(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_OCSP
static int init_status_request(SSL *s, unsigned int context);
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
static int init_npn(SSL *s, unsigned int context);
#endif
static int init_alpn(SSL *s, unsigned int context);
static int final_alpn(SSL *s, unsigned int context, int sent, int *al);
static int init_sig_algs(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_SRP
static int init_srp(SSL *s, unsigned int context);
#endif
static int init_etm(SSL *s, unsigned int context);
static int init_ems(SSL *s, unsigned int context);
static int final_ems(SSL *s, unsigned int context, int sent, int *al);
#ifndef OPENSSL_NO_SRTP
static int init_srtp(SSL *s, unsigned int context);
#endif
static int final_sig_algs(SSL *s, unsigned int context, int sent, int *al);

/* Structure to define a built-in extension */
typedef struct extensions_definition_st {
    /* The defined type for the extension */
    unsigned int type;
    /*
     * The context that this extension applies to, e.g. what messages and
     * protocol versions
     */
    unsigned int context;
    /*
     * Initialise extension before parsing. Always called for relevant contexts
     * even if extension not present
     */
    int (*init)(SSL *s, unsigned int context);
    /* Parse extension sent from client to server */
    int (*parse_ctos)(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al);
    /* Parse extension send from server to client */
    int (*parse_stoc)(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al);
    /* Construct extension sent from server to client */
    int (*construct_stoc)(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                          int *al);
    /* Construct extension sent from client to server */
    int (*construct_ctos)(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                          int *al);
    /*
     * Finalise extension after parsing. Always called where an extensions was
     * initialised even if the extension was not present. |sent| is set to 1 if
     * the extension was seen, or 0 otherwise.
     */
    int (*final)(SSL *s, unsigned int context, int sent, int *al);
} EXTENSION_DEFINITION;

/*
 * Definitions of all built-in extensions. NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the indexes
 * defined in statem_locl.h.
 * Each extension has an initialiser, a client and
 * server side parser and a finaliser. The initialiser is called (if the
 * extension is relevant to the given context) even if we did not see the
 * extension in the message that we received. The parser functions are only
 * called if we see the extension in the message. The finalisers are always
 * called if the initialiser was called.
 * There are also server and client side constructor functions which are always
 * called during message construction if the extension is relevant for the
 * given context.
 * The initialisation, parsing, finalisation and construction functions are
 * always called in the order defined in this list. Some extensions may depend
 * on others having been processed first, so the order of this list is
 * significant.
 * The extension context is defined by a series of flags which specify which
 * messages the extension is relevant to. These flags also specify whether the
 * extension is relevant to a paricular protocol or protocol version.
 *
 * TODO(TLS1.3): Make sure we have a test to check the consistency of these
 */
#define INVALID_EXTENSION { 0x10000, 0, NULL, NULL, NULL, NULL, NULL, NULL }
static const EXTENSION_DEFINITION ext_defs[] = {
    {
        TLSEXT_TYPE_renegotiate,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_SSL3_ALLOWED
        | EXT_TLS1_2_AND_BELOW_ONLY,
        NULL, tls_parse_ctos_renegotiate, tls_parse_stoc_renegotiate,
        tls_construct_stoc_renegotiate, tls_construct_ctos_renegotiate,
        final_renegotiate
    },
    {
        TLSEXT_TYPE_server_name,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
        init_server_name,
        tls_parse_ctos_server_name, tls_parse_stoc_server_name,
        tls_construct_stoc_server_name, tls_construct_ctos_server_name,
        final_server_name
    },
#ifndef OPENSSL_NO_SRP
    {
        TLSEXT_TYPE_srp,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        init_srp, tls_parse_ctos_srp, NULL, NULL, tls_construct_ctos_srp, NULL
    },
#else
    INVALID_EXTENSION,
#endif
#ifndef OPENSSL_NO_EC
    {
        TLSEXT_TYPE_ec_point_formats,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        NULL, tls_parse_ctos_ec_pt_formats, tls_parse_stoc_ec_pt_formats,
        tls_construct_stoc_ec_pt_formats, tls_construct_ctos_ec_pt_formats,
        final_ec_pt_formats
    },
    {
        TLSEXT_TYPE_supported_groups,
        EXT_CLIENT_HELLO | EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
        NULL, tls_parse_ctos_supported_groups, NULL,
        NULL /* TODO(TLS1.3): Need to add this */,
        tls_construct_ctos_supported_groups, NULL
    },
#else
    INVALID_EXTENSION,
    INVALID_EXTENSION,
#endif
    {
        TLSEXT_TYPE_session_ticket,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        init_session_ticket, tls_parse_ctos_session_ticket,
        tls_parse_stoc_session_ticket, tls_construct_stoc_session_ticket,
        tls_construct_ctos_session_ticket, NULL
    },
    {
        TLSEXT_TYPE_signature_algorithms,
        EXT_CLIENT_HELLO,
        init_sig_algs, tls_parse_ctos_sig_algs, NULL, NULL,
        tls_construct_ctos_sig_algs, final_sig_algs
    },
#ifndef OPENSSL_NO_OCSP
    {
        TLSEXT_TYPE_status_request,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE,
        init_status_request, tls_parse_ctos_status_request,
        tls_parse_stoc_status_request, tls_construct_stoc_status_request,
        tls_construct_ctos_status_request, NULL
    },
#else
    INVALID_EXTENSION,
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {
        TLSEXT_TYPE_next_proto_neg,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        init_npn, tls_parse_ctos_npn, tls_parse_stoc_npn,
        tls_construct_stoc_next_proto_neg, tls_construct_ctos_npn, NULL
    },
#else
    INVALID_EXTENSION,
#endif
    {
        /*
         * Must appear in this list after server_name so that finalisation
         * happens after server_name callbacks
         */
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
        init_alpn, tls_parse_ctos_alpn, tls_parse_stoc_alpn,
        tls_construct_stoc_alpn, tls_construct_ctos_alpn, final_alpn
    },
#ifndef OPENSSL_NO_SRTP
    {
        TLSEXT_TYPE_use_srtp,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS | EXT_DTLS_ONLY,
        init_srtp, tls_parse_ctos_use_srtp, tls_parse_stoc_use_srtp,
        tls_construct_stoc_use_srtp, tls_construct_ctos_use_srtp, NULL
    },
#else
    INVALID_EXTENSION,
#endif
    {
        TLSEXT_TYPE_encrypt_then_mac,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        init_etm, tls_parse_ctos_etm, tls_parse_stoc_etm,
        tls_construct_stoc_etm, tls_construct_ctos_etm, NULL
    },
#ifndef OPENSSL_NO_CT
    {
        TLSEXT_TYPE_signed_certificate_timestamp,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE,
        NULL,
        /*
         * No server side support for this, but can be provided by a custom
         * extension. This is an exception to the rule that custom extensions
         * cannot override built in ones.
         */
        NULL, tls_parse_stoc_sct, NULL, tls_construct_ctos_sct,  NULL
    },
#else
    INVALID_EXTENSION,
#endif
    {
        TLSEXT_TYPE_extended_master_secret,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        init_ems, tls_parse_ctos_ems, tls_parse_stoc_ems,
        tls_construct_stoc_ems, tls_construct_ctos_ems, final_ems
    },
    {
        TLSEXT_TYPE_supported_versions,
        EXT_CLIENT_HELLO | EXT_TLS_IMPLEMENTATION_ONLY | EXT_TLS1_3_ONLY,
        NULL,
        /* Processed inline as part of version selection */
        NULL, NULL, NULL, tls_construct_ctos_supported_versions, NULL
    },
    {
        /*
         * Must be in this list after supported_groups. We need that to have
         * been parsed before we do this one.
         */
        TLSEXT_TYPE_key_share,
        EXT_CLIENT_HELLO | EXT_TLS1_3_SERVER_HELLO
        | EXT_TLS1_3_HELLO_RETRY_REQUEST | EXT_TLS_IMPLEMENTATION_ONLY
        | EXT_TLS1_3_ONLY,
        NULL, tls_parse_ctos_key_share, tls_parse_stoc_key_share,
        tls_construct_stoc_key_share, tls_construct_ctos_key_share, NULL
    },
    {
        /*
         * Special unsolicited ServerHello extension only used when
         * SSL_OP_CRYPTOPRO_TLSEXT_BUG is set
         */
        TLSEXT_TYPE_cryptopro_bug,
        EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY,
        NULL, NULL, NULL, tls_construct_stoc_cryptopro_bug, NULL, NULL
    },
    {
        /* Last in the list because it must be added as the last extension */
        TLSEXT_TYPE_padding,
        EXT_CLIENT_HELLO,
        NULL,
        /* We send this, but don't read it */
        NULL, NULL, NULL, tls_construct_ctos_padding, NULL
    }
};

/*
 * Verify whether we are allowed to use the extension |type| in the current
 * |context|. Returns 1 to indicate the extension is allowed or unknown or 0 to
 * indicate the extension is not allowed. If returning 1 then |*found| is set to
 * 1 if we found a definition for the extension, and |*idx| is set to its index
 */
static int verify_extension(SSL *s, unsigned int context, unsigned int type,
                            custom_ext_methods *meths, RAW_EXTENSION *rawexlist,
                            RAW_EXTENSION **found)
{
    size_t i;
    size_t builtin_num = OSSL_NELEM(ext_defs);
    const EXTENSION_DEFINITION *thisext;

    for (i = 0, thisext = ext_defs; i < builtin_num; i++, thisext++) {
        if (type == thisext->type) {
            /* Check we're allowed to use this extension in this context */
            if ((context & thisext->context) == 0)
                return 0;

            if (SSL_IS_DTLS(s)) {
                if ((thisext->context & EXT_TLS_ONLY) != 0)
                    return 0;
            } else if ((thisext->context & EXT_DTLS_ONLY) != 0) {
                    return 0;
            }

            *found = &rawexlist[i];
            return 1;
        }
    }

    if ((context & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) == 0) {
        /*
         * Custom extensions only apply to <=TLS1.2. This extension is unknown
         * in this context - we allow it
         */
        *found = NULL;
        return 1;
    }

    /* Check the custom extensions */
    if (meths != NULL) {
        for (i = builtin_num; i < builtin_num + meths->meths_count; i++) {
            if (meths->meths[i - builtin_num].ext_type == type) {
                *found = &rawexlist[i];
                return 1;
            }
        }
    }

    /* Unknown extension. We allow it */
    *found = NULL;
    return 1;
}

/*
 * Check whether the context defined for an extension |extctx| means whether
 * the extension is relevant for the current context |thisctx| or not. Returns
 * 1 if the extension is relevant for this context, and 0 otherwise
 */
static int extension_is_relevant(SSL *s, unsigned int extctx,
                                 unsigned int thisctx)
{
    if ((SSL_IS_DTLS(s)
                && (extctx & EXT_TLS_IMPLEMENTATION_ONLY) != 0)
            || (s->version == SSL3_VERSION
                    && (extctx & EXT_SSL3_ALLOWED) == 0)
            || (SSL_IS_TLS13(s)
                && (extctx & EXT_TLS1_2_AND_BELOW_ONLY) != 0)
            || (!SSL_IS_TLS13(s) && (extctx & EXT_TLS1_3_ONLY) != 0))
        return 0;

    return 1;
}

/*
 * Gather a list of all the extensions from the data in |packet]. |context|
 * tells us which message this extension is for. The raw extension data is
 * stored in |*res| on success. In the event of an error the alert type to use
 * is stored in |*al|. We don't actually process the content of the extensions
 * yet, except to check their types. This function also runs the initialiser
 * functions for all known extensions (whether we have collected them or not).
 * If successful the caller is responsible for freeing the contents of |*res|.
 *
 * Per http://tools.ietf.org/html/rfc5246#section-7.4.1.4, there may not be
 * more than one extension of the same type in a ClientHello or ServerHello.
 * This function returns 1 if all extensions are unique and we have parsed their
 * types, and 0 if the extensions contain duplicates, could not be successfully
 * found, or an internal error occurred. We only check duplicates for
 * extensions that we know about. We ignore others.
 */
int tls_collect_extensions(SSL *s, PACKET *packet, unsigned int context,
                           RAW_EXTENSION **res, int *al)
{
    PACKET extensions = *packet;
    size_t i = 0;
    custom_ext_methods *exts = NULL;
    RAW_EXTENSION *raw_extensions = NULL;
    const EXTENSION_DEFINITION *thisexd;

    *res = NULL;

    /*
     * Initialise server side custom extensions. Client side is done during
     * construction of extensions for the ClientHello.
     */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        exts = &s->cert->srv_ext;
        custom_ext_init(&s->cert->srv_ext);
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        exts = &s->cert->cli_ext;
    }

    raw_extensions = OPENSSL_zalloc((OSSL_NELEM(ext_defs)
                                     + (exts != NULL ? exts->meths_count : 0))
                                     * sizeof(*raw_extensions));
    if (raw_extensions == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    while (PACKET_remaining(&extensions) > 0) {
        unsigned int type;
        PACKET extension;
        RAW_EXTENSION *thisex;

        if (!PACKET_get_net_2(&extensions, &type) ||
            !PACKET_get_length_prefixed_2(&extensions, &extension)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *al = SSL_AD_DECODE_ERROR;
            goto err;
        }
        /*
         * Verify this extension is allowed. We only check duplicates for
         * extensions that we recognise.
         */
        if (!verify_extension(s, context, type, exts, raw_extensions, &thisex)
                || (thisex != NULL && thisex->present == 1)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            goto err;
        }
        if (thisex != NULL) {
            thisex->data = extension;
            thisex->present = 1;
            thisex->type = type;
        }
    }

    /*
     * Initialise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (thisexd = ext_defs, i = 0; i < OSSL_NELEM(ext_defs); i++, thisexd++) {
        if(thisexd->init != NULL && (thisexd->context & context) != 0
                && extension_is_relevant(s, thisexd->context, context)
                && !thisexd->init(s, context)) {
            *al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
    }

    *res = raw_extensions;
    return 1;

 err:
    OPENSSL_free(raw_extensions);
    return 0;
}

/*
 * Runs the parser for a given extension with index |idx|. |exts| contains the
 * list of all parsed extensions previously collected by
 * tls_collect_extensions(). The parser is only run if it is applicable for the
 * given |context| and the parser has not already been run. If this is for a
 * Certificate message, then we also provide the parser with the relevant
 * Certificate |x| and its position in the |chainidx| with 0 being the first
 * Certificate. Returns 1 on success or 0 on failure. In the event of a failure
 * |*al| is populated with a suitable alert code. If an extension is not present
 * this counted as success.
 */
int tls_parse_extension(SSL *s, TLSEXT_INDEX idx, int context,
                        RAW_EXTENSION *exts, X509 *x, size_t chainidx, int *al)
{
    RAW_EXTENSION *currext = &exts[idx];
    int (*parser)(SSL *s, PACKET *pkt, X509 *x, size_t chainidx, int *al) = NULL;

    /* Skip if the extension is not present */
    if (!currext->present)
        return 1;

    if (s->ext.debug_cb)
        s->ext.debug_cb(s, !s->server, currext->type,
                        PACKET_data(&currext->data),
                        PACKET_remaining(&currext->data),
                        s->ext.debug_arg);

    /* Skip if we've already parsed this extension */
    if (currext->parsed)
        return 1;

    currext->parsed = 1;

    if (idx < OSSL_NELEM(ext_defs)) {
        /* We are handling a built-in extension */
        const EXTENSION_DEFINITION *extdef = &ext_defs[idx];

        /* Check if extension is defined for our protocol. If not, skip */
        if (!extension_is_relevant(s, extdef->context, context))
            return 1;

        parser = s->server ? extdef->parse_ctos : extdef->parse_stoc;

        if (parser != NULL)
            return parser(s, &currext->data, x, chainidx, al);

        /*
         * If the parser is NULL we fall through to the custom extension
         * processing
         */
    }

    /*
     * This is a custom extension. We only allow this if it is a non
     * resumed session on the server side.
     *chain
     * TODO(TLS1.3): We only allow old style <=TLS1.2 custom extensions.
     * We're going to need a new mechanism for TLS1.3 to specify which
     * messages to add the custom extensions to.
     */
    if ((!s->hit || !s->server)
            && (context
                & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) != 0
            && custom_ext_parse(s, s->server, currext->type,
                                PACKET_data(&currext->data),
                                PACKET_remaining(&currext->data),
                                al) <= 0)
        return 0;

    return 1;
}

/*
 * Parse all remaining extensions that have not yet been parsed. Also calls the
 * finalisation for all extensions at the end, whether we collected them or not.
 * Returns 1 for success or 0 for failure. If we are working on a Certificate
 * message then we also pass the Certificate |x| and its position in the
 * |chainidx|, with 0 being the first certificate. On failure, |*al| is
 * populated with a suitable alert code.
 */
int tls_parse_all_extensions(SSL *s, int context, RAW_EXTENSION *exts, X509 *x,
                             size_t chainidx, int *al)
{
    size_t i, numexts = OSSL_NELEM(ext_defs);
    const EXTENSION_DEFINITION *thisexd;

    /* Calculate the number of extensions in the extensions list */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        numexts += s->cert->srv_ext.meths_count;
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        numexts += s->cert->cli_ext.meths_count;
    }

    /* Parse each extension in turn */
    for (i = 0; i < numexts; i++) {
        if (!tls_parse_extension(s, i, context, exts, x, chainidx, al))
            return 0;
    }

    /*
     * Finalise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (i = 0, thisexd = ext_defs; i < OSSL_NELEM(ext_defs); i++, thisexd++) {
        if(thisexd->final != NULL
                && (thisexd->context & context) != 0
                && !thisexd->final(s, context, exts[i].present, al))
            return 0;
    }

    return 1;
}

/*
 * Construct all the extensions relevant to the current |context| and write
 * them to |pkt|. If this is an extension for a Certificate in a Certificate
 * message, then |x| will be set to the Certificate we are handling, and
 * |chainidx| will indicate the position in the chainidx we are processing (with
 * 0 being the first in the chain). Returns 1 on success or 0 on failure. If a
 * failure occurs then |al| is populated with a suitable alert code. On a
 * failure construction stops at the first extension to fail to construct.
 */
int tls_construct_extensions(SSL *s, WPACKET *pkt, unsigned int context,
                             X509 *x, size_t chainidx, int *al)
{
    size_t i;
    int addcustom = 0, min_version, max_version = 0, reason, tmpal;
    const EXTENSION_DEFINITION *thisexd;

    /*
     * Normally if something goes wrong during construction it's an internal
     * error. We can always override this later.
     */
    tmpal = SSL_AD_INTERNAL_ERROR;

    if (!WPACKET_start_sub_packet_u16(pkt)
               /*
                * If extensions are of zero length then we don't even add the
                * extensions length bytes to a ClientHello/ServerHello in SSLv3
                */
            || ((context & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) != 0
               && s->version == SSL3_VERSION
               && !WPACKET_set_flags(pkt,
                                     WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH))) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((context & EXT_CLIENT_HELLO) != 0) {
        reason = ssl_get_client_min_max_version(s, &min_version, &max_version);
        if (reason != 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, reason);
            goto err;
        }
    }

    /* Add custom extensions first */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        custom_ext_init(&s->cert->cli_ext);
        addcustom = 1;
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        /*
         * We already initialised the custom extensions during ClientHello
         * parsing.
         *
         * TODO(TLS1.3): We're going to need a new custom extension mechanism
         * for TLS1.3, so that custom extensions can specify which of the
         * multiple message they wish to add themselves to.
         */
        addcustom = 1;
    }

    if (addcustom && !custom_ext_add(s, s->server, pkt, &tmpal)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    for (i = 0, thisexd = ext_defs; i < OSSL_NELEM(ext_defs); i++, thisexd++) {
        int (*construct)(SSL *s, WPACKET *pkt, X509 *x, size_t chainidx,
                         int *al);

        /* Skip if not relevant for our context */
        if ((thisexd->context & context) == 0)
            continue;

        construct = s->server ? thisexd->construct_stoc
                              : thisexd->construct_ctos;

        /* Check if this extension is defined for our protocol. If not, skip */
        if ((SSL_IS_DTLS(s)
                    && (thisexd->context & EXT_TLS_IMPLEMENTATION_ONLY)
                       != 0)
                || (s->version == SSL3_VERSION
                        && (thisexd->context & EXT_SSL3_ALLOWED) == 0)
                || (SSL_IS_TLS13(s)
                    && (thisexd->context & EXT_TLS1_2_AND_BELOW_ONLY)
                       != 0)
                || (!SSL_IS_TLS13(s)
                    && (thisexd->context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) == 0)
                || ((thisexd->context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) != 0
                    && (SSL_IS_DTLS(s) || max_version < TLS1_3_VERSION))
                || construct == NULL)
            continue;

        if (!construct(s, pkt, x, chainidx, &tmpal))
            goto err;
    }

    if (!WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return 1;

 err:
    *al = tmpal;
    return 0;
}

/*
 * Built in extension finalisation and initialisation functions. All initialise
 * or finalise the associated extension type for the given |context|. For
 * finalisers |sent| is set to 1 if we saw the extension during parsing, and 0
 * otherwise. These functions return 1 on success or 0 on failure. In the event
 * of a failure then |*al| is populated with a suitable error code.
 */

static int final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    if (!s->server) {
        /*
         * Check if we can connect to a server that doesn't support safe
         * renegotiation
         */
        if (!(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
                && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
                && !sent) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_FINAL_RENEGOTIATE,
                   SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
            return 0;
        }

        return 1;
    }

    /* Need RI if renegotiating */
    if (s->renegotiate
            && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            && !sent) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_FINAL_RENEGOTIATE,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }


    return 1;
}

static int init_server_name(SSL *s, unsigned int context)
{
    if (s->server)
        s->servername_done = 0;

    return 1;
}

static int final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int altmp = SSL_AD_UNRECOGNIZED_NAME;

    if (s->ctx != NULL && s->ctx->ext.servername_cb != 0)
        ret = s->ctx->ext.servername_cb(s, &altmp,
                                        s->ctx->ext.servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->ext.servername_cb != 0)
        ret = s->initial_ctx->ext.servername_cb(s, &altmp,
                                       s->initial_ctx->ext.servername_arg);

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        *al = altmp;
        return 0;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        *al = altmp;
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
        return 1;

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_EC
static int final_ec_pt_formats(SSL *s, unsigned int context, int sent,
                                       int *al)
{
    unsigned long alg_k, alg_a;

    if (s->server)
        return 1;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /*
     * If we are client and using an elliptic curve cryptography cipher
     * suite, then if server returns an EC point formats lists extension it
     * must contain uncompressed.
     */
    if (s->ext.ecpointformats != NULL
            && s->ext.ecpointformats_len > 0
            && s->session->ext.ecpointformats != NULL
            && s->session->ext.ecpointformats_len > 0
            && ((alg_k & SSL_kECDHE) || (alg_a & SSL_aECDSA))) {
        /* we are using an ECC cipher */
        size_t i;
        unsigned char *list = s->session->ext.ecpointformats;

        for (i = 0; i < s->session->ext.ecpointformats_len; i++) {
            if (*list++ == TLSEXT_ECPOINTFORMAT_uncompressed)
                break;
        }
        if (i == s->session->ext.ecpointformats_len) {
            SSLerr(SSL_F_FINAL_EC_PT_FORMATS,
                   SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
            return 0;
        }
    }

    return 1;
}
#endif

static int init_session_ticket(SSL *s, unsigned int context)
{
    if (!s->server)
        s->ext.ticket_expected = 0;

    return 1;
}

#ifndef OPENSSL_NO_OCSP
static int init_status_request(SSL *s, unsigned int context)
{
    if (s->server) {
        s->ext.status_type = TLSEXT_STATUSTYPE_nothing;
    } else {
        /*
         * Ensure we get sensible values passed to tlsext_status_cb in the event
         * that we don't receive a status message
         */
        OPENSSL_free(s->ext.ocsp.resp);
        s->ext.ocsp.resp = NULL;
        s->ext.ocsp.resp_len = 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
static int init_npn(SSL *s, unsigned int context)
{
    s->s3->npn_seen = 0;

    return 1;
}
#endif

static int init_alpn(SSL *s, unsigned int context)
{
    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;
    if (s->server) {
        s->s3->alpn_selected_len = 0;
        OPENSSL_free(s->s3->alpn_proposed);
        s->s3->alpn_proposed = NULL;
        s->s3->alpn_proposed_len = 0;
    }
    return 1;
}

static int final_alpn(SSL *s, unsigned int context, int sent, int *al)
{
    const unsigned char *selected = NULL;
    unsigned char selected_len = 0;

    if (!s->server)
        return 1;

    if (s->ctx->ext.alpn_select_cb != NULL && s->s3->alpn_proposed != NULL) {
        int r = s->ctx->ext.alpn_select_cb(s, &selected, &selected_len,
                                           s->s3->alpn_proposed,
                                           (unsigned int)s->s3->alpn_proposed_len,
                                           s->ctx->ext.alpn_select_cb_arg);

        if (r == SSL_TLSEXT_ERR_OK) {
            OPENSSL_free(s->s3->alpn_selected);
            s->s3->alpn_selected = OPENSSL_memdup(selected, selected_len);
            if (s->s3->alpn_selected == NULL) {
                *al = SSL_AD_INTERNAL_ERROR;
                return 0;
            }
            s->s3->alpn_selected_len = selected_len;
#ifndef OPENSSL_NO_NEXTPROTONEG
            /* ALPN takes precedence over NPN. */
            s->s3->npn_seen = 0;
#endif
        } else {
            *al = SSL_AD_NO_APPLICATION_PROTOCOL;
            return 0;
        }
    }

    return 1;
}

static int init_sig_algs(SSL *s, unsigned int context)
{
    /* Clear any signature algorithms extension received */
    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = NULL;

    return 1;
}

#ifndef OPENSSL_NO_SRP
static int init_srp(SSL *s, unsigned int context)
{
    OPENSSL_free(s->srp_ctx.login);
    s->srp_ctx.login = NULL;

    return 1;
}
#endif

static int init_etm(SSL *s, unsigned int context)
{
    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

static int init_ems(SSL *s, unsigned int context)
{
    if (!s->server)
        s->s3->flags &= ~TLS1_FLAGS_RECEIVED_EXTMS;

    return 1;
}

static int final_ems(SSL *s, unsigned int context, int sent, int *al)
{
    if (!s->server && s->hit) {
        /*
         * Check extended master secret extension is consistent with
         * original session.
         */
        if (!(s->s3->flags & TLS1_FLAGS_RECEIVED_EXTMS) !=
            !(s->session->flags & SSL_SESS_FLAG_EXTMS)) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_FINAL_EMS, SSL_R_INCONSISTENT_EXTMS);
            return 0;
        }
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
static int init_srtp(SSL *s, unsigned int context)
{
    if (s->server)
        s->srtp_profile = NULL;

    return 1;
}
#endif

static int final_sig_algs(SSL *s, unsigned int context, int sent, int *al)
{
    if (!sent && SSL_IS_TLS13(s)) {
        *al = TLS13_AD_MISSING_EXTENSION;
        SSLerr(SSL_F_FINAL_SIG_ALGS, SSL_R_MISSING_SIGALGS_EXTENSION);
        return 0;
    }

    return 1;
}
