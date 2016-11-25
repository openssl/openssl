/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

static int tls_ext_final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al);
static int tls_ext_init_server_name(SSL *s, unsigned int context);
static int tls_ext_final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al);
static int tls_ext_init_status_request(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_ext_init_npn(SSL *s, unsigned int context);
#endif
static int tls_ext_init_alpn(SSL *s, unsigned int context);
static int tls_ext_init_sig_algs(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_SRP
static int tls_ext_init_srp(SSL *s, unsigned int context);
#endif
static int tls_ext_init_etm(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_SRTP
static int tls_ext_init_srtp(SSL *s, unsigned int context);
#endif

typedef struct {
    /* The ID for the extension */
    unsigned int type;
    /*
     * Initialise extension before parsing. Always called for relevant contexts
     * even if extension not present
     */
    int (*init_ext)(SSL *s, unsigned int context);
    /* Parse extension received by server from client */
    int (*parse_client_ext)(SSL *s, PACKET *pkt, int *al);
    /* Parse extension received by client from server */
    int (*parse_server_ext)(SSL *s, PACKET *pkt, int *al);
    /* Construct extension sent by server */
    int (*construct_server_ext)(SSL *s, WPACKET *pkt, int *al);
    /* Construct extension sent by client */
    int (*construct_client_ext)(SSL *s, WPACKET *pkt, int *al);
    /*
     * Finalise extension after parsing. Always called where an extensions was
     * initialised even if the extension was not present. |sent| is set to 1 if
     * the extension was seen, or 0 otherwise.
     */
    int (*finalise_ext)(SSL *s, unsigned int context, int sent, int *al);
    unsigned int context;
} EXTENSION_DEFINITION;

/*
 * TODO(TLS1.3): Temporarily modified the definitions below to put all TLS1.3
 * extensions in the ServerHello for now. That needs to be put back to correct
 * setting once encrypted extensions is working properly.
 */
static const EXTENSION_DEFINITION ext_defs[] = {
    {
        TLSEXT_TYPE_renegotiate,
        NULL,
        tls_parse_client_renegotiate,
        tls_parse_server_renegotiate,
        tls_construct_server_renegotiate,
        tls_construct_client_renegotiate,
        tls_ext_final_renegotiate,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_SSL3_ALLOWED
        | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_server_name,
        tls_ext_init_server_name,
        tls_parse_client_server_name,
        tls_parse_server_server_name,
        tls_construct_server_server_name,
        tls_construct_client_server_name,
        tls_ext_final_server_name,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#ifndef OPENSSL_NO_SRP
    {
        TLSEXT_TYPE_srp,
        tls_ext_init_srp,
        tls_parse_client_srp,
        NULL,
        NULL,
        tls_construct_client_srp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
#ifndef OPENSSL_NO_EC
    {
        TLSEXT_TYPE_ec_point_formats,
        NULL,
        tls_parse_client_ec_pt_formats,
        tls_parse_server_ec_pt_formats,
        tls_construct_server_ec_pt_formats,
        tls_construct_client_ec_pt_formats,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_groups,
        NULL,
        tls_parse_client_supported_groups,
        NULL,
        NULL /* TODO(TLS1.3): Need to add this */,
        tls_construct_client_supported_groups,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#endif
    {
        TLSEXT_TYPE_session_ticket,
        NULL,
        tls_parse_client_session_ticket,
        tls_parse_server_session_ticket,
        tls_construct_server_session_ticket,
        tls_construct_client_session_ticket,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_signature_algorithms,
        tls_ext_init_sig_algs,
        tls_parse_client_sig_algs,
        NULL,
        NULL,
        tls_construct_client_sig_algs,
        NULL,
        EXT_CLIENT_HELLO
    },
#ifndef OPENSSL_NO_OCSP
    {
        TLSEXT_TYPE_status_request,
        tls_ext_init_status_request,
        tls_parse_client_status_request,
        tls_parse_server_status_request,
        tls_construct_server_status_request,
        tls_construct_client_status_request,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE
    },
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {
        TLSEXT_TYPE_next_proto_neg,
        tls_ext_init_npn,
        tls_parse_client_npn,
        tls_parse_server_npn,
        tls_construct_server_next_proto_neg,
        tls_construct_client_npn,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
    {
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        tls_ext_init_alpn,
        tls_parse_client_alpn,
        tls_parse_server_alpn,
        tls_construct_server_alpn,
        tls_construct_client_alpn,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#ifndef OPENSSL_NO_SRTP
    {
        TLSEXT_TYPE_use_srtp,
        tls_ext_init_srtp,
        tls_parse_client_use_srtp,
        tls_parse_server_use_srtp,
        tls_construct_server_use_srtp,
        tls_construct_client_use_srtp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS | EXT_DTLS_ONLY
    },
#endif
    {
        TLSEXT_TYPE_encrypt_then_mac,
        tls_ext_init_etm,
        tls_parse_client_etm,
        tls_parse_server_etm,
        tls_construct_server_etm,
        tls_construct_client_etm,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#ifndef OPENSSL_NO_CT
    {
        TLSEXT_TYPE_signed_certificate_timestamp,
        NULL,
        /*
         * No server side support for this, but can be provided by a custom
         * extension. This is an exception to the rule that custom extensions
         * cannot override built in ones.
         */
        NULL,
        tls_parse_server_sct,
        NULL,
        tls_construct_client_sct,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE
    },
#endif
    {
        TLSEXT_TYPE_extended_master_secret,
        NULL,
        tls_parse_client_ems,
        tls_parse_server_ems,
        tls_construct_server_ems,
        tls_construct_client_ems,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_versions,
        NULL,
        /* Processed inline as part of version selection */
        NULL,
        NULL,
        NULL,
        tls_construct_client_supported_versions,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS_IMPLEMENTATION_ONLY | EXT_TLS1_3_ONLY
    },
    {
        TLSEXT_TYPE_key_share,
        NULL,
        tls_parse_client_key_share,
        tls_parse_server_key_share,
        tls_construct_server_key_share,
        tls_construct_client_key_share,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_SERVER_HELLO
        | EXT_TLS1_3_HELLO_RETRY_REQUEST | EXT_TLS_IMPLEMENTATION_ONLY
        | EXT_TLS1_3_ONLY
    },
    {
        /*
         * Special unsolicited ServerHello extension only used when
         * SSL_OP_CRYPTOPRO_TLSEXT_BUG is set
         */
        TLSEXT_TYPE_cryptopro_bug,
        NULL,
        NULL,
        NULL,
        tls_construct_server_cryptopro_bug,
        NULL,
        NULL,
        EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        /* Last in the list because it must be added as the last extension */
        TLSEXT_TYPE_padding,
        NULL,
        /* We send this, but don't read it */
        NULL,
        NULL,
        NULL,
        tls_construct_client_padding,
        NULL,
        EXT_CLIENT_HELLO
    }
};

/*
 * Comparison function used in a call to qsort (see tls_collect_extensions()
 * below.)
 * The two arguments |p1| and |p2| are expected to be pointers to RAW_EXTENSIONs
 *
 * Returns:
 *  1 if the type for p1 is greater than p2
 *  0 if the type for p1 and p2 are the same
 * -1 if the type for p1 is less than p2
 */
static int compare_extensions(const void *p1, const void *p2)
{
    const RAW_EXTENSION *e1 = (const RAW_EXTENSION *)p1;
    const RAW_EXTENSION *e2 = (const RAW_EXTENSION *)p2;

    if (e1->type < e2->type)
        return -1;
    else if (e1->type > e2->type)
        return 1;

    return 0;
}

/*
 * Verify whether we are allowed to use the extension |type| in the current
 * |context|. Returns 1 to indicate the extension is allowed or unknown or 0 to
 * indicate the extension is not allowed.
 */
static int verify_extension(SSL *s, unsigned int context, unsigned int type)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(ext_defs); i++) {
        if (type == ext_defs[i].type) {
            /* Check we're allowed to use this extension in this context */
            if ((context & ext_defs[i].context) == 0)
                return 0;

            if (SSL_IS_DTLS(s)) {
                if ((ext_defs[i].context & EXT_TLS_ONLY) != 0)
                    return 0;
            } else if ((ext_defs[i].context & EXT_DTLS_ONLY) != 0) {
                    return 0;
            }

            return 1;
        }
    }

    /* Unknown extension. We allow it */
    return 1;
}

/*
 * Finds an extension definition for the give extension |type|.
 * Returns 1 if found and stores the definition in |*def|, or returns 0
 * otherwise.
 */
static int find_extension_definition(SSL *s, unsigned int type,
                                     const EXTENSION_DEFINITION **def)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(ext_defs); i++) {
        if (type == ext_defs[i].type) {
            *def = &ext_defs[i];
            return 1;
        }
    }

    /* Unknown extension */
    return 0;
}

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
 * tells us which message this extension is for. Ttls_parse_server_ec_pt_formatshe raw extension data is
 * stored in |*res| with the number of found extensions in |*numfound|. In the
 * event of an error the alert type to use is stored in |*ad|. We don't actually
 * process the content of the extensions yet, except to check their types.
 *
 * Per http://tools.ietf.org/html/rfc5246#section-7.4.1.4, there may not be
 * more than one extension of the same type in a ClientHello or ServerHello.
 * This function returns 1 if all extensions are unique and we have parsed their
 * types, and 0 if the extensions contain duplicates, could not be successfully
 * parsed, or an internal error occurred.
 */

int tls_collect_extensions(SSL *s, PACKET *packet, unsigned int context,
                           RAW_EXTENSION **res, size_t *numfound, int *ad)
{
    PACKET extensions = *packet;
    size_t num_extensions = 0, i = 0;
    RAW_EXTENSION *raw_extensions = NULL;

    /* First pass: count the extensions. */
    while (PACKET_remaining(&extensions) > 0) {
        unsigned int type;
        PACKET extension;

        if (!PACKET_get_net_2(&extensions, &type) ||
            !PACKET_get_length_prefixed_2(&extensions, &extension)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *ad = SSL_AD_DECODE_ERROR;
            goto err;
        }
        /* Verify this extension is allowed */
        if (!verify_extension(s, context, type)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *ad = SSL_AD_ILLEGAL_PARAMETER;
            goto err;
        }
        num_extensions++;
    }

    if (num_extensions > 0) {
        raw_extensions = OPENSSL_zalloc(sizeof(*raw_extensions)
                                        * num_extensions);
        if (raw_extensions == NULL) {
            *ad = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Second pass: collect the extensions. */
        for (i = 0; i < num_extensions; i++) {
            if (!PACKET_get_net_2(packet, &raw_extensions[i].type) ||
                !PACKET_get_length_prefixed_2(packet,
                                              &raw_extensions[i].data)) {
                /* This should not happen. */
                *ad = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        if (PACKET_remaining(packet) != 0) {
            *ad = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        /* Sort the extensions and make sure there are no duplicates. */
        qsort(raw_extensions, num_extensions, sizeof(*raw_extensions),
              compare_extensions);
        for (i = 1; i < num_extensions; i++) {
            if (raw_extensions[i - 1].type == raw_extensions[i].type) {
                *ad = SSL_AD_DECODE_ERROR;
                goto err;
            }
        }
    }

    /*
     * Initialise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (i = 0; i < OSSL_NELEM(ext_defs); i++) {
        if(ext_defs[i].init_ext != NULL && (ext_defs[i].context & context) != 0
                && extension_is_relevant(s, ext_defs[i].context, context)
                && !ext_defs[i].init_ext(s, context)) {
            *ad = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
    }

    /*
     * Initialise server side custom extensions. Client side is done during
     * construction of extensions for the ClientHello.
     */
    if ((context & (EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_3_SERVER_HELLO)) != 0)
        custom_ext_init(&s->cert->srv_ext);

    *res = raw_extensions;
    *numfound = num_extensions;
    return 1;

 err:
    OPENSSL_free(raw_extensions);
    return 0;
}

/*
 * Runs the parsers for all of the extensions in the given list |exts|, which
 * should have |numexts| extensions in it. The parsers are only run if they are
 * applicable for the given |context| and the parser has not already been run
 * for that extension. Returns 1 on success or 0 on failure. In the event of a
 * failure |*al| is populated with a suitable alert code.
 */
static int tls_parse_extension_list(SSL *s, int context, RAW_EXTENSION *exts,
                                    size_t numexts, int *al)
{
    size_t loop;

    for (loop = 0; loop < numexts; loop++) {
        RAW_EXTENSION *currext = &exts[loop];
        const EXTENSION_DEFINITION *extdef = NULL;
        int (*parser)(SSL *s, PACKET *pkt, int *al) = NULL;

        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, !s->server, currext->type,
                               PACKET_data(&currext->data),
                               PACKET_remaining(&currext->data),
                               s->tlsext_debug_arg);

        /* Skip if we've already parsed this extension */
        if (currext->parsed)
            continue;

        currext->parsed = 1;

        parser = NULL;
        if (find_extension_definition(s, currext->type, &extdef)) {
            parser = s->server ? extdef->parse_client_ext
                               : extdef->parse_server_ext;

            /* Check if extension is defined for our protocol. If not, skip */
            if (!extension_is_relevant(s, extdef->context, context))
                continue;
        }

        if (parser == NULL) {
            /*
             * Could be a custom extension. We only allow this if it is a non
             * resumed session on the server side.
             * 
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

            continue;
        }

        if (!parser(s, &currext->data, al))
            return 0;
    }

    return 1;
}

/*
 * Parse all remaining extensions that have not yet been parsed. Also calls the
 * finalisation for all extensions at the end. The given extensions must be in
 * order of type (which happens by default during collection). Returns 1 for
 * success or 0 for failure. On failure, |*al| is populated with a suitable
 * alert code.
 */
int tls_parse_all_extensions(SSL *s, int context, RAW_EXTENSION *exts,
                             size_t numexts, int *al)
{
    size_t loop;

    if (!tls_parse_extension_list(s, context, exts, numexts, al))
        return 0;

    /*
     * Finalise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (loop = 0; loop < OSSL_NELEM(ext_defs); loop++) {
        if(ext_defs[loop].finalise_ext != NULL
                && (ext_defs[loop].context & context) != 0) {
            size_t curr;

            /*
             * Work out whether this extension was sent or not. The sent
             * extensions in |exts| are sorted by order of type
             */
            for (curr = 0; curr < numexts
                           && exts[curr].type < ext_defs[loop].type; curr++)
                continue;

            if (!ext_defs[loop].finalise_ext(s, context,
                    (curr < numexts && exts[curr].type == ext_defs[loop].type),
                    al))
            return 0;
        }
    }

    return 1;
}

/*
 * Find a specific extension by |type| in the list |exts| containing |numexts|
 * extensions, and the parse it immediately. Returns 1 on success, or 0 on
 * failure. If a failure has occurred then |*al| will also be set to the alert
 * to be sent.
 */
int tls_parse_extension(SSL *s, int type, int context, RAW_EXTENSION *exts,
                        size_t numexts, int *al)
{
    RAW_EXTENSION *ext = tls_get_extension_by_type(exts, numexts, type);

    if (ext == NULL)
        return 1;

    return tls_parse_extension_list(s, context, ext, 1, al);
}

int tls_construct_extensions(SSL *s, WPACKET *pkt, unsigned int context,
                             int *al)
{
    size_t loop;
    int addcustom = 0;
    int min_version, max_version = 0, reason;

    /*
     * Normally if something goes wrong during construction its an internal
     * error. We can always override this later.
     */
    *al = SSL_AD_INTERNAL_ERROR;

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
        return 0;
    }

    if ((context & EXT_CLIENT_HELLO) != 0) {
        reason = ssl_get_client_min_max_version(s, &min_version, &max_version);
        if (reason != 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, reason);
            return 0;
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

    if (addcustom && !custom_ext_add(s, s->server, pkt, al)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    for (loop = 0; loop < OSSL_NELEM(ext_defs); loop++) {
        int (*construct)(SSL *s, WPACKET *pkt, int *al);

        /* Skip if not relevant for our context */
        if ((ext_defs[loop].context & context) == 0)
            continue;

        construct = s->server ? ext_defs[loop].construct_server_ext
                              : ext_defs[loop].construct_client_ext;

        /* Check if this extension is defined for our protocol. If not, skip */
        if ((SSL_IS_DTLS(s)
                    && (ext_defs[loop].context & EXT_TLS_IMPLEMENTATION_ONLY)
                       != 0)
                || (s->version == SSL3_VERSION
                        && (ext_defs[loop].context & EXT_SSL3_ALLOWED) == 0)
                || (SSL_IS_TLS13(s)
                    && (ext_defs[loop].context & EXT_TLS1_2_AND_BELOW_ONLY)
                       != 0)
                || (!SSL_IS_TLS13(s)
                    && (ext_defs[loop].context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) == 0)
                || ((ext_defs[loop].context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) != 0
                    && (SSL_IS_DTLS(s) || max_version < TLS1_3_VERSION))
                || construct == NULL)
            continue;

        if (!construct(s, pkt, al))
            return 0;
    }

    if (!WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int tls_ext_final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    if (!s->server)
        return 1;

    /* Need RI if renegotiating */
    if (s->renegotiate
            && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            && !sent) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_EXT_FINAL_RENEGOTIATE,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    return 1;
}

static int tls_ext_init_server_name(SSL *s, unsigned int context)
{
    if (s->server)
        s->servername_done = 0;

    return 1;
}

/* Call the servername callback. Returns 1 for success or 0 for failure. */
static int tls_ext_final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int altmp = SSL_AD_UNRECOGNIZED_NAME;

    if (!s->server)
        return 1;

    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret = s->ctx->tlsext_servername_callback(s, &altmp,
                                                 s->ctx->tlsext_servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->tlsext_servername_callback != 0)
        ret = s->initial_ctx->tlsext_servername_callback(s, &altmp,
                                       s->initial_ctx->tlsext_servername_arg);

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

static int tls_ext_init_status_request(SSL *s, unsigned int context)
{
    if (s->server)
        s->tlsext_status_type = -1;

    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_ext_init_npn(SSL *s, unsigned int context)
{
    if (s->server)
        s->s3->next_proto_neg_seen = 0;

    return 1;
}
#endif

static int tls_ext_init_alpn(SSL *s, unsigned int context)
{
    if (s->server) {
        OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = NULL;
        s->s3->alpn_selected_len = 0;
        OPENSSL_free(s->s3->alpn_proposed);
        s->s3->alpn_proposed = NULL;
        s->s3->alpn_proposed_len = 0;
    }

    return 1;
}

static int tls_ext_init_sig_algs(SSL *s, unsigned int context)
{
    /* Clear any signature algorithms extension received */
    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = NULL;

    return 1;
}

#ifndef OPENSSL_NO_SRP
static int tls_ext_init_srp(SSL *s, unsigned int context)
{
    OPENSSL_free(s->srp_ctx.login);
    s->srp_ctx.login = NULL;

    return 1;
}
#endif

static int tls_ext_init_etm(SSL *s, unsigned int context)
{
    if (s->server)
        s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

#ifndef OPENSSL_NO_SRTP
static int tls_ext_init_srtp(SSL *s, unsigned int context)
{
    if (s->server)
        s->srtp_profile = NULL;

    return 1;
}
#endif
