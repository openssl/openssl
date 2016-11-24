/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/ocsp.h>
#include "../ssl_locl.h"
#include "statem_locl.h"

static int tls_parse_clienthello_renegotiate(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_server_name(SSL *s, PACKET *pkt, int *al);
#ifndef OPENSSL_NO_SRP
static int tls_parse_clienthello_srp(SSL *s, PACKET *pkt, int *al);
#endif
#ifndef OPENSSL_NO_EC
static int tls_parse_clienthello_ec_pt_formats(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_supported_groups(SSL *s, PACKET *pkt, int *al);
#endif
static int tls_parse_clienthello_session_ticket(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_sig_algs(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_status_request(SSL *s, PACKET *pkt, int *al);
#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_parse_clienthello_npn(SSL *s, PACKET *pkt, int *al);
#endif
static int tls_parse_clienthello_alpn(SSL *s, PACKET *pkt, int *al);
#ifndef OPENSSL_NO_SRTP
static int tls_parse_clienthello_use_srtp(SSL *s, PACKET *pkt, int *al);
#endif
static int tls_parse_clienthello_etm(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_key_share(SSL *s, PACKET *pkt, int *al);
static int tls_parse_clienthello_ems(SSL *s, PACKET *pkt, int *al);

typedef struct {
    /* The ID for the extension */
    unsigned int type;
    int (*server_parse)(SSL *s, PACKET *pkt, int *al);
    int (*client_parse)(SSL *s, PACKET *pkt, int *al);
    unsigned int context;
} EXTENSION_DEFINITION;

static const EXTENSION_DEFINITION ext_defs[] = {
    {
        TLSEXT_TYPE_renegotiate,
        tls_parse_clienthello_renegotiate,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_SSL3_ALLOWED
        | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_server_name,
        tls_parse_clienthello_server_name,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#ifndef OPENSSL_NO_SRP
    {
        TLSEXT_TYPE_srp,
        tls_parse_clienthello_srp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
#ifndef OPENSSL_NO_EC
    {
        TLSEXT_TYPE_ec_point_formats,
        tls_parse_clienthello_ec_pt_formats,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_groups,
        tls_parse_clienthello_supported_groups,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#endif
    {
        TLSEXT_TYPE_session_ticket,
        tls_parse_clienthello_session_ticket,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_signature_algorithms,
        tls_parse_clienthello_sig_algs,
        NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_status_request,
        tls_parse_clienthello_status_request,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_3_CERTIFICATE
    },
#ifndef OPENSSL_NO_NEXTPROTONEG
    {
        TLSEXT_TYPE_next_proto_neg,
        tls_parse_clienthello_npn,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
    {
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        tls_parse_clienthello_alpn,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
    {
        TLSEXT_TYPE_use_srtp,
        tls_parse_clienthello_use_srtp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS | EXT_DTLS_ONLY
    },
    {
        TLSEXT_TYPE_encrypt_then_mac,
        tls_parse_clienthello_etm,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_signed_certificate_timestamp,
        /*
         * No server side support for this, but can be provided by a custom
         * extension. This is an exception to the rule that custom extensions
         * cannot override built in ones.
         */
        NULL,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_3_CERTIFICATE
    },
    {
        TLSEXT_TYPE_extended_master_secret,
        tls_parse_clienthello_ems,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_versions,
        /* Processed inline as part of version selection */
        NULL,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS_IMPLEMENTATION_ONLY
    },
    {
        TLSEXT_TYPE_padding,
        /* We send this, but don't read it */
        NULL,
        NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_key_share,
        tls_parse_clienthello_key_share,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_SERVER_HELLO
        | EXT_TLS1_3_HELLO_RETRY_REQUEST | EXT_TLS_IMPLEMENTATION_ONLY
        | EXT_TLS1_3_ONLY
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

/*
 * Gather a list of all the extensions from the data in |packet]. |context|
 * tells us which message this extension is for. The raw extension data is
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
/*
 * TODO(TLS1.3): Refactor ServerHello extension parsing to use this and then
 * remove tls1_check_duplicate_extensions()
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

    *res = raw_extensions;
    *numfound = num_extensions;
    return 1;

 err:
    OPENSSL_free(raw_extensions);
    return 0;
}

int tls_parse_all_extensions(SSL *s, RAW_EXTENSION *exts, size_t numexts,
                             int *al)
{
    size_t loop;

    for (loop = 0; loop < numexts; loop++) {
        RAW_EXTENSION *currext = &exts[loop];
        const EXTENSION_DEFINITION *extdef = NULL;
        int (*parser)(SSL *s, PACKET *pkt, int *al) = NULL;

        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, 0, currext->type,
                               PACKET_data(&currext->data),
                               PACKET_remaining(&currext->data),
                               s->tlsext_debug_arg);

        /* Skip if we've already parsed this extension */
        if (currext->parsed)
            continue;

        currext->parsed = 1;

        parser = NULL;
        if (find_extension_definition(s, currext->type, &extdef))
            parser = s->server ? extdef->server_parse : extdef->client_parse;

        if (parser == NULL) {
            /*
             * Could be a custom extension. We only allow this if it is a non
             * resumed session on the server side
             */
            if ((!s->hit || !s->server)
                    && custom_ext_parse(s, s->server, currext->type,
                                        PACKET_data(&currext->data),
                                        PACKET_remaining(&currext->data),
                                        al) <= 0)
                return 0;

            continue;
        }

        /* Check if this extension is defined for our protocol. If not, skip */
        if ((SSL_IS_DTLS(s)
                    && (extdef->context & EXT_TLS_IMPLEMENTATION_ONLY) != 0)
                || (s->version == SSL3_VERSION
                        && (extdef->context & EXT_SSL3_ALLOWED) == 0)
                || (SSL_IS_TLS13(s)
                    && (extdef->context & EXT_TLS1_2_AND_BELOW_ONLY) != 0)
                || (!SSL_IS_TLS13(s)
                    && (extdef->context & EXT_TLS1_3_ONLY) != 0)
                || (s->server && extdef->server_parse == NULL)
                || (!s->server && extdef->client_parse == NULL))
            continue;

        if (!parser(s, &currext->data, al))
            return 0;
    }

    return 1;
}

/*
 * Find a specific extension by |type| in the list |exts| containing |numexts|
 * extensions, and the parse it immediately. Returns 1 on success, or 0 on
 * failure. If a failure has occurred then |*al| will also be set to the alert
 * to be sent.
 */
int tls_parse_extension(SSL *s, int type,  RAW_EXTENSION *exts, size_t numexts,
                        int *al)
{
    RAW_EXTENSION *ext = tls_get_extension_by_type(exts, numexts, type);

    if (ext == NULL)
        return 1;

    return tls_parse_all_extensions(s, ext, 1, al);
}


/*
 * Parse the client's renegotiation binding and abort if it's not right
 */
static int tls_parse_clienthello_renegotiate(SSL *s, PACKET *pkt, int *al)
{
    unsigned int ilen;
    const unsigned char *data;

    /* Parse the length byte */
    if (!PACKET_get_1(pkt, &ilen)
        || !PACKET_get_bytes(pkt, &data, ilen)) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

    /* Check that the extension matches */
    if (ilen != s->s3->previous_client_finished_len) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    if (memcmp(data, s->s3->previous_client_finished,
               s->s3->previous_client_finished_len)) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT,
               SSL_R_RENEGOTIATION_MISMATCH);
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }

    s->s3->send_connection_binding = 1;

    return 1;
}

static int tls_parse_clienthello_server_name(SSL *s, PACKET *pkt, int *al)
{
    unsigned int servname_type;
    PACKET sni, hostname;

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
    if (!PACKET_as_length_prefixed_2(pkt, &sni)
        /* ServerNameList must be at least 1 byte long. */
        || PACKET_remaining(&sni) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * Although the server_name extension was intended to be
     * extensible to new name types, RFC 4366 defined the
     * syntax inextensibility and OpenSSL 1.0.x parses it as
     * such.
     * RFC 6066 corrected the mistake but adding new name types
     * is nevertheless no longer feasible, so act as if no other
     * SNI types can exist, to simplify parsing.
     *
     * Also note that the RFC permits only one SNI value per type,
     * i.e., we can only have a single hostname.
     */
    if (!PACKET_get_1(&sni, &servname_type)
        || servname_type != TLSEXT_NAMETYPE_host_name
        || !PACKET_as_length_prefixed_2(&sni, &hostname)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit) {
        if (PACKET_remaining(&hostname) > TLSEXT_MAXLEN_host_name) {
            *al = TLS1_AD_UNRECOGNIZED_NAME;
            return 0;
        }

        if (PACKET_contains_zero_byte(&hostname)) {
            *al = TLS1_AD_UNRECOGNIZED_NAME;
            return 0;
        }

        if (!PACKET_strndup(&hostname, &s->session->tlsext_hostname)) {
            *al = TLS1_AD_INTERNAL_ERROR;
            return 0;
        }

        s->servername_done = 1;
    } else {
        /*
         * TODO(openssl-team): if the SNI doesn't match, we MUST
         * fall back to a full handshake.
         */
        s->servername_done = s->session->tlsext_hostname
            && PACKET_equal(&hostname, s->session->tlsext_hostname,
                            strlen(s->session->tlsext_hostname));
    }

    return 1;
}

#ifndef OPENSSL_NO_SRP
static int tls_parse_clienthello_srp(SSL *s, PACKET *pkt, int *al)
{
    PACKET srp_I;

    if (!PACKET_as_length_prefixed_1(pkt, &srp_I)
            || PACKET_contains_zero_byte(&srp_I)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    /*
     * TODO(openssl-team): currently, we re-authenticate the user
     * upon resumption. Instead, we MUST ignore the login.
     */
    if (!PACKET_strndup(&srp_I, &s->srp_ctx.login)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_EC
static int tls_parse_clienthello_ec_pt_formats(SSL *s, PACKET *pkt, int *al)
{
    PACKET ec_point_format_list;

    if (!PACKET_as_length_prefixed_1(pkt, &ec_point_format_list)
        || PACKET_remaining(&ec_point_format_list) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit) {
        if (!PACKET_memdup(&ec_point_format_list,
                           &s->session->tlsext_ecpointformatlist,
                           &s->session->tlsext_ecpointformatlist_length)) {
            *al = TLS1_AD_INTERNAL_ERROR;
            return 0;
        }
    }

    return 1;
}
#endif                          /* OPENSSL_NO_EC */

static int tls_parse_clienthello_session_ticket(SSL *s, PACKET *pkt, int *al)
{
    if (s->tls_session_ticket_ext_cb &&
            !s->tls_session_ticket_ext_cb(s, PACKET_data(pkt),
                                          PACKET_remaining(pkt),
                                          s->tls_session_ticket_ext_cb_arg)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}

static int tls_parse_clienthello_sig_algs(SSL *s, PACKET *pkt, int *al)
{
    PACKET supported_sig_algs;

    if (!PACKET_as_length_prefixed_2(pkt, &supported_sig_algs)
            || (PACKET_remaining(&supported_sig_algs) % 2) != 0
            || PACKET_remaining(&supported_sig_algs) == 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit && !tls1_save_sigalgs(s, PACKET_data(&supported_sig_algs),
                                      PACKET_remaining(&supported_sig_algs))) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}

static int tls_parse_clienthello_status_request(SSL *s, PACKET *pkt, int *al)
{
    if (!PACKET_get_1(pkt, (unsigned int *)&s->tlsext_status_type)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }
#ifndef OPENSSL_NO_OCSP
    if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
        const unsigned char *ext_data;
        PACKET responder_id_list, exts;
        if (!PACKET_get_length_prefixed_2 (pkt, &responder_id_list)) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        /*
         * We remove any OCSP_RESPIDs from a previous handshake
         * to prevent unbounded memory growth - CVE-2016-6304
         */
        sk_OCSP_RESPID_pop_free(s->tlsext_ocsp_ids, OCSP_RESPID_free);
        if (PACKET_remaining(&responder_id_list) > 0) {
            s->tlsext_ocsp_ids = sk_OCSP_RESPID_new_null();
            if (s->tlsext_ocsp_ids == NULL) {
                *al = SSL_AD_INTERNAL_ERROR;
                return 0;
            }
        } else {
            s->tlsext_ocsp_ids = NULL;
        }

        while (PACKET_remaining(&responder_id_list) > 0) {
            OCSP_RESPID *id;
            PACKET responder_id;
            const unsigned char *id_data;

            if (!PACKET_get_length_prefixed_2(&responder_id_list,
                                              &responder_id)
                    || PACKET_remaining(&responder_id) == 0) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

            id_data = PACKET_data(&responder_id);
            /* TODO(size_t): Convert d2i_* to size_t */
            id = d2i_OCSP_RESPID(NULL, &id_data,
                                 (int)PACKET_remaining(&responder_id));
            if (id == NULL) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

            if (id_data != PACKET_end(&responder_id)) {
                OCSP_RESPID_free(id);
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

            if (!sk_OCSP_RESPID_push(s->tlsext_ocsp_ids, id)) {
                OCSP_RESPID_free(id);
                *al = SSL_AD_INTERNAL_ERROR;
                return 0;
            }
        }

        /* Read in request_extensions */
        if (!PACKET_as_length_prefixed_2(pkt, &exts)) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        if (PACKET_remaining(&exts) > 0) {
            ext_data = PACKET_data(&exts);
            sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts,
                                       X509_EXTENSION_free);
            s->tlsext_ocsp_exts =
                d2i_X509_EXTENSIONS(NULL, &ext_data,
                                    (int)PACKET_remaining(&exts));
            if (s->tlsext_ocsp_exts == NULL || ext_data != PACKET_end(&exts)) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
        }
    } else
#endif
    {
        /*
         * We don't know what to do with any other type so ignore it.
         */
        s->tlsext_status_type = -1;
    }

    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_parse_clienthello_npn(SSL *s, PACKET *pkt, int *al)
{
    if (s->s3->tmp.finish_md_len == 0) {
        /*-
         * We shouldn't accept this extension on a
         * renegotiation.
         *
         * s->new_session will be set on renegotiation, but we
         * probably shouldn't rely that it couldn't be set on
         * the initial renegotiation too in certain cases (when
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

    return 1;
}
#endif

/*
 * Save the ALPN extension in a ClientHello.
 * pkt: the contents of the ALPN extension, not including type and length.
 * al: a pointer to the  alert value to send in the event of a failure.
 * returns: 1 on success, 0 on error.
 */
static int tls_parse_clienthello_alpn(SSL *s, PACKET *pkt, int *al)
{
    PACKET protocol_list, save_protocol_list, protocol;

    if (s->s3->tmp.finish_md_len != 0)
        return 1;

    if (!PACKET_as_length_prefixed_2(pkt, &protocol_list)
        || PACKET_remaining(&protocol_list) < 2) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    save_protocol_list = protocol_list;
    do {
        /* Protocol names can't be empty. */
        if (!PACKET_get_length_prefixed_1(&protocol_list, &protocol)
                || PACKET_remaining(&protocol) == 0) {
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }
    } while (PACKET_remaining(&protocol_list) != 0);

    if (!PACKET_memdup(&save_protocol_list,
                       &s->s3->alpn_proposed, &s->s3->alpn_proposed_len)) {
        *al = TLS1_AD_INTERNAL_ERROR;
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
static int tls_parse_clienthello_use_srtp(SSL *s, PACKET *pkt, int *al)
{
    SRTP_PROTECTION_PROFILE *sprof;
    STACK_OF(SRTP_PROTECTION_PROFILE) *srvr;
    unsigned int ct, mki_len, id;
    int i, srtp_pref;
    PACKET subpkt;

    /* Ignore this if we have no SRTP profiles */
    if (SSL_get_srtp_profiles(s) == NULL)
        return 1;

    /* Pull off the length of the cipher suite list  and check it is even */
    if (!PACKET_get_net_2(pkt, &ct)
        || (ct & 1) != 0 || !PACKET_get_sub_packet(pkt, &subpkt, ct)) {
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    srvr = SSL_get_srtp_profiles(s);
    s->srtp_profile = NULL;
    /* Search all profiles for a match initially */
    srtp_pref = sk_SRTP_PROTECTION_PROFILE_num(srvr);

    while (PACKET_remaining(&subpkt)) {
        if (!PACKET_get_net_2(&subpkt, &id)) {
            SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_USE_SRTP,
                   SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
            *al = SSL_AD_DECODE_ERROR;
            return 0;
        }

        /*
         * Only look for match in profiles of higher preference than
         * current match.
         * If no profiles have been have been configured then this
         * does nothing.
         */
        for (i = 0; i < srtp_pref; i++) {
            sprof = sk_SRTP_PROTECTION_PROFILE_value(srvr, i);
            if (sprof->id == id) {
                s->srtp_profile = sprof;
                srtp_pref = i;
                break;
            }
        }
    }

    /*
     * Now extract the MKI value as a sanity check, but discard it for now
     */
    if (!PACKET_get_1(pkt, &mki_len)) {
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_USE_SRTP,
               SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!PACKET_forward(pkt, mki_len)
        || PACKET_remaining(pkt)) {
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_USE_SRTP, SSL_R_BAD_SRTP_MKI_VALUE);
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}
#endif

static int tls_parse_clienthello_etm(SSL *s, PACKET *pkt, int *al)
{
    if (!(s->options & SSL_OP_NO_ENCRYPT_THEN_MAC))
        s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

/*
 * Checks a list of |groups| to determine if the |group_id| is in it. If it is
 * and |checkallow| is 1 then additionally check if the group is allowed to be
 * used. Returns 1 if the group is in the list (and allowed if |checkallow| is
 * 1) or 0 otherwise.
 */
static int check_in_list(SSL *s, unsigned int group_id,
                         const unsigned char *groups, size_t num_groups,
                         int checkallow)
{
    size_t i;

    if (groups == NULL || num_groups == 0)
        return 0;

    for (i = 0; i < num_groups; i++, groups += 2) {
        unsigned int share_id = (groups[0] << 8) | (groups[1]);

        if (group_id == share_id
                && (!checkallow || tls_curve_allowed(s, groups,
                                                     SSL_SECOP_CURVE_CHECK))) {
            break;
        }
    }

    /* If i == num_groups then not in the list */
    return i < num_groups;
}

/*
 * Process a key_share extension received in the ClientHello. |pkt| contains
 * the raw PACKET data for the extension. Returns 1 on success or 0 on failure.
 * If a failure occurs then |*al| is set to an appropriate alert value.
 */
static int tls_parse_clienthello_key_share(SSL *s, PACKET *pkt, int *al)
{
    unsigned int group_id;
    PACKET key_share_list, encoded_pt;
    const unsigned char *clntcurves, *srvrcurves;
    size_t clnt_num_curves, srvr_num_curves;
    int group_nid, found = 0;
    unsigned int curve_flags;

    if (s->hit)
        return 1;

    /* Sanity check */
    if (s->s3->peer_tmp != NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &key_share_list)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    /* Get our list of supported curves */
    if (!tls1_get_curvelist(s, 0, &srvrcurves, &srvr_num_curves)) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Get the clients list of supported curves */
    if (!tls1_get_curvelist(s, 1, &clntcurves, &clnt_num_curves)) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    while (PACKET_remaining(&key_share_list) > 0) {
        if (!PACKET_get_net_2(&key_share_list, &group_id)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE,
                   SSL_R_LENGTH_MISMATCH);
            return 0;
        }

        /*
         * If we already found a suitable key_share we loop through the
         * rest to verify the structure, but don't process them.
         */
        if (found)
            continue;

        /* Check if this share is in supported_groups sent from client */
        if (!check_in_list(s, group_id, clntcurves, clnt_num_curves, 0)) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, SSL_R_BAD_KEY_SHARE);
            return 0;
        }

        /* Check if this share is for a group we can use */
        if (!check_in_list(s, group_id, srvrcurves, srvr_num_curves, 1)) {
            /* Share not suitable */
            continue;
        }

        group_nid = tls1_ec_curve_id2nid(group_id, &curve_flags);

        if (group_nid == 0) {
            *al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            return 0;
        }

        if ((curve_flags & TLS_CURVE_TYPE) == TLS_CURVE_CUSTOM) {
            /* Can happen for some curves, e.g. X25519 */
            EVP_PKEY *key = EVP_PKEY_new();

            if (key == NULL || !EVP_PKEY_set_type(key, group_nid)) {
                *al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, ERR_R_EVP_LIB);
                EVP_PKEY_free(key);
                return 0;
            }
            s->s3->peer_tmp = key;
        } else {
            /* Set up EVP_PKEY with named curve as parameters */
            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (pctx == NULL
                    || EVP_PKEY_paramgen_init(pctx) <= 0
                    || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                              group_nid) <= 0
                    || EVP_PKEY_paramgen(pctx, &s->s3->peer_tmp) <= 0) {
                *al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, ERR_R_EVP_LIB);
                EVP_PKEY_CTX_free(pctx);
                return 0;
            }
            EVP_PKEY_CTX_free(pctx);
            pctx = NULL;
        }
        s->s3->group_id = group_id;

        if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
                PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
            *al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_TLS_PARSE_CLIENTHELLO_KEY_SHARE, SSL_R_BAD_ECPOINT);
            return 0;
        }

        found = 1;
    }

    return 1;
}

#ifndef OPENSSL_NO_EC
static int tls_parse_clienthello_supported_groups(SSL *s, PACKET *pkt, int *al)
{
    PACKET supported_groups_list;

    /* Each group is 2 bytes and we must have at least 1. */
    if (!PACKET_as_length_prefixed_2(pkt, &supported_groups_list)
            || PACKET_remaining(&supported_groups_list) == 0
            || (PACKET_remaining(&supported_groups_list) % 2) != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit
            && !PACKET_memdup(&supported_groups_list,
                              &s->session->tlsext_supportedgroupslist,
                              &s->session->tlsext_supportedgroupslist_length)) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}
#endif

static int tls_parse_clienthello_ems(SSL *s, PACKET *pkt, int *al)
{
    /* The extension must always be empty */
    if (PACKET_remaining(pkt) != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    s->s3->flags |= TLS1_FLAGS_RECEIVED_EXTMS;

    return 1;
}
