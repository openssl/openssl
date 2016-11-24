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

typedef struct {
    /* The ID for the extension */
    unsigned int type;
    int (*server_parse)(SSL *s, PACKET *pkt);
    int (*client_parse)(SSL *s, PACKET *pkt);
    unsigned int context;
} EXTENSION_DEFINITION;


static const EXTENSION_DEFINITION ext_defs[] = {
    {
        TLSEXT_TYPE_renegotiate,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_server_name,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
    {
        TLSEXT_TYPE_srp,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_ec_point_formats,
        NULL, NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_supported_groups,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
    {
        TLSEXT_TYPE_session_ticket,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_signature_algorithms,
        NULL, NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_status_request,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_3_CERTIFICATE
    },
    {
        TLSEXT_TYPE_next_proto_neg,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
    {
        TLSEXT_TYPE_use_srtp,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS | EXT_DTLS_ONLY
    },
    {
        TLSEXT_TYPE_encrypt_then_mac,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_signed_certificate_timestamp,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_3_CERTIFICATE
    },
    {
        TLSEXT_TYPE_extended_master_secret,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
    },
    {
        TLSEXT_TYPE_supported_versions,
        NULL, NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_padding,
        NULL, NULL,
        EXT_CLIENT_HELLO
    },
    {
        TLSEXT_TYPE_key_share,
        NULL, NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_SERVER_HELLO
        | EXT_TLS1_3_HELLO_RETRY_REQUEST
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
            /* Make sure we don't use DTLS extensions in TLS */
            if ((ext_defs[i].context & EXT_DTLS_ONLY) && !SSL_IS_DTLS(s))
                return 0;

            return 1;
        }
    }

    /* Unknown extension. We allow it */
    return 1;
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
        raw_extensions = OPENSSL_malloc(sizeof(*raw_extensions)
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
