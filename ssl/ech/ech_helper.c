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
#include "internal/ech_helpers.h"

/* TODO(ECH): move more code that's used by internals and test here */

/* used in ECH crypto derivations (odd format for EBCDIC goodness) */
/* "tls ech" */
static const char OSSL_ECH_CONTEXT_STRING[] = "\x74\x6c\x73\x20\x65\x63\x68";

/*
 * Construct HPKE "info" input as per spec
 * encoding is the ECHconfig being used
 * encoding_length is the length of ECHconfig being used
 * info is a caller-allocated buffer for results
 * info_len is the buffer size on input, used-length on output
 * return 1 for success, zero otherwise
 */
int ossl_ech_make_enc_info(const unsigned char *encoding,
                           size_t encoding_length,
                           unsigned char *info, size_t *info_len)
{
    WPACKET ipkt = { 0 };

    if (encoding == NULL || info == NULL || info_len == NULL)
        return 0;
    if (!WPACKET_init_static_len(&ipkt, info, *info_len, 0)
        || !WPACKET_memcpy(&ipkt, OSSL_ECH_CONTEXT_STRING,
                           sizeof(OSSL_ECH_CONTEXT_STRING) - 1)
        /*
         * the zero valued octet is required by the spec, section 7.1 so
         * a tiny bit better to add it explicitly rather than depend on
         * the context string being NUL terminated
         */
        || !WPACKET_put_bytes_u8(&ipkt, 0)
        || !WPACKET_memcpy(&ipkt, encoding, encoding_length)
        || !WPACKET_get_total_written(&ipkt, info_len)) {
        WPACKET_cleanup(&ipkt);
        return 0;
    }
    WPACKET_cleanup(&ipkt);
    return 1;
}
