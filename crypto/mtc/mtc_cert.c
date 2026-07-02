/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Parsing of Merkle Tree Certificate wire structures from section 6 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 * See include/crypto/mtc_cert.h.
 *
 * The MTCProof is a TLS-presentation-language structure, decoded here with
 * PACKET (matching the WPACKET used on the generation side).  All returned
 * spans reference the caller's input buffer.
 */

#include <stdint.h>
#include <string.h>

#include "crypto/mtc_cert.h"
#include "internal/packet.h"

int ossl_mtc_proof_parse(const uint8_t *in, size_t in_len,
    OSSL_MTC_PROOF *proof)
{
    PACKET pkt, extensions, inclusion_proof, signatures;
    OSSL_MTC_PROOF parsed;
    size_t count;

    /*
     * MTCProof (section 6.2):
     *   MTCLogEntryExtension extensions<0..2^16-1>;
     *   uint48 start;
     *   uint48 end;
     *   HashValue inclusion_proof<0..2^16-1>;
     *   SubtreeSignature signatures<0..2^24-1>;
     */
    if (!PACKET_buf_init(&pkt, in, in_len)
        || !PACKET_get_length_prefixed_2(&pkt, &extensions)
        || !PACKET_get_net_6(&pkt, &parsed.start)
        || !PACKET_get_net_6(&pkt, &parsed.end)
        || !PACKET_get_length_prefixed_2(&pkt, &inclusion_proof)
        || !PACKET_get_length_prefixed_3(&pkt, &signatures)
        || PACKET_remaining(&pkt) != 0)
        return 0;

    /* The proof is relative to a subtree, which is a non-empty range. */
    if (parsed.start >= parsed.end)
        return 0;

    parsed.extensions = PACKET_data(&extensions);
    parsed.extensions_len = PACKET_remaining(&extensions);
    parsed.inclusion_proof = PACKET_data(&inclusion_proof);
    parsed.inclusion_proof_len = PACKET_remaining(&inclusion_proof);
    parsed.signatures = PACKET_data(&signatures);
    parsed.signatures_len = PACKET_remaining(&signatures);

    /*
     * Section 6.2 requires a parser to reject duplicate or mis-ordered
     * cosigner_id values, so the list is walked here rather than only when
     * the cosignatures are used.
     */
    if (!ossl_mtc_proof_get_cosignatures(&parsed, NULL, 0, &count))
        return 0;

    *proof = parsed;
    return 1;
}

int ossl_mtc_proof_get_cosignatures(const OSSL_MTC_PROOF *proof,
    OSSL_MTC_COSIGNATURE *out, size_t max, size_t *count)
{
    PACKET sigs;
    size_t n = 0;
    const uint8_t *prev_id = NULL;
    size_t prev_id_len = 0;

    if (!PACKET_buf_init(&sigs, proof->signatures, proof->signatures_len))
        return 0;

    while (PACKET_remaining(&sigs) != 0) {
        OSSL_MTC_COSIGNATURE cosig;
        PACKET cosigner_id, signature;

        /*
         * SubtreeSignature (section 6.2):
         *   TrustAnchorID cosigner_id;      (opaque<1..2^8-1>)
         *   opaque signature<0..2^16-1>;
         */
        if (!PACKET_get_length_prefixed_1(&sigs, &cosigner_id)
            || PACKET_remaining(&cosigner_id) == 0
            || !PACKET_get_length_prefixed_2(&sigs, &signature))
            return 0;
        cosig.cosigner_id = PACKET_data(&cosigner_id);
        cosig.cosigner_id_len = PACKET_remaining(&cosigner_id);
        cosig.signature = PACKET_data(&signature);
        cosig.signature_len = PACKET_remaining(&signature);

        /*
         * Entries MUST be unique and strictly ascending by cosigner_id: a
         * shorter id sorts before a longer one, and ids of equal length sort
         * lexicographically (section 6.2).
         */
        if (prev_id != NULL
            && (prev_id_len > cosig.cosigner_id_len
                || (prev_id_len == cosig.cosigner_id_len
                    && memcmp(prev_id, cosig.cosigner_id, prev_id_len) >= 0)))
            return 0;
        prev_id = cosig.cosigner_id;
        prev_id_len = cosig.cosigner_id_len;

        if (out != NULL) {
            if (n >= max)
                return 0;
            out[n] = cosig;
        }
        n++;
    }

    *count = n;
    return 1;
}
