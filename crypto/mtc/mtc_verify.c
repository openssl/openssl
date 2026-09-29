/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Verification of a Merkle Tree Certificate proof, per section 7.2 of
 * https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-06/.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "internal/packet.h"
#include "crypto/ctype.h"
#include <crypto/asn1.h>
#include <crypto/mtc.h>
#include <crypto/mtc_ca.h>
#include <crypto/mtc_cert.h>
#include <crypto/mtc_cosigner.h>
#include <crypto/mtc_verify.h>

/* Experimental id-alg-mtcProof (6.2): 1.3.6.1.4.1.44363.47.0. */
static const uint8_t mtc_proof_alg_oid[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x00
};

/* Experimental trustAnchorID issuer attribute (5.1): 1.3.6.1.4.1.44363.47.3. */
static const uint8_t mtc_taid_attr_oid[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x03
};

/* The universal tag of a RELATIVE-OID, the type of the trustAnchorID value. */
#define MTC_ASN1_RELATIVE_OID 13

/* The prefix of a cosigner_name / log_origin (5.3.1). */
static const char mtc_tai_prefix[] = "oid/1.3.6.1.4.1.";

/* Report whether an ASN1_OBJECT's DER content octets equal oid[0..oid_len). */
static int mtc_obj_is(const ASN1_OBJECT *obj, const uint8_t *oid, size_t oid_len)
{
    return (size_t)OBJ_length(obj) == oid_len
        && memcmp(OBJ_get0_data(obj), oid, oid_len) == 0;
}

/**
 * @brief Encode an ASCII dotted-decimal string as RELATIVE-OID content octets.
 *
 * Each arc is written big-endian base-128 with the continuation bit set on all
 * but its final octet.  Arc values are limited to uint64.
 *
 * @param pkt the packet the encoded octets are appended to
 * @param text the dotted-decimal string
 * @param len the length of text
 * @returns 1 on success, 0 on malformed input or arc overflow.
 */
static int mtc_wpacket_put_reloid_from_text(WPACKET *pkt, const char *text,
    size_t len)
{
    size_t i = 0;

    if (len == 0)
        return 0;
    while (i < len) {
        uint8_t tmp[10];
        uint64_t v = 0;
        size_t n = 0;

        if (!ossl_isdigit(text[i]))
            return 0;
        while (i < len && ossl_isdigit(text[i])) {
            if (v > (UINT64_MAX - 9) / 10)
                return 0; /* arc overflow */
            v = v * 10 + (uint64_t)(text[i] - '0');
            i++;
        }
        do {
            tmp[n++] = (uint8_t)(v & 0x7f);
            v >>= 7;
        } while (v != 0);
        while (n-- > 0)
            if (!WPACKET_put_bytes_u8(pkt, tmp[n] | (n != 0 ? 0x80 : 0)))
                return 0;
        if (i < len) {
            if (text[i] != '.')
                return 0;
            if (++i == len)
                return 0; /* trailing dot */
        }
    }
    return 1;
}

int ossl_mtc_reloid_from_text(const char *text, size_t len, uint8_t **out,
    size_t *out_len)
{
    WPACKET pkt;
    BUF_MEM *buf = NULL;
    size_t written = 0;
    int have_pkt = 0, ok = 0;

    if ((buf = BUF_MEM_new()) == NULL || !WPACKET_init(&pkt, buf))
        goto err;
    have_pkt = 1;
    if (!mtc_wpacket_put_reloid_from_text(&pkt, text, len)
        || !WPACKET_get_total_written(&pkt, &written)
        || !WPACKET_finish(&pkt))
        goto err;
    have_pkt = 0;
    if ((*out = OPENSSL_memdup(buf->data, written)) == NULL)
        goto err;
    *out_len = written;
    ok = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    BUF_MEM_free(buf);
    return ok;
}

/**
 * @brief Decode RELATIVE-OID content octets to a dotted-decimal string.
 *
 * Arc values are limited to uint64.
 *
 * @param in the packet holding the RELATIVE-OID content octets
 * @param out set to a newly allocated NUL-terminated dotted-decimal string
 * @returns 1 on success, 0 on malformed input or arc overflow.
 */
static int mtc_reloid_to_text(PACKET *in, char **out)
{
    WPACKET pkt;
    BUF_MEM *buf = NULL;
    int first = 1, have_pkt = 0, ok = 0;

    if (PACKET_remaining(in) == 0)
        return 0;
    if ((buf = BUF_MEM_new()) == NULL || !WPACKET_init(&pkt, buf))
        goto err;
    have_pkt = 1;
    while (PACKET_remaining(in) > 0) {
        char dec[21]; /* uint64 is at most 20 digits */
        uint64_t v = 0;
        unsigned int c;
        int dec_len;

        for (;;) {
            if (!PACKET_get_1(in, &c))
                goto err; /* truncated arc */
            if (v > (UINT64_MAX >> 7))
                goto err; /* arc overflow */
            v = (v << 7) | (c & 0x7f);
            if ((c & 0x80) == 0)
                break;
        }
        if (!first && !WPACKET_put_bytes_u8(&pkt, '.'))
            goto err;
        first = 0;
        dec_len = snprintf(dec, sizeof(dec), "%ju", (uintmax_t)v);
        if (dec_len < 0 || (size_t)dec_len >= sizeof(dec)
            || !WPACKET_memcpy(&pkt, dec, (size_t)dec_len))
            goto err;
    }
    if (!WPACKET_put_bytes_u8(&pkt, '\0') || !WPACKET_finish(&pkt))
        goto err;
    have_pkt = 0;
    *out = buf->data;
    buf->data = NULL;
    ok = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    BUF_MEM_free(buf);
    return ok;
}

/**
 * @brief Report whether id is a trust anchor ID in binary form: the contents of
 *        a RELATIVE-OID of 1 to 255 bytes, each component minimally encoded in
 *        base 128 (section 4 of
 *        https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/).
 */
static int mtc_reloid_is_valid(const uint8_t *id, size_t id_len)
{
    size_t i = 0;

    if (id_len == 0 || id_len > 255)
        return 0;
    while (i < id_len) {
        /* A component may not start with a zero continuation byte. */
        if (id[i] == 0x80)
            return 0;
        while ((id[i] & 0x80) != 0)
            if (++i == id_len)
                return 0; /* truncated */
        i++;
    }
    return 1;
}

int ossl_mtc_ca_id_from_name(const X509_NAME *name, uint8_t **out,
    size_t *out_len)
{
    const X509_NAME_ENTRY *ne;
    const ASN1_STRING *val;
    const uint8_t *data;
    size_t len;

    if (X509_NAME_entry_count(name) != 1)
        return 0;
    ne = X509_NAME_get_entry(name, 0);
    val = X509_NAME_ENTRY_get_data(ne);
    if (!(mtc_obj_is(X509_NAME_ENTRY_get_object(ne), mtc_taid_attr_oid,
              sizeof(mtc_taid_attr_oid))
            || OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne))
                == NID_id_rdna_trustAnchorID)
        || ASN1_STRING_type(val) != MTC_ASN1_RELATIVE_OID)
        return 0;
    data = ASN1_STRING_get0_data(val);
    len = (size_t)ASN1_STRING_get_length(val);
    if (!mtc_reloid_is_valid(data, len)
        || (*out = OPENSSL_memdup(data, len)) == NULL)
        return 0;
    *out_len = len;
    return 1;
}

/**
 * @brief Advance *p past one DER TLV.
 *
 * @param p pointer to the parse cursor, advanced past the TLV on success
 * @param end one past the last byte available
 * @param field set to the start of the TLV
 * @param field_len set to the TLV length, including its header
 * @param tag set to the TLV tag
 * @returns 1 on success, 0 on malformed input.
 */
static int mtc_next_field(const uint8_t **p, const uint8_t *end,
    const uint8_t **field, size_t *field_len, int *tag)
{
    const uint8_t *start = *p, *content;
    long len;
    int xclass;

    if ((ASN1_get_object(p, &len, tag, &xclass, (long)(end - start)) & 0x80)
        != 0)
        return 0;
    content = *p;
    *p = content + len;
    *field = start;
    *field_len = (size_t)(content - start) + (size_t)len;
    return 1;
}

/**
 * @brief Compute entry_hash for a tbs_cert_entry in a single pass (section 7.2).
 *
 * The entry is the tbs_cert_entry (section 5.2.1), hashed as a Merkle tree
 * leaf: entry_hash = MTH(entry) = HASH(0x00 || entry).  serialNumber and
 * signature are not part of the entry -- the serial encodes tree position and
 * the signature is the proof itself -- so only version, issuer, validity and
 * subject are copied.
 *
 * @param ca the issuing CA, providing the hash algorithm
 * @param tbs the DER-encoded TBSCertificate whose log entry is reconstructed
 * @param tbs_len the length of tbs
 * @param proof the parsed MTCProof, providing the entry extensions
 * @param out buffer receiving the entry hash
 * @param out_len set to the length of the entry hash
 * @returns 1 on success, 0 on error.
 */
static int mtc_entry_hash(const OSSL_MTC_CA *ca, const uint8_t *tbs,
    size_t tbs_len, const OSSL_MTC_PROOF *proof, uint8_t *out, size_t *out_len)
{
    const EVP_MD *md = ossl_mtc_ca_hash(ca);
    EVP_MD_CTX *ctx = NULL;
    uint8_t spki_hash[EVP_MAX_MD_SIZE];
    const uint8_t *p, *cend, *sp;
    const uint8_t *version = NULL, *issuer, *validity, *subject, *spki;
    const uint8_t *spki_alg, *rest, *scratch;
    size_t version_len = 0, issuer_len, validity_len, subject_len, spki_len;
    size_t spki_alg_len, rest_len, scratch_len, hlen;
    long len;
    int tag, xclass, ok = 0;
    unsigned int mdlen;

    if (md == NULL || (hlen = (size_t)EVP_MD_get_size(md)) > 127)
        return 0;

    /* Enter the TBSCertificate SEQUENCE. */
    p = tbs;
    if ((ASN1_get_object(&p, &len, &tag, &xclass, (long)tbs_len) & 0x80) != 0
        || tag != V_ASN1_SEQUENCE)
        goto err;
    cend = p + len;

    /* version [0] EXPLICIT is optional (absent for v1). */
    if (p < cend && (*p & 0xa0) == 0xa0
        && !mtc_next_field(&p, cend, &version, &version_len, &tag))
        goto err;
    /* serialNumber and signature are skipped (see note above). */
    if (!mtc_next_field(&p, cend, &scratch, &scratch_len, &tag)
        || !mtc_next_field(&p, cend, &scratch, &scratch_len, &tag)
        || !mtc_next_field(&p, cend, &issuer, &issuer_len, &tag)
        || !mtc_next_field(&p, cend, &validity, &validity_len, &tag)
        || !mtc_next_field(&p, cend, &subject, &subject_len, &tag)
        || !mtc_next_field(&p, cend, &spki, &spki_len, &tag))
        goto err;
    rest = p;
    rest_len = (size_t)(cend - p);

    /* The SPKI algorithm is the first element of the SPKI SEQUENCE. */
    sp = spki;
    if ((ASN1_get_object(&sp, &len, &tag, &xclass, (long)spki_len) & 0x80) != 0
        || !mtc_next_field(&sp, spki + spki_len, &spki_alg, &spki_alg_len, &tag))
        goto err;
    if (!EVP_Digest(spki, spki_len, spki_hash, &mdlen, md, NULL))
        goto err;

    if ((ctx = EVP_MD_CTX_new()) == NULL || !EVP_DigestInit_ex(ctx, md, NULL))
        goto err;
    if (!EVP_DigestUpdate(ctx, "\x00", 1)) /* leaf domain separator */
        goto err;
    {
        uint8_t el[2] = {
            (uint8_t)(proof->extensions_len >> 8),
            (uint8_t)proof->extensions_len
        };

        if (!EVP_DigestUpdate(ctx, el, sizeof(el))
            || !EVP_DigestUpdate(ctx, proof->extensions, proof->extensions_len))
            goto err;
    }
    if (!EVP_DigestUpdate(ctx, "\x00\x01", 2)) /* tbs_cert_entry type */
        goto err;
    if (version != NULL && !EVP_DigestUpdate(ctx, version, version_len))
        goto err;
    if (!EVP_DigestUpdate(ctx, issuer, issuer_len)
        || !EVP_DigestUpdate(ctx, validity, validity_len)
        || !EVP_DigestUpdate(ctx, subject, subject_len)
        || !EVP_DigestUpdate(ctx, spki_alg, spki_alg_len))
        goto err;
    {
        uint8_t oh[2] = { 0x04, (uint8_t)hlen };

        if (!EVP_DigestUpdate(ctx, oh, sizeof(oh))
            || !EVP_DigestUpdate(ctx, spki_hash, hlen)
            || !EVP_DigestUpdate(ctx, rest, rest_len)
            || !EVP_DigestFinal_ex(ctx, out, &mdlen))
            goto err;
    }
    *out_len = mdlen;
    ok = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/*
 * Extract the serial (a uint64) from a DER-encoded TBSCertificate: enter the
 * TBSCertificate SEQUENCE, skip the optional version [0], and read the
 * serialNumber INTEGER.  Fails if it is negative or exceeds 2^64-1.
 */
static int mtc_serial_from_tbs(const uint8_t *tbs, size_t tbs_len, uint64_t *out)
{
    const uint8_t *p = tbs, *cend, *field, *scratch;
    ASN1_INTEGER *serial = NULL;
    size_t field_len, scratch_len;
    long len;
    int tag, xclass, ok = 0;

    if ((ASN1_get_object(&p, &len, &tag, &xclass, (long)tbs_len) & 0x80) != 0
        || tag != V_ASN1_SEQUENCE)
        return 0;
    cend = p + len;
    /* version [0] EXPLICIT is optional (absent for v1). */
    if (p < cend && (*p & 0xa0) == 0xa0
        && !mtc_next_field(&p, cend, &scratch, &scratch_len, &tag))
        return 0;
    /* serialNumber INTEGER. */
    if (!mtc_next_field(&p, cend, &field, &field_len, &tag)
        || tag != V_ASN1_INTEGER)
        return 0;
    if (d2i_ASN1_INTEGER(&serial, &field, (long)field_len) != NULL)
        ok = ASN1_INTEGER_get_uint64(out, serial);
    ASN1_INTEGER_free(serial);
    return ok;
}

/**
 * @brief Build the CosignedMessage a cosigner signs (section 5.3.1).
 *
 * The message is label, cosigner_name, timestamp (0), log_origin, start, end,
 * subtree_hash.  cosigner_name is the trust-anchor prefix followed by the
 * cosigner ID as dotted text; log_origin uses log_id_text (the dotted text of
 * ca_id ++ 0 ++ log_number).
 *
 * @param cosigner_id the cosigner ID as RELATIVE-OID content octets
 * @param cosigner_id_len the length of cosigner_id
 * @param log_id_text the log ID as a dotted-decimal string
 * @param start the subtree start
 * @param end the subtree end
 * @param subtree_hash the subtree hash
 * @param subtree_hash_len the length of subtree_hash
 * @param out set to the newly allocated message
 * @param out_len set to the length of the message
 * @returns 1 on success, 0 on error.
 */
static int mtc_build_cosigned_message(const uint8_t *cosigner_id,
    size_t cosigner_id_len, const char *log_id_text, uint64_t start,
    uint64_t end, const uint8_t *subtree_hash, size_t subtree_hash_len,
    uint8_t **out, size_t *out_len)
{
    static const uint8_t label[12] = "subtree/v1\n"; /* trailing \0 -> 12 */
    WPACKET pkt;
    PACKET idp;
    BUF_MEM *buf = NULL;
    char *cosigner_text = NULL;
    int have_pkt = 0, ok = 0;

    if (!PACKET_buf_init(&idp, cosigner_id, cosigner_id_len)
        || !mtc_reloid_to_text(&idp, &cosigner_text))
        goto err;
    if ((buf = BUF_MEM_new()) == NULL || !WPACKET_init(&pkt, buf))
        goto err;
    have_pkt = 1;
    if (!WPACKET_memcpy(&pkt, label, sizeof(label))
        || !WPACKET_start_sub_packet_u8(&pkt)
        || !WPACKET_memcpy(&pkt, mtc_tai_prefix, sizeof(mtc_tai_prefix) - 1)
        || !WPACKET_memcpy(&pkt, cosigner_text, strlen(cosigner_text))
        || !WPACKET_close(&pkt)
        || !WPACKET_put_bytes_u64(&pkt, 0) /* timestamp */
        || !WPACKET_start_sub_packet_u8(&pkt)
        || !WPACKET_memcpy(&pkt, mtc_tai_prefix, sizeof(mtc_tai_prefix) - 1)
        || !WPACKET_memcpy(&pkt, log_id_text, strlen(log_id_text))
        || !WPACKET_close(&pkt)
        || !WPACKET_put_bytes_u64(&pkt, start)
        || !WPACKET_put_bytes_u64(&pkt, end)
        || !WPACKET_memcpy(&pkt, subtree_hash, subtree_hash_len)
        || !WPACKET_get_total_written(&pkt, out_len)
        || !WPACKET_finish(&pkt))
        goto err;
    have_pkt = 0;
    *out = (uint8_t *)buf->data;
    buf->data = NULL;
    ok = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    BUF_MEM_free(buf);
    OPENSSL_free(cosigner_text);
    return ok;
}

/**
 * @brief Verify one cosignature over a subtree (section 5.3.1).
 *
 * @param pkey the cosigner's public key
 * @param sig the cosignature, giving the cosigner ID and signature value
 * @param log_id_text the log ID as a dotted-decimal string
 * @param start the subtree start
 * @param end the subtree end
 * @param subtree_hash the subtree hash
 * @param subtree_hash_len the length of subtree_hash
 * @returns 1 if the signature verifies, 0 otherwise.
 */
static int mtc_verify_cosignature(EVP_PKEY *pkey,
    const OSSL_MTC_COSIGNATURE *sig, const char *log_id_text, uint64_t start,
    uint64_t end, const uint8_t *subtree_hash, size_t subtree_hash_len)
{
    EVP_MD_CTX *mdctx = NULL;
    uint8_t *msg = NULL;
    size_t msg_len;
    int ok = 0;

    if (!mtc_build_cosigned_message(sig->cosigner_id, sig->cosigner_id_len,
            log_id_text, start, end, subtree_hash, subtree_hash_len, &msg,
            &msg_len))
        goto err;
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        goto err;
    /* ML-DSA and friends verify directly (no pre-hash): md == NULL. */
    ok = EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL)
        && EVP_DigestVerify(mdctx, sig->signature, sig->signature_len, msg,
               msg_len)
            == 1;
err:
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(msg);
    return ok;
}

/**
 * @brief Check a subtree's cosignatures against the cosigner policy (section
 * 7.2 step 12, 7.3).
 *
 * The policy is a valid signature from the CA cosigner (authenticity) plus
 * valid signatures from at least quorum of the trusted cosigners
 * (transparency).  A cosignature whose cosigner is neither the CA cosigner nor
 * a trusted cosigner is ignored (7.2 step 12); so is one from a trusted
 * cosigner that does not verify, which then does not count toward the quorum.
 * Each cosigner appears at most once in a well-formed list (6.2), so a
 * cosigner counts at most once.
 *
 * @param ca the issuing CA, providing the CA cosigner key and ID
 * @param lookup resolves a cosigner ID to a trusted cosigner; NULL when none
 * @param lookup_arg passed through to lookup
 * @param quorum the number of trusted cosigners that must have signed
 * @param log_number the issuance log number
 * @param proof the parsed MTCProof, providing the cosignatures
 * @param start the subtree start
 * @param end the subtree end
 * @param subtree_hash the evaluated subtree hash
 * @param subtree_hash_len the length of subtree_hash
 * @param error set to X509_V_ERR_MTC_BAD_PROOF for a malformed cosignature list,
 *        X509_V_ERR_MTC_NOT_TRUSTED without a valid CA cosignature, or
 *        X509_V_ERR_MTC_COSIGNER_QUORUM with too few trusted cosignatures
 * @returns 1 if the policy is met, 0 otherwise.
 */
static int mtc_verify_cosignatures(const OSSL_MTC_CA *ca,
    ossl_mtc_cosigner_lookup_fn lookup, void *lookup_arg, size_t quorum,
    uint16_t log_number, const OSSL_MTC_PROOF *proof, uint64_t start,
    uint64_t end, const uint8_t *subtree_hash, size_t subtree_hash_len,
    int *error)
{
    OSSL_MTC_COSIGNATURE *sigs = NULL;
    const uint8_t *ca_id;
    char *ca_id_text = NULL, *log_id_text = NULL;
    PACKET idp;
    size_t count = 0, ca_id_len, i, need, additional = 0;
    int ca_ok = 0, ok = 0;

    *error = X509_V_ERR_MTC_NOT_TRUSTED;
    ca_id = ossl_mtc_ca_id(ca, &ca_id_len);

    /* log_id_text = to_text(ca_id) ++ ".0." ++ log_number. */
    if (!PACKET_buf_init(&idp, ca_id, ca_id_len)
        || !mtc_reloid_to_text(&idp, &ca_id_text))
        goto err;
    need = strlen(ca_id_text) + 3 + 5 + 1; /* ".0." + up to 5 digits + NUL */
    if ((log_id_text = OPENSSL_malloc(need)) == NULL)
        goto err;
    snprintf(log_id_text, need, "%s.0.%u", ca_id_text,
        (unsigned int)log_number);

    /* A malformed or misordered cosignature list is a defect of the proof. */
    if (!ossl_mtc_proof_get_cosignatures(proof, NULL, 0, &count)) {
        *error = X509_V_ERR_MTC_BAD_PROOF;
        goto err;
    }
    if (count == 0)
        goto err; /* no cosignatures: not trusted */
    if ((sigs = OPENSSL_malloc_array(count, sizeof(*sigs))) == NULL)
        goto err;
    if (!ossl_mtc_proof_get_cosignatures(proof, sigs, count, &count)) {
        *error = X509_V_ERR_MTC_BAD_PROOF;
        goto err;
    }

    for (i = 0; i < count && !(ca_ok && additional >= quorum); i++) {
        const OSSL_MTC_COSIGNER *cosigner;
        EVP_PKEY *pkey;
        int is_ca;

        /* The CA cosigner is identified by ca_id (5.4). */
        is_ca = sigs[i].cosigner_id_len == ca_id_len
            && memcmp(sigs[i].cosigner_id, ca_id, ca_id_len) == 0;
        if (is_ca) {
            pkey = ossl_mtc_ca_cosigner_pkey(ca);
        } else {
            cosigner = lookup == NULL ? NULL
                                      : lookup(sigs[i].cosigner_id,
                                            sigs[i].cosigner_id_len, lookup_arg);
            if (cosigner == NULL)
                continue; /* unrecognised cosigner - ignore */
            pkey = ossl_mtc_cosigner_pkey(cosigner);
        }
        if (!mtc_verify_cosignature(pkey, &sigs[i], log_id_text, start, end,
                subtree_hash, subtree_hash_len))
            continue;
        if (is_ca)
            ca_ok = 1;
        else
            additional++;
    }
    if (!ca_ok)
        goto err;
    if (additional < quorum) {
        *error = X509_V_ERR_MTC_COSIGNER_QUORUM;
        goto err;
    }
    ok = 1;
err:
    OPENSSL_free(sigs);
    OPENSSL_free(ca_id_text);
    OPENSSL_free(log_id_text);
    return ok;
}

int ossl_mtc_is_mtc(const X509 *cert)
{
    const ASN1_BIT_STRING *sig;
    const X509_ALGOR *alg;

    if (cert == NULL)
        return 0;
    X509_get0_signature(&sig, &alg, cert);
    return mtc_obj_is(alg->algorithm, mtc_proof_alg_oid,
               sizeof(mtc_proof_alg_oid))
        || OBJ_obj2nid(alg->algorithm) == NID_id_alg_mtcProof;
}

OSSL_MTC_CA *ossl_mtc_ca_for_cert(const STACK_OF(OSSL_MTC_CA) *cas,
    const X509 *cert, int *error)
{
    uint8_t *ca_id = NULL;
    size_t ca_id_len;
    OSSL_MTC_CA *ca = NULL;

    /* The issuing CA is named by the trust anchor ID in the issuer (5.1). */
    if (!ossl_mtc_ca_id_from_name(X509_get_issuer_name(cert), &ca_id,
            &ca_id_len)) {
        *error = X509_V_ERR_MTC_NOT_MTC;
        return NULL;
    }
    if ((ca = ossl_mtc_ca_stack_lookup(cas, ca_id, ca_id_len)) == NULL)
        *error = X509_V_ERR_MTC_UNTRUSTED_CA;
    OPENSSL_free(ca_id);
    return ca;
}

int ossl_mtc_verify(OSSL_MTC_CA *ca, ossl_mtc_cosigner_lookup_fn lookup,
    void *lookup_arg, size_t quorum, const uint8_t *tbs, size_t tbs_len,
    const uint8_t *proof, size_t proof_len, int *error)
{
    const EVP_MD *md = ossl_mtc_ca_hash(ca);
    uint8_t entry_hash[EVP_MAX_MD_SIZE];
    uint8_t subtree_root[EVP_MAX_MD_SIZE];
    OSSL_MTC_PROOF parsed;
    OSSL_MTC_SUBTREE subtree;
    uint64_t serial, index;
    size_t entry_hash_len = 0;
    uint16_t log_number;
    int found = 0, err = X509_V_ERR_MTC_BAD_PROOF, ret = 0;

    /* Step 2: decode the MTCProof.  The caller supplies whole-octet proof. */
    if (!ossl_mtc_proof_parse(proof, proof_len, &parsed))
        goto err;
    /* Steps 3, 5: serial -> index / log_number. */
    if (!mtc_serial_from_tbs(tbs, tbs_len, &serial))
        goto err;
    index = serial & ((UINT64_C(1) << 48) - 1);
    log_number = (uint16_t)(serial >> 48);
    if (log_number == 0)
        goto err;
    /* Step 4 / 7.5: revocation. */
    if (ossl_mtc_ca_serial_is_revoked(ca, serial)) {
        err = X509_V_ERR_MTC_REVOKED;
        goto err;
    }
    /* Steps 7-9: reconstruct and hash the entry. */
    if (!mtc_entry_hash(ca, tbs, tbs_len, &parsed, entry_hash, &entry_hash_len))
        goto err;
    /* Step 10: evaluate the inclusion proof to the subtree hash. */
    subtree.start = parsed.start;
    subtree.end = parsed.end;
    if (!ossl_mtc_eval_subtree_inclusion_proof(md, parsed.inclusion_proof,
            parsed.inclusion_proof_len, index, entry_hash, subtree,
            subtree_root)) {
        err = X509_V_ERR_MTC_INCLUSION_FAILED;
        goto err;
    }
    /* Step 11 (trusted subtree) or step 12 (cosignatures). */
    if (!ossl_mtc_ca_trusted_subtree_matches(ca, log_number, parsed.start,
            parsed.end, subtree_root, entry_hash_len, &found)) {
        if (found) {
            err = X509_V_ERR_MTC_NOT_TRUSTED;
            goto err;
        }
        if (!mtc_verify_cosignatures(ca, lookup, lookup_arg, quorum,
                log_number, &parsed, parsed.start, parsed.end, subtree_root,
                entry_hash_len, &err))
            goto err;
    }
    err = X509_V_OK;
    ret = 1;
err:
    *error = err;
    return ret;
}
