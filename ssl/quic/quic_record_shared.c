#include "quic_record_shared.h"
#include "internal/quic_record_util.h"
#include "internal/common.h"
#include "../ssl_local.h"

/* Constants used for key derivation in QUIC v1. */
static const unsigned char quic_v1_iv_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76 /* "quic iv" */
};
static const unsigned char quic_v1_key_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79 /* "quic key" */
};
static const unsigned char quic_v1_hp_label[] = {
    0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70 /* "quic hp" */
};

OSSL_QRL_ENC_LEVEL *ossl_qrl_enc_level_set_get(OSSL_QRL_ENC_LEVEL_SET *els,
                                               uint32_t enc_level,
                                               int require_valid)
{
    OSSL_QRL_ENC_LEVEL *el;

    if (!ossl_assert(enc_level < QUIC_ENC_LEVEL_NUM))
        return NULL;

    el = &els->el[enc_level];

    if (require_valid && (el->cctx == NULL || el->discarded))
        return NULL;

    return el;
}

int ossl_qrl_enc_level_set_have_el(OSSL_QRL_ENC_LEVEL_SET *els,
                                  uint32_t enc_level)
{
    OSSL_QRL_ENC_LEVEL *el = ossl_qrl_enc_level_set_get(els, enc_level, 0);

    if (el == NULL)
        return 0;
    if (el->cctx != NULL)
        return 1;
    if (el->discarded)
        return -1;
    return 0;
}

/*
 * Sets up cryptographic state for a given encryption level and direction by
 * deriving "quic iv", "quic key" and "quic hp" values from a given secret.
 *
 * md is a hash function used for key derivation. If it is NULL, this function
 * fetches the necessary hash function itself. If it is non-NULL, this function
 * can reuse the caller's reference to a suitable EVP_MD; the EVP_MD provided
 * must match the suite.
 *
 * On success where md is non-NULL, takes ownership of the caller's reference to
 * md.
 */
int ossl_qrl_enc_level_set_provide_secret(OSSL_QRL_ENC_LEVEL_SET *els,
                                          OSSL_LIB_CTX *libctx,
                                          const char *propq,
                                          uint32_t enc_level,
                                          uint32_t suite_id,
                                          EVP_MD *md,
                                          const unsigned char *secret,
                                          size_t secret_len)
{
    OSSL_QRL_ENC_LEVEL *el = ossl_qrl_enc_level_set_get(els, enc_level, 0);
    unsigned char key[EVP_MAX_KEY_LENGTH], hpr_key[EVP_MAX_KEY_LENGTH];
    size_t key_len = 0, hpr_key_len = 0, iv_len = 0;
    const char *cipher_name = NULL, *md_name = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    int own_md = 0, have_hpr = 0;

    if (el == NULL || el->discarded)
        /* Should not be trying to reinitialise an EL which was discarded. */
        return 0;

    cipher_name = ossl_qrl_get_suite_cipher_name(suite_id);
    iv_len      = ossl_qrl_get_suite_cipher_iv_len(suite_id);
    key_len     = ossl_qrl_get_suite_cipher_key_len(suite_id);
    hpr_key_len = ossl_qrl_get_suite_hdr_prot_key_len(suite_id);
    if (cipher_name == NULL)
        return 0;

    if (secret_len != ossl_qrl_get_suite_secret_len(suite_id))
        return 0;

    if (md == NULL) {
        md_name = ossl_qrl_get_suite_md_name(suite_id);

        if ((md = EVP_MD_fetch(libctx, md_name, propq)) == NULL)
            return 0;

        own_md = 1;
    }

    /* Derive "quic iv" key. */
    if (!tls13_hkdf_expand_ex(libctx, propq,
                              md,
                              secret,
                              quic_v1_iv_label,
                              sizeof(quic_v1_iv_label),
                              NULL, 0,
                              el->iv, iv_len, 0))
        goto err;

    /* Derive "quic key" key. */
    if (!tls13_hkdf_expand_ex(libctx, propq,
                              md,
                              secret,
                              quic_v1_key_label,
                              sizeof(quic_v1_key_label),
                              NULL, 0,
                              key, key_len, 0))
        goto err;

    /* Derive "quic hp" key. */
    if (!tls13_hkdf_expand_ex(libctx, propq,
                              md,
                              secret,
                              quic_v1_hp_label,
                              sizeof(quic_v1_hp_label),
                              NULL, 0,
                              hpr_key, hpr_key_len, 0))
        goto err;

    /* Free any old context which is using old keying material. */
    if (el->cctx != NULL) {
        ossl_quic_hdr_protector_destroy(&el->hpr);
        EVP_CIPHER_CTX_free(el->cctx);
        el->cctx = NULL;
    }

    /* Setup header protection context. */
    if (!ossl_quic_hdr_protector_init(&el->hpr,
                                      libctx,
                                      propq,
                                      ossl_qrl_get_suite_hdr_prot_cipher_id(suite_id),
                                      hpr_key,
                                      hpr_key_len))
        goto err;

    have_hpr = 1;

    /* Create and initialise cipher context. */
    if ((cipher = EVP_CIPHER_fetch(libctx, cipher_name, propq)) == NULL)
        goto err;

    if (!ossl_assert(iv_len  == (size_t)EVP_CIPHER_get_iv_length(cipher))
        || !ossl_assert(key_len == (size_t)EVP_CIPHER_get_key_length(cipher)))
        goto err;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* IV will be changed on RX/TX so we don't need to use a real value here. */
    if (!EVP_CipherInit_ex(cctx, cipher, NULL, key, el->iv, 0))
        goto err;

    el->suite_id    = suite_id;
    el->cctx        = cctx;
    el->md          = md;
    el->tag_len     = ossl_qrl_get_suite_cipher_tag_len(suite_id);
    el->op_count    = 0;

    /* Zeroize intermediate keys. */
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(hpr_key, sizeof(hpr_key));
    EVP_CIPHER_free(cipher);
    return 1;

err:
    if (have_hpr)
        ossl_quic_hdr_protector_destroy(&el->hpr);
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (own_md)
        EVP_MD_free(md);
    return 0;
}

/* Drops keying material for a given encryption level. */
void ossl_qrl_enc_level_set_discard(OSSL_QRL_ENC_LEVEL_SET *els,
                                    uint32_t enc_level, int is_final)
{
    OSSL_QRL_ENC_LEVEL *el = ossl_qrl_enc_level_set_get(els, enc_level, 0);

    if (el == NULL || el->discarded)
        return;

    if (el->cctx != NULL) {
        ossl_quic_hdr_protector_destroy(&el->hpr);

        EVP_CIPHER_CTX_free(el->cctx);
        el->cctx    = NULL;

        EVP_MD_free(el->md);
        el->md      = NULL;
    }

    /* Zeroise IV. */
    OPENSSL_cleanse(el->iv, sizeof(el->iv));

    if (is_final)
        el->discarded = 1;
}
