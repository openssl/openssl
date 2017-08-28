/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef __VMS
# pragma names save
# pragma names as_is,shortened
#endif

#include "../ssl/ssl_locl.h"
#include "../ssl/record/record_locl.h"

#ifdef __VMS
# pragma names restore
#endif

#include "internal/nelem.h"
#include "testutil.h"

/*
 * Based on the test vectors provided in:
 * https://www.ietf.org/id/draft-thomson-tls-tls13-vectors-01.txt
 */

typedef struct {
    /*
     * We split these into 3 chunks in order to work around the 509 character
     * limit that the standard specifies for string literals
     */
    const char *plaintext[3];
    const char *ciphertext[3];
    const char *key;
    const char *iv;
    const char *seq;
} RECORD_DATA;

static RECORD_DATA refdata[] = {
    {
        /*
         * Server: EncryptedExtensions, Certificate, CertificateVerify and
         *         Finished
         */
        {
            "0800001e001c000a00140012001d001700180019010001010102010301040000"
            "00000b0001b9000001b50001b0308201ac30820115a003020102020102300d06"
            "092a864886f70d01010b0500300e310c300a06035504031303727361301e170d"
            "3136303733303031323335395a170d3236303733303031323335395a300e310c"
            "300a0603550403130372736130819f300d06092a864886f70d01010105000381"
            "8d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bd"
            "b826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced",
            "43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846"
            "748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6"
            "d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b06"
            "03551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2"
            "a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8"
            "f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2db"
            "f102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b",
            "84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f"
            "00008408040080134e22eac57321ab47db6b38b2992cec2dd79bd065a034a9af"
            "6b9e3d03475e4309e6523ccdf055453fb480804a3a7e996229eb28e734f6702b"
            "ea2b32149899ac043a4b44468197868da77147ce9f73c0543c4e3fc33e306cac"
            "8506faa80a959c5f1edccbee76eda1ad7a4fa440de35dcb87e82ec94e8725355"
            "ce7507713a609e140000207304bb73321f01b71dd94622fae98daf634490d220"
            "e4c8f3ffa2559911a56e5116"
        },
        {
            "40ae92071a3a548b26af31e116dfc0ba4549210b17e70da16cfbda9ccdad844d"
            "94264a9ae65b786b3eaf0de20aa89c6babb448b6f32d07f233584296eefe1931"
            "6bd979659472ee8567cb01d70b0366cddb3c60eb9e1d789a3691dc254c14de73"
            "f4f20100504544ce184d44547e124b1f18303b4859f8f2e2b04423d23a866b43"
            "866374d54af41649d25f4a3ec2cecd5d4e6de1b24953440b46fbb74c1dbec6fb"
            "b1f16bc21d4aa0e1e936a49c07127e19719bc652a2f0b7f8df4a150b2b3c9e9e"
            "353d6ed101970ddc611abad0632c6793f9379c9d06846c311fcbd6f85edd569b",
            "8782c4c5f62294c4611ae60f83230a53aa95e3bcbed204f19a7a1db83c0fbfec"
            "1edd2c17498fa7b5aa2321248a92592d891e4947df6bcef52f4481797d032ad3"
            "32046a384abece6454b3e356d7249bfa5696793c7f7d3048dc87fa7409a46918"
            "87caaf0982c402b902d699f62dc4d5e153f13e8589e4a6206c7f74eb26ddefbb"
            "92309fb753decfea972dec7de02eda9c6d26acd7be53a8aa20f1a93f082ae6eb"
            "927a6a1b7bd9153551aedfaf94f61dd4cb9355ad7ab09f615d9f92c21712c732"
            "c0e7e117797f38cbdc184e3a65e15a89f46cb3624f5fdb8dbbd275f2c8492f8d",
            "95bdbd8d1dc1b9f21107bd433acbbac247239c073a2f24a4a9f8074f325f277d"
            "579b6bff0269ff19aed3809a9ddd21dd29c1363c9dc44812dd41d2111f9c2e83"
            "42046c14133b853262676f15e94de18660e04ae5c0c661ea43559af5842e161c"
            "83dd29f64508b2ec3e635a2134fc0e1a39d3ecb51dcddfcf8382c88ffe2a7378"
            "42ad1de7fe505b6c4d1673870f6fc2a0f2f7972acaee368a1599d64ba18798f1"
            "0333f9779bd5b05f9b084d03dab2f3d80c2eb74ec70c9866ea31c18b491cd597"
            "aae3e941205fcc38a3a10ce8c0269f02ccc9c51278e25f1a0f0731a9"
        },
        "d2dd45f87ad87801a85ac38187f9023b",
        "f0a14f808692cef87a3daf70",
        "0000000000000000"
    },
    {
        /* Client: Finished */
        {
            "1400002078367856d3c8cc4e0a95eb98906ca7a48bd3cc7029f48bd4ae0dc91a"
            "b903ca8916","",""
        },
        {
            "fa15e92daa21cd05d8f9c3152a61748d9aaf049da559718e583f95aacecad657"
            "b52a6562da09a5819e864d86ac2989360a1eb22795","",""
        },
        "40e1201d75d419627f04c88530a15c9d",
        "a0f073f3b35e18f96969696b",
        "0000000000000000"
    },
    {
        /* Server: NewSessionTicket */
        {
            "040000a60002a3004abe594b00924e535321cadc96238da09caf9b02fecafdd6"
            "5e3e418f03e43772cf512ed8066100503b1c08abbbf298a9d138ce821dd12fe1"
            "710e2137cd12e6a85cd3fd7f73706e7f5dddefb87c1ef83824638464099c9d13"
            "63e3c64ed2075c16b8ccd8e524a6bbd7a6a6e34ea1579782b15bbe7dfed5c0c0"
            "d980fb330f9d8ab252ffe7be1277d418b6828ead4dae3b30d448442417ef76af"
            "0008002e00040002000016","",""
        },
        {
            "45a6626fa13b66ce2c5b3ef807e299a118296f26a2dd9ec7487a0673e2460d4c"
            "79f40087dcd014c59c51379c90d26b4e4f9bb2b78f5b6761594f013ff3e4c78d"
            "836905229eac811c4ef8b2faa89867e9ffc586f7f03c216591aa5e620eac3c62"
            "dfe60f846036bd7ecc4464b584af184e9644e94ee1d7834dba408a51cbe42480"
            "04796ed9c558e0f5f96115a6f6ba487e17d16a2e20a3d3a650a9a070fb53d9da"
            "82864b5621d77650bd0c7947e9889917b53d0515627c72b0ded521","",""
        },
        "3381f6b3f94500f16226de440193e858",
        "4f1d73cc1d465eb30021c41f",
        "0000000000000000"
    },
    {
        /* Client: Application Data */
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303117","",""
        },
        {
            "e306178ad97f74bb64f35eaf3c39846b83aef8472cbc9046749b81a949dfb12c"
            "fbc65cbabd20ade92c1f944605892ceeb12fdee8a927bce77c83036ac5a794a8"
            "f54a69","",""
        },
        "eb23a804904b80ba4fe8399e09b1ce42",
        "efa8c50c06b9c9b8c483e174",
        "0000000000000000"
    },
    {
        /* Server: Application Data */
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303117","",""
        },
        {
            "467d99a807dbf778e6ffd8be52456c70665f890811ef2f3c495d5bbe983feeda"
            "b0c251dde596bc7e2b135909ec9f9166fb0152e8c16a84e4b1039256467f9538"
            "be4463","",""
        },
        "3381f6b3f94500f16226de440193e858",
        "4f1d73cc1d465eb30021c41f",
        "0000000000000001"
    },
    {
        /* Client: CloseNotify */
        {
            "010015","",""
        },
        {
            "6bdf60847ba6fb650da36e872adc684a4af2e8","",""
        },
        "eb23a804904b80ba4fe8399e09b1ce42",
        "efa8c50c06b9c9b8c483e174",
        "0000000000000001"
    },
    {
        /* Server: CloseNotify */
        {
            "010015","",""
        },
        {
            "621b7cc1962cd8a70109fee68a52efedf87d2e","",""
        },
        "3381f6b3f94500f16226de440193e858",
        "4f1d73cc1d465eb30021c41f",
        "0000000000000002"
    }
};

/*
 * Same thing as OPENSSL_hexstr2buf() but enables us to pass the string in
 * 3 chunks
 */
static unsigned char *multihexstr2buf(const char *str[3], size_t *len)
{
    size_t outer, inner, curr = 0;
    unsigned char *outbuf;
    size_t totlen = 0;

    /* Check lengths of all input strings are even */
    for (outer = 0; outer < 3; outer++) {
        totlen += strlen(str[outer]);
        if ((totlen & 1) != 0)
            return NULL;
    }

    totlen /= 2;
    outbuf = OPENSSL_malloc(totlen);
    if (outbuf == NULL)
        return NULL;

    for (outer = 0; outer < 3; outer++) {
        for (inner = 0; str[outer][inner] != 0; inner += 2) {
            int hi, lo;

            hi = OPENSSL_hexchar2int(str[outer][inner]);
            lo = OPENSSL_hexchar2int(str[outer][inner + 1]);

            if (hi < 0 || lo < 0) {
                OPENSSL_free(outbuf);
                return NULL;
            }
            outbuf[curr++] = (hi << 4) | lo;
        }
    }

    *len = totlen;
    return outbuf;
}

static int load_record(SSL3_RECORD *rec, RECORD_DATA *recd, unsigned char **key,
                       unsigned char *iv, size_t ivlen, unsigned char *seq)
{
    unsigned char *pt = NULL, *sq = NULL, *ivtmp = NULL;
    size_t ptlen;

    *key = OPENSSL_hexstr2buf(recd->key, NULL);
    ivtmp = OPENSSL_hexstr2buf(recd->iv, NULL);
    sq = OPENSSL_hexstr2buf(recd->seq, NULL);
    pt = multihexstr2buf(recd->plaintext, &ptlen);

    if (*key == NULL || ivtmp == NULL || sq == NULL || pt == NULL)
        goto err;

    rec->data = rec->input = OPENSSL_malloc(ptlen + EVP_GCM_TLS_TAG_LEN);

    if (rec->data == NULL)
        goto err;

    rec->length = ptlen;
    memcpy(rec->data, pt, ptlen);
    OPENSSL_free(pt);
    memcpy(seq, sq, SEQ_NUM_SIZE);
    OPENSSL_free(sq);
    memcpy(iv, ivtmp, ivlen);
    OPENSSL_free(ivtmp);

    return 1;
 err:
    OPENSSL_free(*key);
    *key = NULL;
    OPENSSL_free(ivtmp);
    OPENSSL_free(sq);
    OPENSSL_free(pt);
    return 0;
}

static int test_record(SSL3_RECORD *rec, RECORD_DATA *recd, int enc)
{
    int ret = 0;
    unsigned char *refd;
    size_t refdatalen;

    if (enc)
        refd = multihexstr2buf(recd->ciphertext, &refdatalen);
    else
        refd = multihexstr2buf(recd->plaintext, &refdatalen);

    if (!TEST_ptr(refd)) {
        TEST_info("Failed to get reference data");
        goto err;
    }

    if (!TEST_mem_eq(rec->data, rec->length, refd, refdatalen))
        goto err;

    ret = 1;

 err:
    OPENSSL_free(refd);
    return ret;
}

#define TLS13_AES_128_GCM_SHA256_BYTES  ((const unsigned char *)"\x13\x01")

static int test_tls13_encryption(void)
{
    SSL_CTX *ctx = NULL;
    SSL *s = NULL;
    SSL3_RECORD rec;
    unsigned char *key = NULL, *iv = NULL, *seq = NULL;
    const EVP_CIPHER *ciph = EVP_aes_128_gcm();
    int ret = 0;
    size_t ivlen, ctr;

    rec.data = NULL;

    ctx = SSL_CTX_new(TLS_method());
    if (!TEST_ptr(ctx)) {
        TEST_info("Failed creating SSL_CTX");
        goto err;
    }

    s = SSL_new(ctx);
    if (!TEST_ptr(s)) {
        TEST_info("Failed creating SSL");
        goto err;
    }

    s->enc_read_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(s->enc_read_ctx))
        goto err;

    s->enc_write_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(s->enc_write_ctx))
        goto err;

    s->s3->tmp.new_cipher = SSL_CIPHER_find(s, TLS13_AES_128_GCM_SHA256_BYTES);
    if (!TEST_ptr(s->s3->tmp.new_cipher)) {
        TEST_info("Failed to find cipher");
        goto err;
    }

    for (ctr = 0; ctr < OSSL_NELEM(refdata); ctr++) {
        /* Load the record */
        ivlen = EVP_CIPHER_iv_length(ciph);
        if (!load_record(&rec, &refdata[ctr], &key, s->read_iv, ivlen,
                         RECORD_LAYER_get_read_sequence(&s->rlayer))) {
            TEST_error("Failed loading key into EVP_CIPHER_CTX");
            goto err;
        }

        /* Set up the read/write sequences */
        memcpy(RECORD_LAYER_get_write_sequence(&s->rlayer),
               RECORD_LAYER_get_read_sequence(&s->rlayer), SEQ_NUM_SIZE);
        memcpy(s->write_iv, s->read_iv, ivlen);

        /* Load the key into the EVP_CIPHER_CTXs */
        if (EVP_CipherInit_ex(s->enc_write_ctx, ciph, NULL, key, NULL, 1) <= 0
                || EVP_CipherInit_ex(s->enc_read_ctx, ciph, NULL, key, NULL, 0)
                   <= 0) {
            TEST_error("Failed loading key into EVP_CIPHER_CTX\n");
            goto err;
        }

        /* Encrypt it */
        if (!TEST_size_t_eq(tls13_enc(s, &rec, 1, 1), 1)) {
            TEST_info("Failed to encrypt record %zu", ctr);
            goto err;
        }
        if (!TEST_true(test_record(&rec, &refdata[ctr], 1))) {
            TEST_info("Record %zu encryption test failed", ctr);
            goto err;
        }

        /* Decrypt it */
        if (!TEST_int_eq(tls13_enc(s, &rec, 1, 0), 1)) {
            TEST_info("Failed to decrypt record %zu", ctr);
            goto err;
        }
        if (!TEST_true(test_record(&rec, &refdata[ctr], 0))) {
            TEST_info("Record %zu decryption test failed", ctr);
            goto err;
        }

        OPENSSL_free(rec.data);
        OPENSSL_free(key);
        OPENSSL_free(iv);
        OPENSSL_free(seq);
        rec.data = NULL;
        key = NULL;
        iv = NULL;
        seq = NULL;
    }

    TEST_note("PASS: %zu records tested", ctr);
    ret = 1;

 err:
    OPENSSL_free(rec.data);
    OPENSSL_free(key);
    OPENSSL_free(iv);
    OPENSSL_free(seq);
    SSL_free(s);
    SSL_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_tls13_encryption);
    return 1;
}
