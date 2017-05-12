/*
 * Copyright 2015-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/kdf.h>
#include "internal/numbers.h"
#include "testutil.h"

static const char *current_test_file = "???";

/*
 * Remove spaces from beginning and end of a string
 */
static void remove_space(char **pval)
{
    unsigned char *p = (unsigned char *)*pval, *beginning;

    while (isspace(*p))
        p++;

    *pval = (char *)(beginning = p);

    p = p + strlen(*pval) - 1;

    /* Remove trailing space */
    while (p >= beginning && isspace(*p))
        *p-- = 0;
}

/*
 * Given a line of the form:
 *      name = value # comment
 * extract name and value. NB: modifies |linebuf|.
 */
static int parse_line(char **pkw, char **pval, char *linebuf)
{
    char *p = linebuf + strlen(linebuf) - 1;

    if (*p != '\n') {
        TEST_error("FATAL: missing EOL");
        return 0;
    }

    /* Look for # */
    p = strchr(linebuf, '#');
    if (p != NULL)
        *p = '\0';

    /* Look for = sign */
    if ((p = strchr(linebuf, '=')) == NULL)
        return 0;
    *p++ = '\0';

    *pkw = linebuf;
    *pval = p;
    remove_space(pkw);
    remove_space(pval);
    return 1;
}

/*
 * Unescape some escape sequences in string literals.
 * Return the result in a newly allocated buffer.
 * Currently only supports '\n'.
 * If the input length is 0, returns a valid 1-byte buffer, but sets
 * the length to 0.
 */
static unsigned char* unescape(const char *input, size_t input_len,
                               size_t *out_len)
{
    unsigned char *ret, *p;
    size_t i;

    if (input_len == 0) {
        *out_len = 0;
        return OPENSSL_zalloc(1);
    }

    /* Escaping is non-expanding; over-allocate original size for simplicity. */
    ret = p = OPENSSL_malloc(input_len);
    if (ret == NULL)
        return NULL;

    for (i = 0; i < input_len; i++) {
        if (input[i] == '\\') {
            if (i == input_len - 1 || input[i+1] != 'n')
                goto err;
            *p++ = '\n';
            i++;
        } else {
            *p++ = input[i];
        }
    }

    *out_len = p - ret;
    return ret;

 err:
    OPENSSL_free(ret);
    return NULL;
}

/* For a hex string "value" convert to a binary allocated buffer */
static int test_bin(const char *value, unsigned char **buf, size_t *buflen)
{
    long len;

    *buflen = 0;

    /* Check for empty value */
    if (!*value) {
        /*
         * Don't return NULL for zero length buffer.
         * This is needed for some tests with empty keys: HMAC_Init_ex() expects
         * a non-NULL key buffer even if the key length is 0, in order to detect
         * key reset.
         */
        *buf = OPENSSL_malloc(1);
        if (!*buf)
            return 0;
        **buf = 0;
        *buflen = 0;
        return 1;
    }

    /* Check for NULL literal */
    if (strcmp(value, "NULL") == 0) {
        *buf = NULL;
        *buflen = 0;
        return 1;
    }

    /* Check for string literal */
    if (value[0] == '"') {
        size_t vlen;
        value++;
        vlen = strlen(value);
        if (value[vlen - 1] != '"')
            return 0;
        vlen--;
        *buf = unescape(value, vlen, buflen);
        if (*buf == NULL)
            return 0;
        return 1;
    }

    /* Otherwise assume as hex literal and convert it to binary buffer */
    if (!TEST_ptr(*buf = OPENSSL_hexstr2buf(value, &len))) {
        TEST_info("Cannot convert %s", value);
        ERR_print_errors(bio_err);
        return -1;
    }
    /* Size of input buffer means we'll never overflow */
    *buflen = len;
    return 1;
}
#ifndef OPENSSL_NO_SCRYPT
/* Currently only used by scrypt tests */
/* Parse unsigned decimal 64 bit integer value */
static int test_uint64(const char *value, uint64_t *pr)
{
    const char *p = value;

    if (!TEST_true(*p)) {
        TEST_info("Invalid empty integer value");
        return -1;
    }
    *pr = 0;
    while (*p) {
        if (*pr > UINT64_MAX / 10) {
            TEST_error("Integer overflow in string %s", value);
            return -1;
        }
        *pr *= 10;
        if (!TEST_true(isdigit(*p))) {
            TEST_error("Invalid character in string %s", value);
            return -1;
        }
        *pr += *p - '0';
        p++;
    }
    return 1;
}

static int compare_mem(unsigned char *expected, size_t expected_len,
                       unsigned char *got, size_t  got_len)
{
    if (!TEST_mem_eq(expected, expected_len, got, got_len))
        return 0;
    return 1;
}
#endif

typedef struct evp_test_method_st EVP_TEST_METHOD;

/* Structure holding test information */
typedef struct evp_test_st {
    /* file being read */
    BIO *in;
    /* temp memory BIO for reading in keys */
    BIO *key;
    /* method for this test */
    const EVP_TEST_METHOD *meth;
    /* current line being processed */
    unsigned int line;
    /* start line of current test */
    unsigned int start_line;
    /* Error string for test */
    const char *err, *aux_err;
    /* Expected error value of test */
    char *expected_err;
    /* Expected error function string */
    char *func;
    /* Expected error reason string */
    char *reason;
    /* Number of tests */
    int ntests;
    /* Error count */
    int errors;
    /* Number of tests skipped */
    int nskip;
    /* test specific data */
    void *data;
    /* Current test should be skipped */
    int skip;
} EVP_TEST;

/*
 * Linked list of named keys.
 */
typedef struct key_list_st {
    char *name;
    EVP_PKEY *key;
    struct key_list_st *next;
} KEY_LIST;

/* List of public and private keys */
static KEY_LIST *private_keys;
static KEY_LIST *public_keys;

/*
 * Test method structure
 */
struct evp_test_method_st {
    /* Name of test as it appears in file */
    const char *name;
    /* Initialise test for "alg" */
    int (*init) (EVP_TEST * t, const char *alg);
    /* Clean up method */
    void (*cleanup) (EVP_TEST * t);
    /* Test specific name value pair processing */
    int (*parse) (EVP_TEST * t, const char *name, const char *value);
    /* Run the test itself */
    int (*run_test) (EVP_TEST * t);
};

static const EVP_TEST_METHOD digest_test_method, cipher_test_method;
static const EVP_TEST_METHOD mac_test_method;
static const EVP_TEST_METHOD psign_test_method, pverify_test_method;
static const EVP_TEST_METHOD pdecrypt_test_method;
static const EVP_TEST_METHOD pverify_recover_test_method;
static const EVP_TEST_METHOD pderive_test_method;
static const EVP_TEST_METHOD pbe_test_method;
static const EVP_TEST_METHOD encode_test_method;
static const EVP_TEST_METHOD kdf_test_method;
static const EVP_TEST_METHOD keypair_test_method;

static const EVP_TEST_METHOD *evp_test_list[] = {
    &digest_test_method,
    &cipher_test_method,
    &mac_test_method,
    &psign_test_method,
    &pverify_test_method,
    &pdecrypt_test_method,
    &pverify_recover_test_method,
    &pderive_test_method,
    &pbe_test_method,
    &encode_test_method,
    &kdf_test_method,
    &keypair_test_method,
    NULL
};

static const EVP_TEST_METHOD *evp_find_test(const char *name)
{
    const EVP_TEST_METHOD **tt;

    for (tt = evp_test_list; *tt; tt++) {
        if (strcmp(name, (*tt)->name) == 0)
            return *tt;
    }
    return NULL;
}

static void clear_test(EVP_TEST *t)
{
    OPENSSL_free(t->expected_err);
    t->expected_err = NULL;
    OPENSSL_free(t->func);
    t->func = NULL;
    OPENSSL_free(t->reason);
    t->reason = NULL;
    /* Text literal. */
    t->err = NULL;
}

/*
 * Check for errors in the test structure; return 1 if okay, else 0.
 */
static int check_test_error(EVP_TEST *t)
{
    unsigned long err;
    const char *func;
    const char *reason;

    if (t->err == NULL && t->expected_err == NULL)
        return 1;
    if (t->err != NULL && t->expected_err == NULL) {
        if (t->aux_err != NULL) {
            TEST_info("Above error from the test at %s:%d "
                      "(%s) unexpected error %s",
                      current_test_file, t->start_line, t->aux_err, t->err);
        } else {
            TEST_info("Above error from the test at %s:%d "
                      "unexpected error %s",
                      current_test_file, t->start_line, t->err);
        }
        clear_test(t);
        return 0;
    }
    if (t->err == NULL && t->expected_err != NULL) {
        TEST_info("Test line %d: succeeded expecting %s",
                  t->start_line, t->expected_err);
        return 0;
    }

    if (strcmp(t->err, t->expected_err) != 0) {
        TEST_info("Test line %d: expecting %s got %s",
                  t->start_line, t->expected_err, t->err);
        return 0;
    }

    if (t->func == NULL && t->reason == NULL)
        return 1;

    if (t->func == NULL || t->reason == NULL) {
        TEST_info("Test line %d: missing function or reason code",
                  t->start_line);
        return 0;
    }

    err = ERR_peek_error();
    if (err == 0) {
        TEST_info("Test line %d, expected error \"%s:%s\" not set",
                  t->start_line, t->func, t->reason);
        return 0;
    }

    func = ERR_func_error_string(err);
    reason = ERR_reason_error_string(err);
    if (func == NULL && reason == NULL) {
        TEST_info("Test line %d: expected error \"%s:%s\","
                  " no strings available.  Skipping...\n",
                  t->start_line, t->func, t->reason);
        return 1;
    }

    if (strcmp(func, t->func) == 0 && strcmp(reason, t->reason) == 0)
        return 1;

    TEST_info("Test line %d: expected error \"%s:%s\", got \"%s:%s\"",
              t->start_line, t->func, t->reason, func, reason);

    return 0;
}

/*
 * Setup a new test, run any existing test. Log a message and return 0
 * on error.
 */
static int run_and_get_next(EVP_TEST *t, const EVP_TEST_METHOD *tmeth)
{
    /* If we already have a test set up run it */
    if (t->meth) {
        t->ntests++;
        if (t->skip) {
            /*TEST_info("Line %d skipped %s test", t->start_line, t->meth->name);
             */
            t->nskip++;
        } else {
            /* run the test */
            if (t->err == NULL && t->meth->run_test(t) != 1) {
                TEST_info("Line %d error %s", t->start_line, t->meth->name);
                return 0;
            }
            if (!check_test_error(t)) {
                test_openssl_errors();
                t->errors++;
            }
        }
        /* clean it up */
        ERR_clear_error();
        if (t->data != NULL) {
            t->meth->cleanup(t);
            OPENSSL_free(t->data);
            t->data = NULL;
        }
        clear_test(t);
    }
    t->meth = tmeth;
    return 1;
}

static int find_key(EVP_PKEY **ppk, const char *name, KEY_LIST *lst)
{
    for (; lst; lst = lst->next) {
        if (strcmp(lst->name, name) == 0) {
            if (ppk)
                *ppk = lst->key;
            return 1;
        }
    }
    return 0;
}

static void free_key_list(KEY_LIST *lst)
{
    while (lst != NULL) {
        KEY_LIST *ltmp;

        EVP_PKEY_free(lst->key);
        OPENSSL_free(lst->name);
        ltmp = lst->next;
        OPENSSL_free(lst);
        lst = ltmp;
    }
}

static int check_unsupported()
{
    long err = ERR_peek_error();

    if (ERR_GET_LIB(err) == ERR_LIB_EVP
            && ERR_GET_REASON(err) == EVP_R_UNSUPPORTED_ALGORITHM) {
        ERR_clear_error();
        return 1;
    }
#ifndef OPENSSL_NO_EC
    /*
     * If EC support is enabled we should catch also EC_R_UNKNOWN_GROUP as an
     * hint to an unsupported algorithm/curve (e.g. if binary EC support is
     * disabled).
     */
    if (ERR_GET_LIB(err) == ERR_LIB_EC
        && ERR_GET_REASON(err) == EC_R_UNKNOWN_GROUP) {
        ERR_clear_error();
        return 1;
    }
#endif /* OPENSSL_NO_EC */
    return 0;
}


static int read_key(EVP_TEST *t)
{
    char tmpbuf[80];

    if (t->key == NULL) {
        if (!TEST_ptr(t->key = BIO_new(BIO_s_mem())))
            return 0;
    } else if (!TEST_int_gt(BIO_reset(t->key), 0)) {
        return 0;
    }

    /* Read to PEM end line and place content in memory BIO */
    while (BIO_gets(t->in, tmpbuf, sizeof(tmpbuf))) {
        t->line++;
        if (!TEST_int_gt(BIO_puts(t->key, tmpbuf), 0))
            return 0;
        if (strncmp(tmpbuf, "-----END", 8) == 0)
            return 1;
    }
    TEST_error("Can't find key end");
    return 0;
}

/*
 * Parse a line into the current test |t|.  Return 0 on error.
 */
static int parse_test_line(EVP_TEST *t, char *buf)
{
    char *keyword = NULL, *value = NULL;
    int add_key = 0;
    KEY_LIST **lst = NULL, *key = NULL;
    EVP_PKEY *pk = NULL;
    const EVP_TEST_METHOD *tmeth = NULL;

    if (!parse_line(&keyword, &value, buf))
        return 1;
    if (strcmp(keyword, "PrivateKey") == 0) {
        if (!read_key(t))
            return 0;
        pk = PEM_read_bio_PrivateKey(t->key, NULL, 0, NULL);
        if (pk == NULL && !check_unsupported()) {
            TEST_info("Error reading private key %s", value);
            ERR_print_errors_fp(stderr);
            return 0;
        }
        lst = &private_keys;
        add_key = 1;
    }
    if (strcmp(keyword, "PublicKey") == 0) {
        if (!read_key(t))
            return 0;
        pk = PEM_read_bio_PUBKEY(t->key, NULL, 0, NULL);
        if (pk == NULL && !check_unsupported()) {
            TEST_info("Error reading public key %s", value);
            ERR_print_errors_fp(stderr);
            return 0;
        }
        lst = &public_keys;
        add_key = 1;
    }
    /* If we have a key add to list */
    if (add_key) {
        if (find_key(NULL, value, *lst)) {
            TEST_info("Duplicate key %s", value);
            return 0;
        }
        if (!TEST_ptr(key = OPENSSL_malloc(sizeof(*key)))
                || !TEST_ptr(key->name = OPENSSL_strdup(value)))
            return 0;
        key->key = pk;
        key->next = *lst;
        *lst = key;
        return 1;
    }

    /* See if keyword corresponds to a test start */
    if ((tmeth = evp_find_test(keyword)) != NULL) {
        if (!run_and_get_next(t, tmeth))
            return 0;
        t->start_line = t->line;
        t->skip = 0;
        if (!tmeth->init(t, value)) {
            TEST_info("Unknown %s: %s", keyword, value);
            return 0;
        }
        return 1;
    }
    if (t->skip)
        return 1;
    if (strcmp(keyword, "Title") == 0) {
        TEST_info("Starting %s tests", value);
        set_test_title(value);
    } else if (strcmp(keyword, "Result") == 0) {
        if (t->expected_err != NULL) {
            TEST_info("Line %d: multiple result lines", t->line);
            return 0;
        }
        if (!TEST_ptr(t->expected_err = OPENSSL_strdup(value)))
            return 0;
    } else if (strcmp(keyword, "Function") == 0) {
        if (t->func != NULL) {
            TEST_info("Line %d: multiple function lines\n", t->line);
            return 0;
        }
        if (!TEST_ptr(t->func = OPENSSL_strdup(value)))
            return 0;
    } else if (strcmp(keyword, "Reason") == 0) {
        if (t->reason != NULL) {
            TEST_info("Line %d: multiple reason lines", t->line);
            return 0;
        }
        if (!TEST_ptr(t->reason = OPENSSL_strdup(value)))
            return 0;
    } else {
        /* Must be test specific line: try to parse it */
        int rv = t->meth == NULL ? 0 : t->meth->parse(t, keyword, value);

        if (rv == 0) {
            TEST_info("Line %d: unknown keyword %s", t->line, keyword);
            return 0;
        }
        if (rv < 0) {
            TEST_info("Line %d: error processing keyword %s\n",
                      t->line, keyword);
            return 0;
        }
    }
    return 1;
}

/* Message digest tests */

typedef struct digest_data_st {
    /* Digest this test is for */
    const EVP_MD *digest;
    /* Input to digest */
    unsigned char *input;
    size_t input_len;
    /* Repeat count for input */
    size_t nrpt;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
} DIGEST_DATA;

static int digest_test_init(EVP_TEST *t, const char *alg)
{
    const EVP_MD *digest;
    DIGEST_DATA *mdat;

    digest = EVP_get_digestbyname(alg);
    if (!digest) {
        /* If alg has an OID assume disabled algorithm */
        if (OBJ_sn2nid(alg) != NID_undef || OBJ_ln2nid(alg) != NID_undef) {
            t->skip = 1;
            return 1;
        }
        return 0;
    }
    mdat = OPENSSL_zalloc(sizeof(*mdat));
    mdat->digest = digest;
    mdat->nrpt = 1;
    t->data = mdat;
    return 1;
}

static void digest_test_cleanup(EVP_TEST *t)
{
    DIGEST_DATA *mdat = t->data;

    OPENSSL_free(mdat->input);
    OPENSSL_free(mdat->output);
}

static int digest_test_parse(EVP_TEST *t,
                             const char *keyword, const char *value)
{
    DIGEST_DATA *mdata = t->data;

    if (strcmp(keyword, "Input") == 0)
        return test_bin(value, &mdata->input, &mdata->input_len);
    if (strcmp(keyword, "Output") == 0)
        return test_bin(value, &mdata->output, &mdata->output_len);
    if (strcmp(keyword, "Count") == 0) {
        long nrpt = atoi(value);
        if (nrpt <= 0)
            return 0;
        mdata->nrpt = (size_t)nrpt;
        return 1;
    }
    return 0;
}

static int digest_test_run(EVP_TEST *t)
{
    DIGEST_DATA *mdata = t->data;
    size_t i;
    EVP_MD_CTX *mctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    t->err = "TEST_FAILURE";
    if (!TEST_ptr(mctx = EVP_MD_CTX_new()))
        goto err;

    if (!EVP_DigestInit_ex(mctx, mdata->digest, NULL)) {
        t->err = "DIGESTINIT_ERROR";
        goto err;
    }
    for (i = 0; i < mdata->nrpt; i++)
        if (!EVP_DigestUpdate(mctx, mdata->input, mdata->input_len)) {
            t->err = "DIGESTUPDATE_ERROR";
            goto err;
        }
    if (!EVP_DigestFinal(mctx, md, &md_len)) {
        t->err = "DIGESTFINAL_ERROR";
        goto err;
    }
    if (md_len != mdata->output_len) {
        t->err = "DIGEST_LENGTH_MISMATCH";
        goto err;
    }
    if (!compare_mem(mdata->output, mdata->output_len, md, md_len)) {
        t->err = "DIGEST_MISMATCH";
        goto err;
    }
    t->err = NULL;

 err:
    EVP_MD_CTX_free(mctx);
    return 1;
}

static const EVP_TEST_METHOD digest_test_method = {
    "Digest",
    digest_test_init,
    digest_test_cleanup,
    digest_test_parse,
    digest_test_run
};

/* Cipher tests */
typedef struct cipher_data_st {
    const EVP_CIPHER *cipher;
    int enc;
    /* EVP_CIPH_GCM_MODE, EVP_CIPH_CCM_MODE or EVP_CIPH_OCB_MODE if AEAD */
    int aead;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char *plaintext;
    size_t plaintext_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    /* GCM, CCM only */
    unsigned char *aad;
    size_t aad_len;
    unsigned char *tag;
    size_t tag_len;
} CIPHER_DATA;

static int cipher_test_init(EVP_TEST *t, const char *alg)
{
    const EVP_CIPHER *cipher;
    CIPHER_DATA *cdat = t->data;

    cipher = EVP_get_cipherbyname(alg);
    if (!cipher) {
        /* If alg has an OID assume disabled algorithm */
        if (OBJ_sn2nid(alg) != NID_undef || OBJ_ln2nid(alg) != NID_undef) {
            t->skip = 1;
            return 1;
        }
        return 0;
    }
    cdat = OPENSSL_malloc(sizeof(*cdat));
    cdat->cipher = cipher;
    cdat->enc = -1;
    cdat->key = NULL;
    cdat->iv = NULL;
    cdat->ciphertext = NULL;
    cdat->plaintext = NULL;
    cdat->aad = NULL;
    cdat->tag = NULL;
    t->data = cdat;
    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE
        || EVP_CIPHER_mode(cipher) == EVP_CIPH_OCB_MODE
        || EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE)
        cdat->aead = EVP_CIPHER_mode(cipher);
    else if (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)
        cdat->aead = -1;
    else
        cdat->aead = 0;

    return 1;
}

static void cipher_test_cleanup(EVP_TEST *t)
{
    CIPHER_DATA *cdat = t->data;

    OPENSSL_free(cdat->key);
    OPENSSL_free(cdat->iv);
    OPENSSL_free(cdat->ciphertext);
    OPENSSL_free(cdat->plaintext);
    OPENSSL_free(cdat->aad);
    OPENSSL_free(cdat->tag);
}

static int cipher_test_parse(EVP_TEST *t, const char *keyword,
                             const char *value)
{
    CIPHER_DATA *cdat = t->data;

    if (strcmp(keyword, "Key") == 0)
        return test_bin(value, &cdat->key, &cdat->key_len);
    if (strcmp(keyword, "IV") == 0)
        return test_bin(value, &cdat->iv, &cdat->iv_len);
    if (strcmp(keyword, "Plaintext") == 0)
        return test_bin(value, &cdat->plaintext, &cdat->plaintext_len);
    if (strcmp(keyword, "Ciphertext") == 0)
        return test_bin(value, &cdat->ciphertext, &cdat->ciphertext_len);
    if (cdat->aead) {
        if (strcmp(keyword, "AAD") == 0)
            return test_bin(value, &cdat->aad, &cdat->aad_len);
        if (strcmp(keyword, "Tag") == 0)
            return test_bin(value, &cdat->tag, &cdat->tag_len);
    }

    if (strcmp(keyword, "Operation") == 0) {
        if (strcmp(value, "ENCRYPT") == 0)
            cdat->enc = 1;
        else if (strcmp(value, "DECRYPT") == 0)
            cdat->enc = 0;
        else
            return 0;
        return 1;
    }
    return 0;
}

static int cipher_test_enc(EVP_TEST *t, int enc,
                           size_t out_misalign, size_t inp_misalign, int frag)
{
    CIPHER_DATA *cdat = t->data;
    unsigned char *in, *out, *tmp = NULL;
    size_t in_len, out_len, donelen = 0;
    int ok = 0, tmplen, chunklen, tmpflen;
    EVP_CIPHER_CTX *ctx = NULL;

    t->err = "TEST_FAILURE";
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (enc) {
        in = cdat->plaintext;
        in_len = cdat->plaintext_len;
        out = cdat->ciphertext;
        out_len = cdat->ciphertext_len;
    } else {
        in = cdat->ciphertext;
        in_len = cdat->ciphertext_len;
        out = cdat->plaintext;
        out_len = cdat->plaintext_len;
    }
    if (inp_misalign == (size_t)-1) {
        /*
         * Exercise in-place encryption
         */
        tmp = OPENSSL_malloc(out_misalign + in_len + 2 * EVP_MAX_BLOCK_LENGTH);
        if (!tmp)
            goto err;
        in = memcpy(tmp + out_misalign, in, in_len);
    } else {
        inp_misalign += 16 - ((out_misalign + in_len) & 15);
        /*
         * 'tmp' will store both output and copy of input. We make the copy
         * of input to specifically aligned part of 'tmp'. So we just
         * figured out how much padding would ensure the required alignment,
         * now we allocate extended buffer and finally copy the input just
         * past inp_misalign in expression below. Output will be written
         * past out_misalign...
         */
        tmp = OPENSSL_malloc(out_misalign + in_len + 2 * EVP_MAX_BLOCK_LENGTH +
                             inp_misalign + in_len);
        if (!tmp)
            goto err;
        in = memcpy(tmp + out_misalign + in_len + 2 * EVP_MAX_BLOCK_LENGTH +
                    inp_misalign, in, in_len);
    }
    if (!EVP_CipherInit_ex(ctx, cdat->cipher, NULL, NULL, NULL, enc)) {
        t->err = "CIPHERINIT_ERROR";
        goto err;
    }
    if (cdat->iv) {
        if (cdat->aead) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                     cdat->iv_len, 0)) {
                t->err = "INVALID_IV_LENGTH";
                goto err;
            }
        } else if (cdat->iv_len != (size_t)EVP_CIPHER_CTX_iv_length(ctx)) {
            t->err = "INVALID_IV_LENGTH";
            goto err;
        }
    }
    if (cdat->aead) {
        unsigned char *tag;
        /*
         * If encrypting or OCB just set tag length initially, otherwise
         * set tag length and value.
         */
        if (enc || cdat->aead == EVP_CIPH_OCB_MODE) {
            t->err = "TAG_LENGTH_SET_ERROR";
            tag = NULL;
        } else {
            t->err = "TAG_SET_ERROR";
            tag = cdat->tag;
        }
        if (tag || cdat->aead != EVP_CIPH_GCM_MODE) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                     cdat->tag_len, tag))
                goto err;
        }
    }

    if (!EVP_CIPHER_CTX_set_key_length(ctx, cdat->key_len)) {
        t->err = "INVALID_KEY_LENGTH";
        goto err;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, cdat->key, cdat->iv, -1)) {
        t->err = "KEY_SET_ERROR";
        goto err;
    }

    if (!enc && cdat->aead == EVP_CIPH_OCB_MODE) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                 cdat->tag_len, cdat->tag)) {
            t->err = "TAG_SET_ERROR";
            goto err;
        }
    }

    if (cdat->aead == EVP_CIPH_CCM_MODE) {
        if (!EVP_CipherUpdate(ctx, NULL, &tmplen, NULL, out_len)) {
            t->err = "CCM_PLAINTEXT_LENGTH_SET_ERROR";
            goto err;
        }
    }
    if (cdat->aad) {
        t->err = "AAD_SET_ERROR";
        if (!frag) {
            if (!EVP_CipherUpdate(ctx, NULL, &chunklen, cdat->aad,
                                  cdat->aad_len))
                goto err;
        } else {
            /*
             * Supply the AAD in chunks less than the block size where possible
             */
            if (cdat->aad_len > 0) {
                if (!EVP_CipherUpdate(ctx, NULL, &chunklen, cdat->aad, 1))
                    goto err;
                donelen++;
            }
            if (cdat->aad_len > 2) {
                if (!EVP_CipherUpdate(ctx, NULL, &chunklen, cdat->aad + donelen,
                                      cdat->aad_len - 2))
                    goto err;
                donelen += cdat->aad_len - 2;
            }
            if (cdat->aad_len > 1
                    && !EVP_CipherUpdate(ctx, NULL, &chunklen,
                                         cdat->aad + donelen, 1))
                goto err;
        }
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    t->err = "CIPHERUPDATE_ERROR";
    tmplen = 0;
    if (!frag) {
        /* We supply the data all in one go */
        if (!EVP_CipherUpdate(ctx, tmp + out_misalign, &tmplen, in, in_len))
            goto err;
    } else {
        /* Supply the data in chunks less than the block size where possible */
        if (in_len > 0) {
            if (!EVP_CipherUpdate(ctx, tmp + out_misalign, &chunklen, in, 1))
                goto err;
            tmplen += chunklen;
            in++;
            in_len--;
        }
        if (in_len > 1) {
            if (!EVP_CipherUpdate(ctx, tmp + out_misalign + tmplen, &chunklen,
                                  in, in_len - 1))
                goto err;
            tmplen += chunklen;
            in += in_len - 1;
            in_len = 1;
        }
        if (in_len > 0 ) {
            if (!EVP_CipherUpdate(ctx, tmp + out_misalign + tmplen, &chunklen,
                                  in, 1))
                goto err;
            tmplen += chunklen;
        }
    }
    if (!EVP_CipherFinal_ex(ctx, tmp + out_misalign + tmplen, &tmpflen)) {
        t->err = "CIPHERFINAL_ERROR";
        goto err;
    }
    if (!compare_mem(out, out_len, tmp + out_misalign, tmplen + tmpflen)) {
        t->err = "VALUE_MISMATCH";
        goto err;
    }
    if (enc && cdat->aead) {
        unsigned char rtag[16];

        if (cdat->tag_len > sizeof(rtag)) {
            t->err = "TAG_LENGTH_INTERNAL_ERROR";
            goto err;
        }
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                 cdat->tag_len, rtag)) {
            t->err = "TAG_RETRIEVE_ERROR";
            goto err;
        }
        if (!compare_mem(cdat->tag, cdat->tag_len, rtag, cdat->tag_len)) {
            t->err = "TAG_VALUE_MISMATCH";
            goto err;
        }
    }
    t->err = NULL;
    ok = 1;
 err:
    OPENSSL_free(tmp);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int cipher_test_run(EVP_TEST *t)
{
    CIPHER_DATA *cdat = t->data;
    int rv, frag = 0;
    size_t out_misalign, inp_misalign;

    if (!cdat->key) {
        t->err = "NO_KEY";
        return 0;
    }
    if (!cdat->iv && EVP_CIPHER_iv_length(cdat->cipher)) {
        /* IV is optional and usually omitted in wrap mode */
        if (EVP_CIPHER_mode(cdat->cipher) != EVP_CIPH_WRAP_MODE) {
            t->err = "NO_IV";
            return 0;
        }
    }
    if (cdat->aead && !cdat->tag) {
        t->err = "NO_TAG";
        return 0;
    }
    for (out_misalign = 0; out_misalign <= 1;) {
        static char aux_err[64];
        t->aux_err = aux_err;
        for (inp_misalign = (size_t)-1; inp_misalign != 2; inp_misalign++) {
            if (inp_misalign == (size_t)-1) {
                /* kludge: inp_misalign == -1 means "exercise in-place" */
                BIO_snprintf(aux_err, sizeof(aux_err),
                             "%s in-place, %sfragmented",
                             out_misalign ? "misaligned" : "aligned",
                             frag ? "" : "not ");
            } else {
                BIO_snprintf(aux_err, sizeof(aux_err),
                             "%s output and %s input, %sfragmented",
                             out_misalign ? "misaligned" : "aligned",
                             inp_misalign ? "misaligned" : "aligned",
                             frag ? "" : "not ");
            }
            if (cdat->enc) {
                rv = cipher_test_enc(t, 1, out_misalign, inp_misalign, frag);
                /* Not fatal errors: return */
                if (rv != 1) {
                    if (rv < 0)
                        return 0;
                    return 1;
                }
            }
            if (cdat->enc != 1) {
                rv = cipher_test_enc(t, 0, out_misalign, inp_misalign, frag);
                /* Not fatal errors: return */
                if (rv != 1) {
                    if (rv < 0)
                        return 0;
                    return 1;
                }
            }
        }

        if (out_misalign == 1 && frag == 0) {
            /*
             * XTS, CCM and Wrap modes have special requirements about input
             * lengths so we don't fragment for those
             */
            if (cdat->aead == EVP_CIPH_CCM_MODE
                    || EVP_CIPHER_mode(cdat->cipher) == EVP_CIPH_XTS_MODE
                     || EVP_CIPHER_mode(cdat->cipher) == EVP_CIPH_WRAP_MODE)
                break;
            out_misalign = 0;
            frag++;
        } else {
            out_misalign++;
        }
    }
    t->aux_err = NULL;

    return 1;
}

static const EVP_TEST_METHOD cipher_test_method = {
    "Cipher",
    cipher_test_init,
    cipher_test_cleanup,
    cipher_test_parse,
    cipher_test_run
};

typedef struct mac_data_st {
    /* MAC type */
    int type;
    /* Algorithm string for this MAC */
    char *alg;
    /* MAC key */
    unsigned char *key;
    size_t key_len;
    /* Input to MAC */
    unsigned char *input;
    size_t input_len;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
} MAC_DATA;

static int mac_test_init(EVP_TEST *t, const char *alg)
{
    int type;
    MAC_DATA *mdat;

    if (strcmp(alg, "HMAC") == 0) {
        type = EVP_PKEY_HMAC;
    } else if (strcmp(alg, "CMAC") == 0) {
#ifndef OPENSSL_NO_CMAC
        type = EVP_PKEY_CMAC;
#else
        t->skip = 1;
        return 1;
#endif
    } else if (strcmp(alg, "Poly1305") == 0) {
#ifndef OPENSSL_NO_POLY1305
        type = EVP_PKEY_POLY1305;
#else
        t->skip = 1;
        return 1;
#endif
    } else if (strcmp(alg, "SipHash") == 0) {
#ifndef OPENSSL_NO_SIPHASH
        type = EVP_PKEY_SIPHASH;
#else
        t->skip = 1;
        return 1;
#endif
    } else
        return 0;

    mdat = OPENSSL_zalloc(sizeof(*mdat));
    mdat->type = type;
    t->data = mdat;
    return 1;
}

static void mac_test_cleanup(EVP_TEST *t)
{
    MAC_DATA *mdat = t->data;

    OPENSSL_free(mdat->alg);
    OPENSSL_free(mdat->key);
    OPENSSL_free(mdat->input);
    OPENSSL_free(mdat->output);
}

static int mac_test_parse(EVP_TEST *t,
                          const char *keyword, const char *value)
{
    MAC_DATA *mdata = t->data;

    if (strcmp(keyword, "Key") == 0)
        return test_bin(value, &mdata->key, &mdata->key_len);
    if (strcmp(keyword, "Algorithm") == 0) {
        mdata->alg = OPENSSL_strdup(value);
        if (!mdata->alg)
            return 0;
        return 1;
    }
    if (strcmp(keyword, "Input") == 0)
        return test_bin(value, &mdata->input, &mdata->input_len);
    if (strcmp(keyword, "Output") == 0)
        return test_bin(value, &mdata->output, &mdata->output_len);
    return 0;
}

static int mac_test_run(EVP_TEST *t)
{
    MAC_DATA *mdata = t->data;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL, *genctx = NULL;
    EVP_PKEY *key = NULL;
    const EVP_MD *md = NULL;
    unsigned char *mac = NULL;
    size_t mac_len;

#ifdef OPENSSL_NO_DES
    if (mdata->alg != NULL && strstr(mdata->alg, "DES") != NULL) {
        /* Skip DES */
        t->err = NULL;
        goto err;
    }
#endif

    if (!TEST_ptr(genctx = EVP_PKEY_CTX_new_id(mdata->type, NULL))) {
        t->err = "MAC_PKEY_CTX_ERROR";
        goto err;
    }

    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        t->err = "MAC_KEYGEN_INIT_ERROR";
        goto err;
    }
    if (mdata->type == EVP_PKEY_CMAC
             && EVP_PKEY_CTX_ctrl_str(genctx, "cipher", mdata->alg) <= 0) {
        t->err = "MAC_ALGORITHM_SET_ERROR";
        goto err;
    }

    if (EVP_PKEY_CTX_set_mac_key(genctx, mdata->key, mdata->key_len) <= 0) {
        t->err = "MAC_KEY_SET_ERROR";
        goto err;
    }

    if (EVP_PKEY_keygen(genctx, &key) <= 0) {
        t->err = "MAC_KEY_GENERATE_ERROR";
        goto err;
    }
    if (mdata->type == EVP_PKEY_HMAC) {
        if (!TEST_ptr(md = EVP_get_digestbyname(mdata->alg))) {
            t->err = "MAC_ALGORITHM_SET_ERROR";
            goto err;
        }
    }
    if (!TEST_ptr(mctx = EVP_MD_CTX_new())) {
        t->err = "INTERNAL_ERROR";
        goto err;
    }
    if (!EVP_DigestSignInit(mctx, &pctx, md, NULL, key)) {
        t->err = "DIGESTSIGNINIT_ERROR";
        goto err;
    }

    if (!EVP_DigestSignUpdate(mctx, mdata->input, mdata->input_len)) {
        t->err = "DIGESTSIGNUPDATE_ERROR";
        goto err;
    }
    if (!EVP_DigestSignFinal(mctx, NULL, &mac_len)) {
        t->err = "DIGESTSIGNFINAL_LENGTH_ERROR";
        goto err;
    }
    if (!TEST_ptr(mac = OPENSSL_malloc(mac_len))) {
        t->err = "TEST_FAILURE";
        goto err;
    }
    if (!EVP_DigestSignFinal(mctx, mac, &mac_len)
            || !compare_mem(mdata->output, mdata->output_len, mac, mac_len)) {
        t->err = "TEST_MAC_ERR";
        goto err;
    }
    t->err = NULL;
 err:
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(mac);
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(key);
    return 1;
}

static const EVP_TEST_METHOD mac_test_method = {
    "MAC",
    mac_test_init,
    mac_test_cleanup,
    mac_test_parse,
    mac_test_run
};

/*
 * Public key operations. These are all very similar and can share
 * a lot of common code.
 */

typedef struct pkey_data_st {
    /* Context for this operation */
    EVP_PKEY_CTX *ctx;
    /* Key operation to perform */
    int (*keyop) (EVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
    /* Input to MAC */
    unsigned char *input;
    size_t input_len;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
} PKEY_DATA;

/*
 * Perform public key operation setup: lookup key, allocated ctx and call
 * the appropriate initialisation function
 */
static int pkey_test_init(EVP_TEST *t, const char *name,
                          int use_public,
                          int (*keyopinit) (EVP_PKEY_CTX *ctx),
                          int (*keyop) (EVP_PKEY_CTX *ctx,
                                        unsigned char *sig, size_t *siglen,
                                        const unsigned char *tbs,
                                        size_t tbslen)
    )
{
    PKEY_DATA *kdata;
    EVP_PKEY *pkey = NULL;
    int rv = 0;

    if (use_public)
        rv = find_key(&pkey, name, public_keys);
    if (rv == 0)
        rv = find_key(&pkey, name, private_keys);
    if (rv == 0 || pkey == NULL) {
        t->skip = 1;
        return 1;
    }

    if (!TEST_ptr(kdata = OPENSSL_malloc(sizeof(*kdata)))) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    kdata->ctx = NULL;
    kdata->input = NULL;
    kdata->output = NULL;
    kdata->keyop = keyop;
    t->data = kdata;
    if (!TEST_ptr(kdata->ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        return 0;
    if (keyopinit(kdata->ctx) <= 0)
        t->err = "KEYOP_INIT_ERROR";
    return 1;
}

static void pkey_test_cleanup(EVP_TEST *t)
{
    PKEY_DATA *kdata = t->data;

    OPENSSL_free(kdata->input);
    OPENSSL_free(kdata->output);
    EVP_PKEY_CTX_free(kdata->ctx);
}

static int pkey_test_ctrl(EVP_TEST *t, EVP_PKEY_CTX *pctx,
                          const char *value)
{
    int rv;
    char *p, *tmpval;

    if (!TEST_ptr(tmpval = OPENSSL_strdup(value)))
        return 0;
    p = strchr(tmpval, ':');
    if (p != NULL)
        *p++ = 0;
    rv = EVP_PKEY_CTX_ctrl_str(pctx, tmpval, p);
    if (rv == -2) {
        t->err = "PKEY_CTRL_INVALID";
        rv = 1;
    } else if (p != NULL && rv <= 0) {
        /* If p has an OID and lookup fails assume disabled algorithm */
        int nid = OBJ_sn2nid(p);

        if (nid == NID_undef)
             nid = OBJ_ln2nid(p);
        if ((nid != NID_undef) && EVP_get_digestbynid(nid) == NULL &&
            EVP_get_cipherbynid(nid) == NULL) {
            t->skip = 1;
            rv = 1;
        } else {
            t->err = "PKEY_CTRL_ERROR";
            rv = 1;
        }
    }
    OPENSSL_free(tmpval);
    return rv > 0;
}

static int pkey_test_parse(EVP_TEST *t,
                           const char *keyword, const char *value)
{
    PKEY_DATA *kdata = t->data;
    if (strcmp(keyword, "Input") == 0)
        return test_bin(value, &kdata->input, &kdata->input_len);
    if (strcmp(keyword, "Output") == 0)
        return test_bin(value, &kdata->output, &kdata->output_len);
    if (strcmp(keyword, "Ctrl") == 0)
        return pkey_test_ctrl(t, kdata->ctx, value);
    return 0;
}

static int pkey_test_run(EVP_TEST *t)
{
    PKEY_DATA *kdata = t->data;
    unsigned char *out = NULL;
    size_t out_len;

    if (kdata->keyop(kdata->ctx, NULL, &out_len, kdata->input,
                     kdata->input_len) <= 0
            || !TEST_ptr(out = OPENSSL_malloc(out_len))) {
        t->err = "KEYOP_LENGTH_ERROR";
        goto err;
    }
    if (kdata->keyop(kdata->ctx, out,
                     &out_len, kdata->input, kdata->input_len) <= 0) {
        t->err = "KEYOP_ERROR";
        goto err;
    }
    if (!compare_mem(kdata->output, kdata->output_len, out, out_len)) {
        t->err = "KEYOP_MISMATCH";
        goto err;
    }
    t->err = NULL;
 err:
    OPENSSL_free(out);
    return 1;
}

static int sign_test_init(EVP_TEST *t, const char *name)
{
    return pkey_test_init(t, name, 0, EVP_PKEY_sign_init, EVP_PKEY_sign);
}

static const EVP_TEST_METHOD psign_test_method = {
    "Sign",
    sign_test_init,
    pkey_test_cleanup,
    pkey_test_parse,
    pkey_test_run
};

static int verify_recover_test_init(EVP_TEST *t, const char *name)
{
    return pkey_test_init(t, name, 1, EVP_PKEY_verify_recover_init,
                          EVP_PKEY_verify_recover);
}

static const EVP_TEST_METHOD pverify_recover_test_method = {
    "VerifyRecover",
    verify_recover_test_init,
    pkey_test_cleanup,
    pkey_test_parse,
    pkey_test_run
};

static int decrypt_test_init(EVP_TEST *t, const char *name)
{
    return pkey_test_init(t, name, 0, EVP_PKEY_decrypt_init,
                          EVP_PKEY_decrypt);
}

static const EVP_TEST_METHOD pdecrypt_test_method = {
    "Decrypt",
    decrypt_test_init,
    pkey_test_cleanup,
    pkey_test_parse,
    pkey_test_run
};

static int verify_test_init(EVP_TEST *t, const char *name)
{
    return pkey_test_init(t, name, 1, EVP_PKEY_verify_init, 0);
}

static int verify_test_run(EVP_TEST *t)
{
    PKEY_DATA *kdata = t->data;

    if (EVP_PKEY_verify(kdata->ctx, kdata->output, kdata->output_len,
                        kdata->input, kdata->input_len) <= 0)
        t->err = "VERIFY_ERROR";
    return 1;
}

static const EVP_TEST_METHOD pverify_test_method = {
    "Verify",
    verify_test_init,
    pkey_test_cleanup,
    pkey_test_parse,
    verify_test_run
};


static int pderive_test_init(EVP_TEST *t, const char *name)
{
    return pkey_test_init(t, name, 0, EVP_PKEY_derive_init, 0);
}

static int pderive_test_parse(EVP_TEST *t,
                              const char *keyword, const char *value)
{
    PKEY_DATA *kdata = t->data;

    if (strcmp(keyword, "PeerKey") == 0) {
        EVP_PKEY *peer;
        if (find_key(&peer, value, public_keys) == 0)
            return 0;
        if (EVP_PKEY_derive_set_peer(kdata->ctx, peer) <= 0)
            return 0;
        return 1;
    }
    if (strcmp(keyword, "SharedSecret") == 0)
        return test_bin(value, &kdata->output, &kdata->output_len);
    if (strcmp(keyword, "Ctrl") == 0)
        return pkey_test_ctrl(t, kdata->ctx, value);
    return 0;
}

static int pderive_test_run(EVP_TEST *t)
{
    PKEY_DATA *kdata = t->data;
    unsigned char *out = NULL;
    size_t out_len;

    out_len = kdata->output_len;
    if (!TEST_ptr(out = OPENSSL_malloc(out_len))) {
        t->err = "DERIVE_ERROR";
        goto err;
    }
    if (EVP_PKEY_derive(kdata->ctx, out, &out_len) <= 0) {
        t->err = "DERIVE_ERROR";
        goto err;
    }
    if (!compare_mem(kdata->output, kdata->output_len, out, out_len)) {
        t->err = "SHARED_SECRET_MISMATCH";
        goto err;
    }

    t->err = NULL;
 err:
    OPENSSL_free(out);
    return 1;
}

static const EVP_TEST_METHOD pderive_test_method = {
    "Derive",
    pderive_test_init,
    pkey_test_cleanup,
    pderive_test_parse,
    pderive_test_run
};

/* PBE tests */

#define PBE_TYPE_SCRYPT 1
#define PBE_TYPE_PBKDF2 2
#define PBE_TYPE_PKCS12 3

typedef struct pbe_data_st {
    int pbe_type;
        /* scrypt parameters */
    uint64_t N, r, p, maxmem;
        /* PKCS#12 parameters */
    int id, iter;
    const EVP_MD *md;
        /* password */
    unsigned char *pass;
    size_t pass_len;
        /* salt */
    unsigned char *salt;
    size_t salt_len;
        /* Expected output */
    unsigned char *key;
    size_t key_len;
} PBE_DATA;

#ifndef OPENSSL_NO_SCRYPT
static int scrypt_test_parse(EVP_TEST *t,
                             const char *keyword, const char *value)
{
    PBE_DATA *pdata = t->data;

    if (strcmp(keyword, "N") == 0)
        return test_uint64(value, &pdata->N);
    if (strcmp(keyword, "p") == 0)
        return test_uint64(value, &pdata->p);
    if (strcmp(keyword, "r") == 0)
        return test_uint64(value, &pdata->r);
    if (strcmp(keyword, "maxmem") == 0)
        return test_uint64(value, &pdata->maxmem);
    return 0;
}
#endif

static int pbkdf2_test_parse(EVP_TEST *t,
                             const char *keyword, const char *value)
{
    PBE_DATA *pdata = t->data;

    if (strcmp(keyword, "iter") == 0) {
        pdata->iter = atoi(value);
        if (pdata->iter <= 0)
            return 0;
        return 1;
    }
    if (strcmp(keyword, "MD") == 0) {
        pdata->md = EVP_get_digestbyname(value);
        if (pdata->md == NULL)
            return 0;
        return 1;
    }
    return 0;
}

static int pkcs12_test_parse(EVP_TEST *t,
                             const char *keyword, const char *value)
{
    PBE_DATA *pdata = t->data;

    if (strcmp(keyword, "id") == 0) {
        pdata->id = atoi(value);
        if (pdata->id <= 0)
            return 0;
        return 1;
    }
    return pbkdf2_test_parse(t, keyword, value);
}

static int pbe_test_init(EVP_TEST *t, const char *alg)
{
    PBE_DATA *pdat;
    int pbe_type = 0;

    if (strcmp(alg, "scrypt") == 0) {
#ifndef OPENSSL_NO_SCRYPT
        pbe_type = PBE_TYPE_SCRYPT;
#else
        t->skip = 1;
        return 1;
#endif
    } else if (strcmp(alg, "pbkdf2") == 0) {
        pbe_type = PBE_TYPE_PBKDF2;
    } else if (strcmp(alg, "pkcs12") == 0) {
        pbe_type = PBE_TYPE_PKCS12;
    } else {
        TEST_error("Unknown pbe algorithm %s", alg);
    }
    pdat = OPENSSL_malloc(sizeof(*pdat));
    pdat->pbe_type = pbe_type;
    pdat->pass = NULL;
    pdat->salt = NULL;
    pdat->N = 0;
    pdat->r = 0;
    pdat->p = 0;
    pdat->maxmem = 0;
    pdat->id = 0;
    pdat->iter = 0;
    pdat->md = NULL;
    t->data = pdat;
    return 1;
}

static void pbe_test_cleanup(EVP_TEST *t)
{
    PBE_DATA *pdat = t->data;

    OPENSSL_free(pdat->pass);
    OPENSSL_free(pdat->salt);
    OPENSSL_free(pdat->key);
}

static int pbe_test_parse(EVP_TEST *t,
                          const char *keyword, const char *value)
{
    PBE_DATA *pdata = t->data;

    if (strcmp(keyword, "Password") == 0)
        return test_bin(value, &pdata->pass, &pdata->pass_len);
    if (strcmp(keyword, "Salt") == 0)
        return test_bin(value, &pdata->salt, &pdata->salt_len);
    if (strcmp(keyword, "Key") == 0)
        return test_bin(value, &pdata->key, &pdata->key_len);
    if (pdata->pbe_type == PBE_TYPE_PBKDF2)
        return pbkdf2_test_parse(t, keyword, value);
    else if (pdata->pbe_type == PBE_TYPE_PKCS12)
        return pkcs12_test_parse(t, keyword, value);
#ifndef OPENSSL_NO_SCRYPT
    else if (pdata->pbe_type == PBE_TYPE_SCRYPT)
        return scrypt_test_parse(t, keyword, value);
#endif
    return 0;
}

static int pbe_test_run(EVP_TEST *t)
{
    PBE_DATA *pdata = t->data;
    unsigned char *key;

    if (!TEST_ptr(key = OPENSSL_malloc(pdata->key_len))) {
        t->err = "INTERNAL_ERROR";
        goto err;
    }
    if (pdata->pbe_type == PBE_TYPE_PBKDF2) {
        if (PKCS5_PBKDF2_HMAC((char *)pdata->pass, pdata->pass_len,
                              pdata->salt, pdata->salt_len,
                              pdata->iter, pdata->md,
                              pdata->key_len, key) == 0) {
            t->err = "PBKDF2_ERROR";
            goto err;
        }
#ifndef OPENSSL_NO_SCRYPT
    } else if (pdata->pbe_type == PBE_TYPE_SCRYPT) {
        if (EVP_PBE_scrypt((const char *)pdata->pass, pdata->pass_len,
                           pdata->salt, pdata->salt_len,
                           pdata->N, pdata->r, pdata->p, pdata->maxmem,
                           key, pdata->key_len) == 0) {
            t->err = "SCRYPT_ERROR";
            goto err;
        }
#endif
    } else if (pdata->pbe_type == PBE_TYPE_PKCS12) {
        if (PKCS12_key_gen_uni(pdata->pass, pdata->pass_len,
                               pdata->salt, pdata->salt_len,
                               pdata->id, pdata->iter, pdata->key_len,
                               key, pdata->md) == 0) {
            t->err = "PKCS12_ERROR";
            goto err;
        }
    }
    if (!compare_mem(pdata->key, pdata->key_len, key, pdata->key_len)) {
        t->err = "KEY_MISMATCH";
        goto err;
    }
    t->err = NULL;
err:
    OPENSSL_free(key);
    return 1;
}

static const EVP_TEST_METHOD pbe_test_method = {
    "PBE",
    pbe_test_init,
    pbe_test_cleanup,
    pbe_test_parse,
    pbe_test_run
};

/* Base64 tests */

typedef enum {
    BASE64_CANONICAL_ENCODING = 0,
    BASE64_VALID_ENCODING = 1,
    BASE64_INVALID_ENCODING = 2
} base64_encoding_type;

typedef struct encode_data_st {
    /* Input to encoding */
    unsigned char *input;
    size_t input_len;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
    base64_encoding_type encoding;
} ENCODE_DATA;

static int encode_test_init(EVP_TEST *t, const char *encoding)
{
    ENCODE_DATA *edata = OPENSSL_zalloc(sizeof(*edata));

    if (strcmp(encoding, "canonical") == 0) {
        edata->encoding = BASE64_CANONICAL_ENCODING;
    } else if (strcmp(encoding, "valid") == 0) {
        edata->encoding = BASE64_VALID_ENCODING;
    } else if (strcmp(encoding, "invalid") == 0) {
        edata->encoding = BASE64_INVALID_ENCODING;
        t->expected_err = OPENSSL_strdup("DECODE_ERROR");
        if (t->expected_err == NULL)
            return 0;
    } else {
        TEST_info("Bad encoding: %s. Should be one of "
                  "{canonical, valid, invalid}", encoding);
        return 0;
    }
    t->data = edata;
    return 1;
}

static void encode_test_cleanup(EVP_TEST *t)
{
    ENCODE_DATA *edata = t->data;

    OPENSSL_free(edata->input);
    OPENSSL_free(edata->output);
    memset(edata, 0, sizeof(*edata));
}

static int encode_test_parse(EVP_TEST *t,
                             const char *keyword, const char *value)
{
    ENCODE_DATA *edata = t->data;
    if (strcmp(keyword, "Input") == 0)
        return test_bin(value, &edata->input, &edata->input_len);
    if (strcmp(keyword, "Output") == 0)
        return test_bin(value, &edata->output, &edata->output_len);
    return 0;
}

static int encode_test_run(EVP_TEST *t)
{
    ENCODE_DATA *edata = t->data;
    unsigned char *encode_out = NULL, *decode_out = NULL;
    int output_len, chunk_len;
    EVP_ENCODE_CTX *decode_ctx;

    if (!TEST_ptr(decode_ctx = EVP_ENCODE_CTX_new())) {
        t->err = "INTERNAL_ERROR";
        goto err;
    }

    if (edata->encoding == BASE64_CANONICAL_ENCODING) {
        EVP_ENCODE_CTX *encode_ctx;

        if (!TEST_ptr(encode_ctx = EVP_ENCODE_CTX_new())
                || !TEST_ptr(encode_out =
                        OPENSSL_malloc(EVP_ENCODE_LENGTH(edata->input_len))))
            goto err;

        EVP_EncodeInit(encode_ctx);
        EVP_EncodeUpdate(encode_ctx, encode_out, &chunk_len,
                         edata->input, edata->input_len);
        output_len = chunk_len;

        EVP_EncodeFinal(encode_ctx, encode_out + chunk_len, &chunk_len);
        output_len += chunk_len;

        EVP_ENCODE_CTX_free(encode_ctx);

        if (!compare_mem(edata->output, edata->output_len,
                         encode_out, output_len)) {
            t->err = "BAD_ENCODING";
            goto err;
        }
    }

    if (!TEST_ptr(decode_out =
                OPENSSL_malloc(EVP_DECODE_LENGTH(edata->output_len))))
        goto err;

    EVP_DecodeInit(decode_ctx);
    if (EVP_DecodeUpdate(decode_ctx, decode_out, &chunk_len, edata->output,
                         edata->output_len) < 0) {
        t->err = "DECODE_ERROR";
        goto err;
    }
    output_len = chunk_len;

    if (EVP_DecodeFinal(decode_ctx, decode_out + chunk_len, &chunk_len) != 1) {
        t->err = "DECODE_ERROR";
        goto err;
    }
    output_len += chunk_len;

    if (edata->encoding != BASE64_INVALID_ENCODING
            && !compare_mem(edata->input, edata->input_len,
                            decode_out, output_len)) {
        t->err = "BAD_DECODING";
        goto err;
    }

    t->err = NULL;
 err:
    OPENSSL_free(encode_out);
    OPENSSL_free(decode_out);
    EVP_ENCODE_CTX_free(decode_ctx);
    return 1;
}

static const EVP_TEST_METHOD encode_test_method = {
    "Encoding",
    encode_test_init,
    encode_test_cleanup,
    encode_test_parse,
    encode_test_run,
};

/* KDF operations */

typedef struct kdf_data_st {
    /* Context for this operation */
    EVP_PKEY_CTX *ctx;
    /* Expected output */
    unsigned char *output;
    size_t output_len;
} KDF_DATA;

/*
 * Perform public key operation setup: lookup key, allocated ctx and call
 * the appropriate initialisation function
 */
static int kdf_test_init(EVP_TEST *t, const char *name)
{
    KDF_DATA *kdata;

    kdata = OPENSSL_malloc(sizeof(*kdata));
    if (kdata == NULL)
        return 0;
    kdata->ctx = NULL;
    kdata->output = NULL;
    t->data = kdata;
    kdata->ctx = EVP_PKEY_CTX_new_id(OBJ_sn2nid(name), NULL);
    if (kdata->ctx == NULL)
        return 0;
    if (EVP_PKEY_derive_init(kdata->ctx) <= 0)
        return 0;
    return 1;
}

static void kdf_test_cleanup(EVP_TEST *t)
{
    KDF_DATA *kdata = t->data;
    OPENSSL_free(kdata->output);
    EVP_PKEY_CTX_free(kdata->ctx);
}

static int kdf_test_parse(EVP_TEST *t,
                          const char *keyword, const char *value)
{
    KDF_DATA *kdata = t->data;

    if (strcmp(keyword, "Output") == 0)
        return test_bin(value, &kdata->output, &kdata->output_len);
    if (strncmp(keyword, "Ctrl", 4) == 0)
        return pkey_test_ctrl(t, kdata->ctx, value);
    return 0;
}

static int kdf_test_run(EVP_TEST *t)
{
    KDF_DATA *kdata = t->data;
    unsigned char *out = NULL;
    size_t out_len = kdata->output_len;

    if (!TEST_ptr(out = OPENSSL_malloc(out_len))) {
        t->err = "INTERNAL_ERROR";
        goto err;
    }
    if (EVP_PKEY_derive(kdata->ctx, out, &out_len) <= 0) {
        t->err = "KDF_DERIVE_ERROR";
        goto err;
    }
    if (!compare_mem(kdata->output, kdata->output_len, out, out_len)) {
        t->err = "KDF_MISMATCH";
        goto err;
    }
    t->err = NULL;

 err:
    OPENSSL_free(out);
    return 1;
}

static const EVP_TEST_METHOD kdf_test_method = {
    "KDF",
    kdf_test_init,
    kdf_test_cleanup,
    kdf_test_parse,
    kdf_test_run
};

typedef struct keypair_test_data_st {
    EVP_PKEY *privk;
    EVP_PKEY *pubk;
} KEYPAIR_TEST_DATA;

static int keypair_test_init(EVP_TEST *t, const char *pair)
{
    int rv = 0;
    EVP_PKEY *pk = NULL, *pubk = NULL;
    char *pub, *priv = NULL;
    KEYPAIR_TEST_DATA *data;

    if (!TEST_ptr(priv = OPENSSL_strdup(pair))
            || !TEST_ptr(pub = strchr(priv, ':'))) {
        t->err = "PARSING_ERROR";
        goto end;
    }
    *pub++ = 0; /* split priv and pub strings */

    if (!TEST_true(find_key(&pk, priv, private_keys))) {
        TEST_info("Cannot find private key: %s", priv);
        t->err = "MISSING_PRIVATE_KEY";
        goto end;
    }
    if (!TEST_true(find_key(&pubk, pub, public_keys))) {
        TEST_info("Cannot find public key: %s", pub);
        t->err = "MISSING_PUBLIC_KEY";
        goto end;
    }

    if (pk == NULL && pubk == NULL) {
        /* Both keys are listed but unsupported: skip this test */
        t->skip = 1;
        rv = 1;
        goto end;
    }

    if (!TEST_ptr(data = OPENSSL_malloc(sizeof(*data))))
        goto end;

    data->privk = pk;
    data->pubk = pubk;
    t->data = data;
    rv = 1;
    t->err = NULL;

end:
    OPENSSL_free(priv);
    return rv;
}

static void keypair_test_cleanup(EVP_TEST *t)
{
    OPENSSL_free(t->data);
    t->data = NULL;
}

/* For test that do not accept any custom keyword:
 *      return 0 if called
 */
static int void_test_parse(EVP_TEST *t, const char *keyword, const char *value)
{
    return 0;
}

static int keypair_test_run(EVP_TEST *t)
{
    int rv = 0;
    const KEYPAIR_TEST_DATA *pair = t->data;

    if (pair->privk == NULL || pair->pubk == NULL) {
        /*
         * this can only happen if only one of the keys is not set
         * which means that one of them was unsupported while the
         * other isn't: hence a key type mismatch.
         */
        t->err = "KEYPAIR_TYPE_MISMATCH";
        rv = 1;
        goto end;
    }

    if ((rv = EVP_PKEY_cmp(pair->privk, pair->pubk)) != 1 ) {
        if ( 0 == rv ) {
            t->err = "KEYPAIR_MISMATCH";
        } else if ( -1 == rv ) {
            t->err = "KEYPAIR_TYPE_MISMATCH";
        } else if ( -2 == rv ) {
            t->err = "UNSUPPORTED_KEY_COMPARISON";
        } else {
            TEST_error("Unexpected error in key comparison");
            rv = 0;
            goto end;
        }
        rv = 1;
        goto end;
    }

    rv = 1;
    t->err = NULL;

end:
    return rv;
}

static const EVP_TEST_METHOD keypair_test_method = {
    "PrivPubKeyPair",
    keypair_test_init,
    keypair_test_cleanup,
    void_test_parse,
    keypair_test_run
};

static int do_test_file(const char *testfile)
{
    BIO *in;
    char buf[10240];
    EVP_TEST t;

    set_test_title(testfile);
    current_test_file = testfile;
    if (!TEST_ptr(in = BIO_new_file(testfile, "rb")))
        return 0;
    memset(&t, 0, sizeof(t));
    t.start_line = -1;
    t.in = in;
    t.err = NULL;
    while (BIO_gets(in, buf, sizeof(buf))) {
        t.line++;
        if (!TEST_true(parse_test_line(&t, buf)))
            return 0;
    }
    /* Run any final test we have */
    if (!run_and_get_next(&t, NULL))
        return 0;

    TEST_info("Completed %d tests with %d errors and %d skipped",
              t.ntests, t.errors, t.nskip);
    free_key_list(public_keys);
    free_key_list(private_keys);
    BIO_free(t.key);
    BIO_free(in);
    return t.errors == 0;
}

static char * const *testfiles;

static int run_file_tests(int i)
{
    return do_test_file(testfiles[i]);
}

int test_main(int argc, char *argv[])
{
    if (argc < 2) {
        TEST_error("Usage: %s file...", argv[0]);
        return 0;
    }
    testfiles = &argv[1];

    ADD_ALL_TESTS(run_file_tests, argc - 1);

    return run_tests(argv[0]);
}
