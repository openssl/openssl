/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_pkcs11.h"
#include "e_pkcs11_err.c"

static int pkcs11_parse_uri(const char *path, char *token, char **value);
static int pkcs11_parse(PKCS11_CTX *ctx, const char *path);
static char pkcs11_hex_int(char nib1, char nib2);
static int pkcs11_ishex(char *hex);
static char* pkcs11_hex2a(char *hex);
static PKCS11_CTX *pkcs11_ctx_new(void);
static void pkcs11_ctx_free(PKCS11_CTX *ctx);
static int bind_pkcs11(ENGINE *e);
static int pkcs11_init(ENGINE *e);
static int pkcs11_destroy(ENGINE *e);
static int pkcs11_finish(ENGINE *e);
static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data);
void engine_load_pkcs11_int(void);
static RSA_METHOD *pkcs11_rsa = NULL;
static const char *engine_id = "pkcs11";
static const char *engine_name = "A minimal PKCS#11 engine only for sign";
static int pkcs11_idx = -1;

static int pkcs11_init(ENGINE *e)
{
    PKCS11_CTX *ctx;

    if (pkcs11_idx < 0) {
        pkcs11_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (pkcs11_idx < 0)
            goto memerr;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    if (ctx == NULL) {
        ctx = pkcs11_ctx_new();

        if (ctx == NULL)
            goto memerr;

        ENGINE_set_ex_data(e, pkcs11_idx, ctx);
    }

    return 1;

 memerr:
    PKCS11err(PKCS11_F_PKCS11_INIT, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int pkcs11_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    char *tmpstr;
    PKCS11_CTX *ctx;

    if (pkcs11_idx == -1 && !pkcs11_init(e)) {
        PKCS11err(PKCS11_F_PKCS11_CTRL, PKCS11_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);

    switch (cmd) {
    case PKCS11_CMD_MODULE_PATH:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->module_path = tmpstr;
            PKCS11_trace("Setting module path to %s\n", ctx->module_path);
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;

    case PKCS11_CMD_PIN:
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->pin = (CK_BYTE *) tmpstr;
            PKCS11_trace("Setting pin\n");
        } else {
            PKCS11err(PKCS11_F_PKCS11_CTRL, ERR_R_MALLOC_FAILURE);
            ret = 0;
        }
        break;
    }

    return ret;
}

static char pkcs11_hex_int(char nib1, char nib2)
{
    int ret = (nib1-(nib1 <= 57 ? 48 : (nib1 < 97 ? 55 : 87)))*16;
    ret += (nib2-(nib2 <= 57 ? 48 : (nib2 < 97 ? 55 : 87)));
    return ret;
}

static char* pkcs11_hex2a(char *hex)
{
    int vlen, j = 0, i, ishex;
    char *hex2a;

    hex2a = OPENSSL_malloc(strlen(hex) + 1);

    if (hex2a == NULL) {
        return NULL;
    }

    vlen = strlen(hex);
    ishex = pkcs11_ishex(hex);
    for (i = 0; i < vlen; i++) {
        if ((*(hex+i) == '%' && i < (vlen-2)) || ishex) {
            *(hex2a+j) = pkcs11_hex_int(*(hex+i+1-ishex), *(hex+i+2-ishex));
            i += (2-ishex);
        } else {
            *(hex2a+j) = *(hex+i);
        }
        j++;
    }
    *(hex2a+j) = '\0';
    return hex2a;
}

static int pkcs11_ishex(char *hex)
{
    int i;
    size_t len, h = 0;

    len = strlen(hex);
    for (i = 0; i < len; i++) {
        if ((*(hex) >= '0' && *(hex) <= '9') || (*(hex) >= 'a' && *(hex) <= 'f')
            || (*(hex) >= 'A' && *(hex) <= 'F')) h++;
    }
    if (h == len && !(h % 2))
        return 1;
    return 0;
}

static int pkcs11_parse_uri(const char *path, char *token, char **value)
{
    char *tmp, *end, *hex2a;
    size_t tmplen;

    if ((tmp = strstr(path, token)) == NULL)
        return 0;
    tmp += strlen(token);
    tmplen = strlen(tmp);
    *value = OPENSSL_malloc(tmplen + 1);

    if (*value == NULL) {
        PKCS11err(PKCS11_F_PKCS11_PARSE_URI, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    end = strpbrk(tmp, ";");
    BIO_snprintf(*value, end == NULL ? tmplen + 1 :
                 (size_t) (end - tmp + 1), "%s", tmp);

    hex2a = pkcs11_hex2a(*value);
    free(*value);
    *value = hex2a;
    return 1;

 err:
    free(*value);
    *value = NULL;
    return 0;
}

static int pkcs11_get_console_pin(char **pin)
{
#ifndef OPENSSL_NO_UI_CONSOLE
    int i;
    const int buflen = 512;
    char *strbuf = OPENSSL_malloc(buflen);

    if (strbuf == NULL) {
        PKCS11err(PKCS11_F_PKCS11_GET_CONSOLE_PIN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (;;) {
        char prompt[200];
        BIO_snprintf(prompt, sizeof(prompt), "Enter PIN: ");
        strbuf[0] = '\0';
        i = EVP_read_pw_string((char *)strbuf, buflen, prompt, 1);
        if (i == 0) {
            if (strbuf[0] == '\0') {
                goto err;
            }
            *pin = strbuf;
            return 1;
        }
        if (i < 0) {
            PKCS11_trace("bad password read\n");
            goto err;
        }
    }

 err:
    OPENSSL_free(strbuf);
#endif

    return 0;
}

static int pkcs11_parse(PKCS11_CTX *ctx, const char *path)
{
    char *id, *module_path = NULL;
    char *pin = NULL, *label = NULL, *slotid = NULL;

    ctx->slotid = 0;
    if (strncmp(path, "pkcs11:", 7) == 0) {
        path += 7;
	if (ctx->module_path == NULL &&
            !pkcs11_parse_uri(path,"module-path=", &module_path))
            goto err;
        if (ctx->module_path == NULL) ctx->module_path = module_path;
	if (!pkcs11_parse_uri(path,"id=", &id) &&
            !pkcs11_parse_uri(path,"object=", &label)) {
            PKCS11_trace("ID and OBJECT are null\n");
            goto err;
        }
	if (!pkcs11_parse_uri(path,"slot-id=", &slotid)) {
           slotid = NULL;
        }
        pkcs11_parse_uri(path,"pin-value=", &pin);
        if (pin != NULL)
            ctx->pin = (CK_BYTE *) pin;
    } else if (path == NULL) {
       PKCS11_trace("inkey is null\n");
       goto err;
    } else {
        if (ctx->module_path == NULL) {
            PKCS11_trace("Module path is null\n");
            goto err;
        }
        id = OPENSSL_strdup(path);

        if (id == NULL) {
            PKCS11err(PKCS11_F_PKCS11_PARSE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (pkcs11_ishex(id))
            id = pkcs11_hex2a(id);

        slotid = NULL;

    }
    if (label != NULL)
        ctx->label = (CK_BYTE *) label;
    else
        ctx->id = (CK_BYTE *) id;
    if (slotid != NULL)
        ctx->slotid = (CK_SLOT_ID) atoi(slotid);

    if (ctx->pin == NULL) {
        if (!pkcs11_get_console_pin(&pin))
            goto err;
        ctx->pin = (CK_BYTE *) pin;
        if (ctx->pin == NULL) {
            PKCS11_trace("PIN is invalid\n");
            goto err;
        }
    }
    return 1;

 err:
    return 0;
}

static EVP_PKEY *pkcs11_engine_load_private_key(ENGINE * e, const char *path,
                                                UI_METHOD * ui_method,
                                                void *callback_data)
{
    CK_RV rv;
    PKCS11_CTX *ctx;

    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    if (!pkcs11_parse(ctx, path))
        goto err;

    rv = pkcs11_initialize(ctx->module_path);

    if (rv != CKR_OK)
        goto err;
    if (!pkcs11_get_slot(ctx))
        goto err;
    if (!pkcs11_start_session(ctx))
        goto err;
    if (!pkcs11_login(ctx, CKU_USER))
        goto err;
    if (!pkcs11_find_private_key(ctx))
        goto err;

    return pkcs11_load_pkey(ctx);

 err:
    PKCS11_trace("pkcs11_engine_load_private_key failed\n");
    return 0;
}

static int bind_pkcs11(ENGINE *e)
{
    const RSA_METHOD *ossl_rsa_meth;

    ossl_rsa_meth = RSA_PKCS1_OpenSSL();

    if ((pkcs11_rsa = RSA_meth_new("PKCS#11 RSA method", 0)) == NULL
        || !RSA_meth_set_sign(pkcs11_rsa, pkcs11_rsa_sign)
        || !RSA_meth_set_pub_enc(pkcs11_rsa,
                                 RSA_meth_get_pub_enc(ossl_rsa_meth))
        || !RSA_meth_set_pub_dec(pkcs11_rsa,
                                 RSA_meth_get_pub_dec(ossl_rsa_meth))
        || !RSA_meth_set_priv_enc(pkcs11_rsa, pkcs11_rsa_priv_enc)
        || !RSA_meth_set_mod_exp(pkcs11_rsa,
                                 RSA_meth_get_mod_exp(ossl_rsa_meth))
        || !RSA_meth_set_bn_mod_exp(pkcs11_rsa,
                                    RSA_meth_get_bn_mod_exp(ossl_rsa_meth))) {
        PKCS11err(PKCS11_F_BIND_PKCS11, PKCS11_R_RSA_INIT_FAILED);
        return 0;
    }

    if (!ENGINE_set_id(e, engine_id)
        || !ENGINE_set_name(e, engine_name)
        || !ENGINE_set_RSA(e, pkcs11_rsa)
        || !ENGINE_set_load_privkey_function(e, pkcs11_engine_load_private_key)
        || !ENGINE_set_destroy_function(e, pkcs11_destroy)
        || !ENGINE_set_init_function(e, pkcs11_init)
        || !ENGINE_set_finish_function(e, pkcs11_finish)
        || !ENGINE_set_cmd_defns(e, pkcs11_cmd_defns)
        || !ENGINE_set_ctrl_function(e, pkcs11_ctrl))
        goto end;

    ERR_load_PKCS11_strings();
    return 1;

 end:
    PKCS11_trace("ENGINE_set failed\n");
    return 0;
}

void PKCS11_trace(char *format, ...)
{
#ifdef DEBUG
# ifndef OPENSSL_NO_STDIO
    BIO *out;
    va_list args;

    out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (out == NULL) {
        PKCS11err(PKCS11_F_PKCS11_TRACE, PKCS11_R_FILE_OPEN_ERROR);
        return;
    }

    va_start(args, format);
    BIO_vprintf(out, format, args);
    va_end(args);
    BIO_free(out);
# endif
#endif
}

static PKCS11_CTX *pkcs11_ctx_new(void)
{
    PKCS11_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        PKCS11err(PKCS11_F_PKCS11_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->lock = CRYPTO_THREAD_lock_new();
    return ctx;
}

static int pkcs11_finish(ENGINE *e)
{
    PKCS11_CTX *ctx;
    ctx = ENGINE_get_ex_data(e, pkcs11_idx);
    pkcs11_ctx_free(ctx);
    ENGINE_set_ex_data(e, pkcs11_idx, NULL);
    return 1;
}

static int pkcs11_destroy(ENGINE *e)
{
    RSA_meth_free(pkcs11_rsa);
    pkcs11_rsa = NULL;
    PKCS11_trace("Calling pkcs11_destroy with engine: %p\n", e);
    ERR_unload_PKCS11_strings();
    return 1;
}

static void pkcs11_ctx_free(PKCS11_CTX *ctx)
{
    CRYPTO_THREAD_lock_free(ctx->lock);
    PKCS11_trace("Calling pkcs11_ctx_free with %p\n", ctx);
    OPENSSL_free(ctx);
}

PKCS11_CTX *pkcs11_get_cms(const RSA *rsa)
{
    return ENGINE_get_ex_data(RSA_get0_engine(rsa), pkcs11_idx);
}


#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_id) != 0))
        return 0;
    if (!bind_pkcs11(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()
#else
static ENGINE *engine_pkcs11(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_pkcs11(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}
void engine_load_pkcs11_int(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_pkcs11();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif
