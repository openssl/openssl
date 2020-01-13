/*
 * Copyright 2004-2018 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2004, EdelKey Project. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 *
 * Originally written by Christophe Renou and Peter Sylvester,
 * for the EdelKey project.
 */

#include <opentls/crypto.h>
#include <opentls/rand.h>
#include <opentls/err.h>
#include "tls_local.h"

#ifndef OPENtls_NO_SRP
# include <opentls/srp.h>

int tls_CTX_SRP_CTX_free(struct tls_ctx_st *ctx)
{
    if (ctx == NULL)
        return 0;
    OPENtls_free(ctx->srp_ctx.login);
    OPENtls_free(ctx->srp_ctx.info);
    BN_free(ctx->srp_ctx.N);
    BN_free(ctx->srp_ctx.g);
    BN_free(ctx->srp_ctx.s);
    BN_free(ctx->srp_ctx.B);
    BN_free(ctx->srp_ctx.A);
    BN_free(ctx->srp_ctx.a);
    BN_free(ctx->srp_ctx.b);
    BN_free(ctx->srp_ctx.v);
    memset(&ctx->srp_ctx, 0, sizeof(ctx->srp_ctx));
    ctx->srp_ctx.strength = SRP_MINIMAL_N;
    return 1;
}

int tls_SRP_CTX_free(struct tls_st *s)
{
    if (s == NULL)
        return 0;
    OPENtls_free(s->srp_ctx.login);
    OPENtls_free(s->srp_ctx.info);
    BN_free(s->srp_ctx.N);
    BN_free(s->srp_ctx.g);
    BN_free(s->srp_ctx.s);
    BN_free(s->srp_ctx.B);
    BN_free(s->srp_ctx.A);
    BN_free(s->srp_ctx.a);
    BN_free(s->srp_ctx.b);
    BN_free(s->srp_ctx.v);
    memset(&s->srp_ctx, 0, sizeof(s->srp_ctx));
    s->srp_ctx.strength = SRP_MINIMAL_N;
    return 1;
}

int tls_SRP_CTX_init(struct tls_st *s)
{
    tls_CTX *ctx;

    if ((s == NULL) || ((ctx = s->ctx) == NULL))
        return 0;

    memset(&s->srp_ctx, 0, sizeof(s->srp_ctx));

    s->srp_ctx.SRP_cb_arg = ctx->srp_ctx.SRP_cb_arg;
    /* set client Hello login callback */
    s->srp_ctx.TLS_ext_srp_username_callback =
        ctx->srp_ctx.TLS_ext_srp_username_callback;
    /* set SRP N/g param callback for verification */
    s->srp_ctx.SRP_verify_param_callback =
        ctx->srp_ctx.SRP_verify_param_callback;
    /* set SRP client passwd callback */
    s->srp_ctx.SRP_give_srp_client_pwd_callback =
        ctx->srp_ctx.SRP_give_srp_client_pwd_callback;

    s->srp_ctx.strength = ctx->srp_ctx.strength;

    if (((ctx->srp_ctx.N != NULL) &&
         ((s->srp_ctx.N = BN_dup(ctx->srp_ctx.N)) == NULL)) ||
        ((ctx->srp_ctx.g != NULL) &&
         ((s->srp_ctx.g = BN_dup(ctx->srp_ctx.g)) == NULL)) ||
        ((ctx->srp_ctx.s != NULL) &&
         ((s->srp_ctx.s = BN_dup(ctx->srp_ctx.s)) == NULL)) ||
        ((ctx->srp_ctx.B != NULL) &&
         ((s->srp_ctx.B = BN_dup(ctx->srp_ctx.B)) == NULL)) ||
        ((ctx->srp_ctx.A != NULL) &&
         ((s->srp_ctx.A = BN_dup(ctx->srp_ctx.A)) == NULL)) ||
        ((ctx->srp_ctx.a != NULL) &&
         ((s->srp_ctx.a = BN_dup(ctx->srp_ctx.a)) == NULL)) ||
        ((ctx->srp_ctx.v != NULL) &&
         ((s->srp_ctx.v = BN_dup(ctx->srp_ctx.v)) == NULL)) ||
        ((ctx->srp_ctx.b != NULL) &&
         ((s->srp_ctx.b = BN_dup(ctx->srp_ctx.b)) == NULL))) {
        tlserr(tls_F_tls_SRP_CTX_INIT, ERR_R_BN_LIB);
        goto err;
    }
    if ((ctx->srp_ctx.login != NULL) &&
        ((s->srp_ctx.login = OPENtls_strdup(ctx->srp_ctx.login)) == NULL)) {
        tlserr(tls_F_tls_SRP_CTX_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((ctx->srp_ctx.info != NULL) &&
        ((s->srp_ctx.info = OPENtls_strdup(ctx->srp_ctx.info)) == NULL)) {
        tlserr(tls_F_tls_SRP_CTX_INIT, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    s->srp_ctx.srp_Mask = ctx->srp_ctx.srp_Mask;

    return 1;
 err:
    OPENtls_free(s->srp_ctx.login);
    OPENtls_free(s->srp_ctx.info);
    BN_free(s->srp_ctx.N);
    BN_free(s->srp_ctx.g);
    BN_free(s->srp_ctx.s);
    BN_free(s->srp_ctx.B);
    BN_free(s->srp_ctx.A);
    BN_free(s->srp_ctx.a);
    BN_free(s->srp_ctx.b);
    BN_free(s->srp_ctx.v);
    memset(&s->srp_ctx, 0, sizeof(s->srp_ctx));
    return 0;
}

int tls_CTX_SRP_CTX_init(struct tls_ctx_st *ctx)
{
    if (ctx == NULL)
        return 0;

    memset(&ctx->srp_ctx, 0, sizeof(ctx->srp_ctx));
    ctx->srp_ctx.strength = SRP_MINIMAL_N;

    return 1;
}

/* server side */
int tls_srp_server_param_with_username(tls *s, int *ad)
{
    unsigned char b[tls_MAX_MASTER_KEY_LENGTH];
    int al;

    *ad = tls_AD_UNKNOWN_PSK_IDENTITY;
    if ((s->srp_ctx.TLS_ext_srp_username_callback != NULL) &&
        ((al =
          s->srp_ctx.TLS_ext_srp_username_callback(s, ad,
                                                   s->srp_ctx.SRP_cb_arg)) !=
         tls_ERROR_NONE))
        return al;

    *ad = tls_AD_INTERNAL_ERROR;
    if ((s->srp_ctx.N == NULL) ||
        (s->srp_ctx.g == NULL) ||
        (s->srp_ctx.s == NULL) || (s->srp_ctx.v == NULL))
        return tls3_AL_FATAL;

    if (RAND_priv_bytes(b, sizeof(b)) <= 0)
        return tls3_AL_FATAL;
    s->srp_ctx.b = BN_bin2bn(b, sizeof(b), NULL);
    OPENtls_cleanse(b, sizeof(b));

    /* Calculate:  B = (kv + g^b) % N  */

    return ((s->srp_ctx.B =
             SRP_Calc_B(s->srp_ctx.b, s->srp_ctx.N, s->srp_ctx.g,
                        s->srp_ctx.v)) !=
            NULL) ? tls_ERROR_NONE : tls3_AL_FATAL;
}

/*
 * If the server just has the raw password, make up a verifier entry on the
 * fly
 */
int tls_set_srp_server_param_pw(tls *s, const char *user, const char *pass,
                                const char *grp)
{
    SRP_gN *GN = SRP_get_default_gN(grp);
    if (GN == NULL)
        return -1;
    s->srp_ctx.N = BN_dup(GN->N);
    s->srp_ctx.g = BN_dup(GN->g);
    BN_clear_free(s->srp_ctx.v);
    s->srp_ctx.v = NULL;
    BN_clear_free(s->srp_ctx.s);
    s->srp_ctx.s = NULL;
    if (!SRP_create_verifier_BN
        (user, pass, &s->srp_ctx.s, &s->srp_ctx.v, GN->N, GN->g))
        return -1;

    return 1;
}

int tls_set_srp_server_param(tls *s, const BIGNUM *N, const BIGNUM *g,
                             BIGNUM *sa, BIGNUM *v, char *info)
{
    if (N != NULL) {
        if (s->srp_ctx.N != NULL) {
            if (!BN_copy(s->srp_ctx.N, N)) {
                BN_free(s->srp_ctx.N);
                s->srp_ctx.N = NULL;
            }
        } else
            s->srp_ctx.N = BN_dup(N);
    }
    if (g != NULL) {
        if (s->srp_ctx.g != NULL) {
            if (!BN_copy(s->srp_ctx.g, g)) {
                BN_free(s->srp_ctx.g);
                s->srp_ctx.g = NULL;
            }
        } else
            s->srp_ctx.g = BN_dup(g);
    }
    if (sa != NULL) {
        if (s->srp_ctx.s != NULL) {
            if (!BN_copy(s->srp_ctx.s, sa)) {
                BN_free(s->srp_ctx.s);
                s->srp_ctx.s = NULL;
            }
        } else
            s->srp_ctx.s = BN_dup(sa);
    }
    if (v != NULL) {
        if (s->srp_ctx.v != NULL) {
            if (!BN_copy(s->srp_ctx.v, v)) {
                BN_free(s->srp_ctx.v);
                s->srp_ctx.v = NULL;
            }
        } else
            s->srp_ctx.v = BN_dup(v);
    }
    if (info != NULL) {
        if (s->srp_ctx.info)
            OPENtls_free(s->srp_ctx.info);
        if ((s->srp_ctx.info = OPENtls_strdup(info)) == NULL)
            return -1;
    }

    if (!(s->srp_ctx.N) ||
        !(s->srp_ctx.g) || !(s->srp_ctx.s) || !(s->srp_ctx.v))
        return -1;

    return 1;
}

int srp_generate_server_master_secret(tls *s)
{
    BIGNUM *K = NULL, *u = NULL;
    int ret = -1, tmp_len = 0;
    unsigned char *tmp = NULL;

    if (!SRP_Verify_A_mod_N(s->srp_ctx.A, s->srp_ctx.N))
        goto err;
    if ((u = SRP_Calc_u(s->srp_ctx.A, s->srp_ctx.B, s->srp_ctx.N)) == NULL)
        goto err;
    if ((K = SRP_Calc_server_key(s->srp_ctx.A, s->srp_ctx.v, u, s->srp_ctx.b,
                                 s->srp_ctx.N)) == NULL)
        goto err;

    tmp_len = BN_num_bytes(K);
    if ((tmp = OPENtls_malloc(tmp_len)) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_SRP_GENERATE_SERVER_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_bn2bin(K, tmp);
    /* Calls tlsfatal() as required */
    ret = tls_generate_master_secret(s, tmp, tmp_len, 1);
 err:
    BN_clear_free(K);
    BN_clear_free(u);
    return ret;
}

/* client side */
int srp_generate_client_master_secret(tls *s)
{
    BIGNUM *x = NULL, *u = NULL, *K = NULL;
    int ret = -1, tmp_len = 0;
    char *passwd = NULL;
    unsigned char *tmp = NULL;

    /*
     * Checks if b % n == 0
     */
    if (SRP_Verify_B_mod_N(s->srp_ctx.B, s->srp_ctx.N) == 0
            || (u = SRP_Calc_u(s->srp_ctx.A, s->srp_ctx.B, s->srp_ctx.N))
               == NULL
            || s->srp_ctx.SRP_give_srp_client_pwd_callback == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_SRP_GENERATE_CLIENT_MASTER_SECRET, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((passwd = s->srp_ctx.SRP_give_srp_client_pwd_callback(s,
                                                      s->srp_ctx.SRP_cb_arg))
            == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_SRP_GENERATE_CLIENT_MASTER_SECRET,
                 tls_R_CALLBACK_FAILED);
        goto err;
    }
    if ((x = SRP_Calc_x(s->srp_ctx.s, s->srp_ctx.login, passwd)) == NULL
            || (K = SRP_Calc_client_key(s->srp_ctx.N, s->srp_ctx.B,
                                        s->srp_ctx.g, x,
                                        s->srp_ctx.a, u)) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_SRP_GENERATE_CLIENT_MASTER_SECRET, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    tmp_len = BN_num_bytes(K);
    if ((tmp = OPENtls_malloc(tmp_len)) == NULL) {
        tlsfatal(s, tls_AD_INTERNAL_ERROR,
                 tls_F_SRP_GENERATE_CLIENT_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_bn2bin(K, tmp);
    /* Calls tlsfatal() as required */
    ret = tls_generate_master_secret(s, tmp, tmp_len, 1);
 err:
    BN_clear_free(K);
    BN_clear_free(x);
    if (passwd != NULL)
        OPENtls_clear_free(passwd, strlen(passwd));
    BN_clear_free(u);
    return ret;
}

int srp_verify_server_param(tls *s)
{
    SRP_CTX *srp = &s->srp_ctx;
    /*
     * Sanity check parameters: we can quickly check B % N == 0 by checking B
     * != 0 since B < N
     */
    if (BN_ucmp(srp->g, srp->N) >= 0 || BN_ucmp(srp->B, srp->N) >= 0
        || BN_is_zero(srp->B)) {
        tlsfatal(s, tls_AD_ILLEGAL_PARAMETER, tls_F_SRP_VERIFY_SERVER_PARAM,
                 tls_R_BAD_DATA);
        return 0;
    }

    if (BN_num_bits(srp->N) < srp->strength) {
        tlsfatal(s, tls_AD_INSUFFICIENT_SECURITY, tls_F_SRP_VERIFY_SERVER_PARAM,
                 tls_R_INSUFFICIENT_SECURITY);
        return 0;
    }

    if (srp->SRP_verify_param_callback) {
        if (srp->SRP_verify_param_callback(s, srp->SRP_cb_arg) <= 0) {
            tlsfatal(s, tls_AD_INSUFFICIENT_SECURITY,
                     tls_F_SRP_VERIFY_SERVER_PARAM,
                     tls_R_CALLBACK_FAILED);
            return 0;
        }
    } else if (!SRP_check_known_gN_param(srp->g, srp->N)) {
        tlsfatal(s, tls_AD_INSUFFICIENT_SECURITY, tls_F_SRP_VERIFY_SERVER_PARAM,
                 tls_R_INSUFFICIENT_SECURITY);
        return 0;
    }

    return 1;
}

int SRP_Calc_A_param(tls *s)
{
    unsigned char rnd[tls_MAX_MASTER_KEY_LENGTH];

    if (RAND_priv_bytes(rnd, sizeof(rnd)) <= 0)
        return 0;
    s->srp_ctx.a = BN_bin2bn(rnd, sizeof(rnd), s->srp_ctx.a);
    OPENtls_cleanse(rnd, sizeof(rnd));

    if (!(s->srp_ctx.A = SRP_Calc_A(s->srp_ctx.a, s->srp_ctx.N, s->srp_ctx.g)))
        return 0;

    return 1;
}

BIGNUM *tls_get_srp_g(tls *s)
{
    if (s->srp_ctx.g != NULL)
        return s->srp_ctx.g;
    return s->ctx->srp_ctx.g;
}

BIGNUM *tls_get_srp_N(tls *s)
{
    if (s->srp_ctx.N != NULL)
        return s->srp_ctx.N;
    return s->ctx->srp_ctx.N;
}

char *tls_get_srp_username(tls *s)
{
    if (s->srp_ctx.login != NULL)
        return s->srp_ctx.login;
    return s->ctx->srp_ctx.login;
}

char *tls_get_srp_userinfo(tls *s)
{
    if (s->srp_ctx.info != NULL)
        return s->srp_ctx.info;
    return s->ctx->srp_ctx.info;
}

# define tls1_ctx_ctrl tls3_ctx_ctrl
# define tls1_ctx_callback_ctrl tls3_ctx_callback_ctrl

int tls_CTX_set_srp_username(tls_CTX *ctx, char *name)
{
    return tls1_ctx_ctrl(ctx, tls_CTRL_SET_TLS_EXT_SRP_USERNAME, 0, name);
}

int tls_CTX_set_srp_password(tls_CTX *ctx, char *password)
{
    return tls1_ctx_ctrl(ctx, tls_CTRL_SET_TLS_EXT_SRP_PASSWORD, 0, password);
}

int tls_CTX_set_srp_strength(tls_CTX *ctx, int strength)
{
    return tls1_ctx_ctrl(ctx, tls_CTRL_SET_TLS_EXT_SRP_STRENGTH, strength,
                         NULL);
}

int tls_CTX_set_srp_verify_param_callback(tls_CTX *ctx,
                                          int (*cb) (tls *, void *))
{
    return tls1_ctx_callback_ctrl(ctx, tls_CTRL_SET_SRP_VERIFY_PARAM_CB,
                                  (void (*)(void))cb);
}

int tls_CTX_set_srp_cb_arg(tls_CTX *ctx, void *arg)
{
    return tls1_ctx_ctrl(ctx, tls_CTRL_SET_SRP_ARG, 0, arg);
}

int tls_CTX_set_srp_username_callback(tls_CTX *ctx,
                                      int (*cb) (tls *, int *, void *))
{
    return tls1_ctx_callback_ctrl(ctx, tls_CTRL_SET_TLS_EXT_SRP_USERNAME_CB,
                                  (void (*)(void))cb);
}

int tls_CTX_set_srp_client_pwd_callback(tls_CTX *ctx,
                                        char *(*cb) (tls *, void *))
{
    return tls1_ctx_callback_ctrl(ctx, tls_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB,
                                  (void (*)(void))cb);
}

#endif
