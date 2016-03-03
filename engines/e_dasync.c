/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#if (defined(OPENSSL_SYS_UNIX) || defined(OPENSSL_SYS_CYGWIN)) && defined(OPENSSL_THREADS)
# undef ASYNC_POSIX
# define ASYNC_POSIX
# include <unistd.h>
#elif defined(_WIN32)
# undef ASYNC_WIN
# define ASYNC_WIN
# include <windows.h>
#endif

#define DASYNC_LIB_NAME "DASYNC"
#include "e_dasync_err.c"

/* Engine Id and Name */
static const char *engine_dasync_id = "dasync";
static const char *engine_dasync_name = "Dummy Async engine support";


/* Engine Lifetime functions */
static int dasync_destroy(ENGINE *e);
static int dasync_init(ENGINE *e);
static int dasync_finish(ENGINE *e);
void engine_load_dasync_internal(void);


/* Set up digests. Just SHA1 for now */
static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

static void dummy_pause_job(void);

/* SHA1 */
static int dasync_sha1_init(EVP_MD_CTX *ctx);
static int dasync_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int dasync_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *dasync_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, dasync_sha1_init)
            || !EVP_MD_meth_set_update(md, dasync_sha1_update)
            || !EVP_MD_meth_set_final(md, dasync_sha1_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}
static void destroy_digests(void)
{
    EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
}
static int dasync_digest_nids(const int **nids)
{
    static int digest_nids[2] = { 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = dasync_sha1()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* RSA */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                              BN_CTX *ctx);

static int dasync_rsa_init(RSA *rsa);
static int dasync_rsa_finish(RSA *rsa);

static RSA_METHOD dasync_rsa_method = {
    "Dummy Async RSA method",
    dasync_pub_enc,             /* pub_enc */
    dasync_pub_dec,             /* pub_dec */
    dasync_rsa_priv_enc,        /* priv_enc */
    dasync_rsa_priv_dec,        /* priv_dec */
    dasync_rsa_mod_exp,         /* rsa_mod_exp */
    BN_mod_exp_mont,            /* bn_mod_exp */
    dasync_rsa_init,            /* init */
    dasync_rsa_finish,          /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    0,                          /* rsa_sign */
    0,                          /* rsa_verify */
    NULL                        /* rsa_keygen */
};


static int bind_dasync(ENGINE *e)
{
    /* Ensure the dasync error handling is set up */
    ERR_load_DASYNC_strings();

    if (!ENGINE_set_id(e, engine_dasync_id)
        || !ENGINE_set_name(e, engine_dasync_name)
        || !ENGINE_set_RSA(e, &dasync_rsa_method)
        || !ENGINE_set_digests(e, dasync_digests)
        || !ENGINE_set_destroy_function(e, dasync_destroy)
        || !ENGINE_set_init_function(e, dasync_init)
        || !ENGINE_set_finish_function(e, dasync_finish)) {
        DASYNCerr(DASYNC_F_BIND_DASYNC, DASYNC_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_dasync_id) != 0))
        return 0;
    if (!bind_dasync(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static ENGINE *engine_dasync(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_dasync(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_dasync_internal(void)
{
    ENGINE *toadd = engine_dasync();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

static int dasync_init(ENGINE *e)
{
    return 1;
}


static int dasync_finish(ENGINE *e)
{
    return 1;
}


static int dasync_destroy(ENGINE *e)
{
    destroy_digests();
    ERR_unload_DASYNC_strings();
    return 1;
}

static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return dasync_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_sha1:
        *digest = dasync_sha1();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static void wait_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                         OSSL_ASYNC_FD readfd, void *pvwritefd)
{
    OSSL_ASYNC_FD *pwritefd = (OSSL_ASYNC_FD *)pvwritefd;
#if defined(ASYNC_WIN)
    CloseHandle(readfd);
    CloseHandle(*pwritefd);
#elif defined(ASYNC_POSIX)
    close(readfd);
    close(*pwritefd);
#endif
    OPENSSL_free(pwritefd);
}

#define DUMMY_CHAR 'X'

static void dummy_pause_job(void) {
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    OSSL_ASYNC_FD pipefds[2] = {0, 0};
    OSSL_ASYNC_FD *writefd;
#if defined(ASYNC_WIN)
    DWORD numwritten, numread;
    char buf = DUMMY_CHAR;
#elif defined(ASYNC_POSIX)
    char buf = DUMMY_CHAR;
#endif

    if ((job = ASYNC_get_current_job()) == NULL)
        return;

    waitctx = ASYNC_get_wait_ctx(job);

    if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_dasync_id, &pipefds[0],
                              (void **)&writefd)) {
        pipefds[1] = *writefd;
    } else {
        writefd = OPENSSL_malloc(sizeof(*writefd));
        if (writefd == NULL)
            return;
#if defined(ASYNC_WIN)
        if (CreatePipe(&pipefds[0], &pipefds[1], NULL, 256) == 0) {
            OPENSSL_free(writefd);
            return;
        }
#elif defined(ASYNC_POSIX)
        if (pipe(pipefds) != 0) {
            OPENSSL_free(writefd);
            return;
        }
#endif
        *writefd = pipefds[1];

        if(!ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_dasync_id, pipefds[0],
                                       writefd, wait_cleanup)) {
            wait_cleanup(waitctx, engine_dasync_id, pipefds[0], writefd);
            return;
        }
    }
    /*
     * In the Dummy async engine we are cheating. We signal that the job
     * is complete by waking it before the call to ASYNC_pause_job(). A real
     * async engine would only wake when the job was actually complete
     */
#if defined(ASYNC_WIN)
    WriteFile(pipefds[1], &buf, 1, &numwritten, NULL);
#elif defined(ASYNC_POSIX)
    write(pipefds[1], &buf, 1);
#endif

    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

    /* Clear the wake signal */
#if defined(ASYNC_WIN)
    ReadFile(pipefds[0], &buf, 1, &numread, NULL);
#elif defined(ASYNC_POSIX)
    read(pipefds[0], &buf, 1);
#endif
}

/*
 * SHA1 implementation. At the moment we just defer to the standard
 * implementation
 */
#undef data
#define data(ctx) ((SHA_CTX *)EVP_MD_CTX_md_data(ctx))
static int dasync_sha1_init(EVP_MD_CTX *ctx)
{
    dummy_pause_job();

    return SHA1_Init(data(ctx));
}

static int dasync_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    dummy_pause_job();

    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int dasync_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    dummy_pause_job();

    return SHA1_Final(md, data(ctx));
}

/*
 * RSA implementation
 */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_pub_enc(flen, from, to, rsa, padding);
}

static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_pub_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_priv_enc(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_priv_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_mod_exp(r0, I, rsa, ctx);
}

static int dasync_rsa_init(RSA *rsa)
{
    return RSA_PKCS1_OpenSSL()->init(rsa);
}
static int dasync_rsa_finish(RSA *rsa)
{
    return RSA_PKCS1_OpenSSL()->finish(rsa);
}
