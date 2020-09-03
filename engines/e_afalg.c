/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

/* Required for vmsplice */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/nelem.h"

#include <sys/socket.h>
#include <linux/version.h>
#define K_MAJ   4
#define K_MIN1  1
#define K_MIN2  0
#if LINUX_VERSION_CODE < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2) || \
    !defined(AF_ALG)
# ifndef PEDANTIC
#  warning "AFALG ENGINE requires Kernel Headers >= 4.1.0"
#  warning "Skipping Compilation of AFALG engine"
# endif
void engine_load_afalg_int(void);
void engine_load_afalg_int(void)
{
}
#else

# include <linux/if_alg.h>
# include <fcntl.h>
# include <sys/utsname.h>

# include <linux/aio_abi.h>
# include <sys/syscall.h>
# include <errno.h>

# include "e_afalg.h"
# include "e_afalg_err.c"

# ifndef SOL_ALG
#  define SOL_ALG 279
# endif

# ifdef ALG_ZERO_COPY
#  ifndef SPLICE_F_GIFT
#   define SPLICE_F_GIFT    (0x08)
#  endif
# endif

# define ALG_AES_IV_LEN 16
# define ALG_IV_LEN(len) (sizeof(struct af_alg_iv) + (len))
# define ALG_OP_TYPE     unsigned int
# define ALG_OP_LEN      (sizeof(ALG_OP_TYPE))

# ifdef OPENSSL_NO_DYNAMIC_ENGINE
void engine_load_afalg_int(void);
# endif

/* Local Linkage Functions */
static int afalg_init_aio(afalg_aio *aio);
static int afalg_fin_cipher_aio(afalg_aio *ptr, int sfd,
                                unsigned char *buf, size_t len);
static int afalg_create_sk(EVP_CIPHER_CTX *ctx, const char *ciphertype,
                           const char *ciphername, const unsigned char *key);
static int afalg_destroy(ENGINE *e);
static int afalg_init(ENGINE *e);
static int afalg_finish(ENGINE *e);
static const EVP_CIPHER *afalg_aes_cipher(int nid);
static const EVP_CIPHER *afalg_aes_aead(int nid);
static aes_handles *get_cipher_handle(int nid);
static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid);
static int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
static int afalg_aead_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc);
static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl);
static int afalg_do_aead(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl);
static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx);
static int afalg_aead_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                           void *ptr);
static int afalg_chk_platform(void);
static int chk_gcm_kernel_supp(void);
static int aes_gcm_nontls_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t len);
static int aes_gcm_nontls_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len);
static int aes_gcm_nontls_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len);
static int afalg_start_nontlsaead_sk(EVP_CIPHER_CTX *ctx, struct iovec *iov,
                                     int iovlen, const unsigned char *iv,
                                     int inl, unsigned int enc);
static int afalg_fin_nontlsaead_aio(EVP_CIPHER_CTX *ctx, int sfd,
                                    struct iovec *iov, int iovlen);

/* Engine Id and Name */
static const char *engine_afalg_id = "afalg";
static const char *engine_afalg_name = "AFALG engine support";

static int afalg_aes_nids[] = {
    NID_aes_128_cbc,
    NID_aes_192_cbc,
    NID_aes_256_cbc,
    NID_aes_128_gcm,
    NID_aes_192_gcm,
    NID_aes_256_gcm
};

static aes_handles aes_handle[] = {{AES_KEY_SIZE_128, NULL},
                                   {AES_KEY_SIZE_192, NULL},
                                   {AES_KEY_SIZE_256, NULL},
                                   {AES_KEY_SIZE_128, NULL},
                                   {AES_KEY_SIZE_192, NULL},
                                   {AES_KEY_SIZE_256, NULL}};

static ossl_inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static ossl_inline int eventfd(int n)
{
    return syscall(__NR_eventfd2, n, 0);
}

static ossl_inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static ossl_inline int io_read(aio_context_t ctx, long n, struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}

static ossl_inline int io_getevents(aio_context_t ctx, long min, long max,
                               struct io_event *events,
                               struct timespec *timeout)
{
#if defined(__NR_io_getevents)
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
#elif defined(__NR_io_pgetevents_time64)
    /* Let's only support the 64 suffix syscalls for 64-bit time_t.
     * This simplifies the code for us as we don't need to use a 64-bit
     * version of timespec with a 32-bit time_t and handle converting
     * between 64-bit and 32-bit times and check for overflows.
     */
    if (sizeof(timeout->tv_sec) == 8)
        return syscall(__NR_io_pgetevents_time64, ctx, min, max, events, timeout, NULL);
    else {
        errno = ENOSYS;
        return -1;
    }
#else
# error "We require either the io_getevents syscall or __NR_io_pgetevents_time64."
#endif
}

static void afalg_waitfd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
                                 OSSL_ASYNC_FD waitfd, void *custom)
{
    close(waitfd);
}

static int afalg_setup_async_event_notification(afalg_aio *aio)
{
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    void *custom = NULL;
    int ret;

    if ((job = ASYNC_get_current_job()) != NULL) {
        /* Async mode */
        waitctx = ASYNC_get_wait_ctx(job);
        if (waitctx == NULL) {
            ALG_WARN("%s(%d): ASYNC_get_wait_ctx error", __FILE__, __LINE__);
            return 0;
        }
        /* Get waitfd from ASYNC_WAIT_CTX if it is already set */
        ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_afalg_id,
                                    &aio->efd, &custom);
        if (ret == 0) {
            /*
             * waitfd is not set in ASYNC_WAIT_CTX, create a new one
             * and set it. efd will be signaled when AIO operation completes
             */
            aio->efd = eventfd(0);
            if (aio->efd == -1) {
                ALG_PERR("%s(%d): Failed to get eventfd : ", __FILE__,
                         __LINE__);
                AFALGerr(AFALG_F_AFALG_SETUP_ASYNC_EVENT_NOTIFICATION,
                         AFALG_R_EVENTFD_FAILED);
                return 0;
            }
            ret = ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_afalg_id,
                                             aio->efd, custom,
                                             afalg_waitfd_cleanup);
            if (ret == 0) {
                ALG_WARN("%s(%d): Failed to set wait fd", __FILE__, __LINE__);
                close(aio->efd);
                return 0;
            }
            /* make fd non-blocking in async mode */
            if (fcntl(aio->efd, F_SETFL, O_NONBLOCK) != 0) {
                ALG_WARN("%s(%d): Failed to set event fd as NONBLOCKING",
                         __FILE__, __LINE__);
            }
        }
        aio->mode = MODE_ASYNC;
    } else {
        /* Sync mode */
        aio->efd = eventfd(0);
        if (aio->efd == -1) {
            ALG_PERR("%s(%d): Failed to get eventfd : ", __FILE__, __LINE__);
            AFALGerr(AFALG_F_AFALG_SETUP_ASYNC_EVENT_NOTIFICATION,
                     AFALG_R_EVENTFD_FAILED);
            return 0;
        }
        aio->mode = MODE_SYNC;
    }
    return 1;
}

static void afalg_set_aad_sk(struct cmsghdr *cmsg, const unsigned int len)
{
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned int));
    memcpy(CMSG_DATA(cmsg), &len, sizeof(unsigned int));
}

static int afalg_init_aio(afalg_aio *aio)
{
    int r = -1;

    /* Initialise for AIO */
    aio->aio_ctx = 0;
    r = io_setup(MAX_INFLIGHTS, &aio->aio_ctx);
    if (r < 0) {
        ALG_PERR("%s(%d): io_setup error : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_INIT_AIO, AFALG_R_IO_SETUP_FAILED);
        return 0;
    }

    memset(aio->cbt, 0, sizeof(aio->cbt));
    aio->efd = -1;
    aio->mode = MODE_UNINIT;

    return 1;
}

static int afalg_fin_cipher_aio(afalg_aio *aio, int sfd, unsigned char *buf,
                                size_t len)
{
    int r;
    int retry = 0;
    unsigned int done = 0;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];
    u_int64_t eval = 0;

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    /* if efd has not been initialised yet do it here */
    if (aio->mode == MODE_UNINIT) {
        r = afalg_setup_async_event_notification(aio);
        if (r == 0)
            return 0;
    }

    cb = &(aio->cbt[0 % MAX_INFLIGHTS]);
    memset(cb, '\0', sizeof(*cb));
    cb->aio_fildes = sfd;
    cb->aio_lio_opcode = IOCB_CMD_PREAD;
    /*
     * The pointer has to be converted to unsigned value first to avoid
     * sign extension on cast to 64 bit value in 32-bit builds
     */
    cb->aio_buf = (size_t)buf;
    cb->aio_offset = 0;
    cb->aio_data = 0;
    cb->aio_nbytes = len;
    cb->aio_flags = IOCB_FLAG_RESFD;
    cb->aio_resfd = aio->efd;

    /*
     * Perform AIO read on AFALG socket, this in turn performs an async
     * crypto operation in kernel space
     */
    r = io_read(aio->aio_ctx, 1, &cb);
    if (r < 0) {
        ALG_PWARN("%s(%d): io_read failed : ", __FILE__, __LINE__);
        return 0;
    }

    do {
        /* While AIO read is being performed pause job */
        ASYNC_pause_job();

        /* Check for completion of AIO read */
        r = read(aio->efd, &eval, sizeof(eval));
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            ALG_PERR("%s(%d): read failed for event fd : ", __FILE__, __LINE__);
            return 0;
        } else if (r == 0 || eval <= 0) {
            ALG_WARN("%s(%d): eventfd read %d bytes, eval = %lu\n", __FILE__,
                     __LINE__, r, eval);
        }
        if (eval > 0) {

            /* Get results of AIO read */
            r = io_getevents(aio->aio_ctx, 1, MAX_INFLIGHTS,
                             events, &timeout);
            if (r > 0) {
                /*
                 * events.res indicates the actual status of the operation.
                 * Handle the error condition first.
                 */
                if (events[0].res < 0) {
                    /*
                     * Underlying operation cannot be completed at the time
                     * of previous submission. Resubmit for the operation.
                     */
                    if (events[0].res == -EBUSY && retry++ < 3) {
                        r = io_read(aio->aio_ctx, 1, &cb);
                        if (r < 0) {
                            ALG_PERR("%s(%d): retry %d for io_read failed : ",
                                     __FILE__, __LINE__, retry);
                            return 0;
                        }
                        continue;
                    } else {
                        /*
                         * Retries exceed for -EBUSY or unrecoverable error
                         * condition for this instance of operation.
                         */
                        ALG_WARN
                            ("%s(%d): Crypto Operation failed with code %lld\n",
                             __FILE__, __LINE__, events[0].res);
                        return 0;
                    }
                }
                /* Operation successful. */
                done = 1;
            } else if (r < 0) {
                ALG_PERR("%s(%d): io_getevents failed : ", __FILE__, __LINE__);
                return 0;
            } else {
                ALG_WARN("%s(%d): io_geteventd read 0 bytes\n", __FILE__,
                         __LINE__);
            }
        }
    } while (!done);

    return 1;
}

static int afalg_fin_nontlsaead_aio(EVP_CIPHER_CTX *ctx, int sfd,
                                    struct iovec *iov, int iovlen)
{
    afalg_aead_ctx *gctx;
    afalg_ctx *actx;
    afalg_aio *aio;
    int retry = 0;
    unsigned int done = 0;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];
    u_int64_t eval = 0;
    int r;

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
    gctx = (afalg_aead_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    actx = (afalg_ctx *)&gctx->ctx;
    aio = &actx->aio;

    /* if efd has not been initialised yet do it here */
    if (aio->mode == MODE_UNINIT) {
        r = afalg_setup_async_event_notification(aio);
        if (r == 0)
            return 0;
    }

    cb = &(aio->cbt[0 % MAX_INFLIGHTS]);
    memset(cb, '\0', sizeof(*cb));
    cb->aio_fildes = sfd;
    cb->aio_lio_opcode = IOCB_CMD_PREADV;
    /*
     * The pointer has to be converted to unsigned value first to avoid
     * sign extension on cast to 64 bit value in 32-bit builds
     */
    cb->aio_buf = (size_t)iov;
    cb->aio_offset = 0;
    cb->aio_data = 0;
    cb->aio_nbytes = iovlen;
    cb->aio_flags = IOCB_FLAG_RESFD;
    cb->aio_resfd = aio->efd;

    /*
     * Perform AIO read on AFALG socket, this in turn performs an async
     * crypto operation in kernel space
     */
    r = io_read(aio->aio_ctx, 1, &cb);
    if (r < 0) {
        ALG_PWARN("%s(%d): io_read failed : ", __FILE__, __LINE__);
        return 0;
    }

    do {
        /* While AIO read is being performed pause job */
        ASYNC_pause_job();

        /* Check for completion of AIO read */
        r = read(aio->efd, &eval, sizeof(eval));
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            ALG_PERR("%s(%d): read failed for event fd : ", __FILE__, __LINE__);
            return 0;
        } else if (r == 0 || eval <= 0) {
            ALG_WARN("%s: eventfd read %d bytes, eval = %lu\n", __func__, r,
                     eval);
        }
        if (eval > 0) {

            /* Get results of AIO read */
            r = io_getevents(aio->aio_ctx, 1, MAX_INFLIGHTS,
                             events, &timeout);
            if (r > 0) {
                /*
                 * events.res indicates the actual status of the operation.
                 * Handle the error condition first.
                 */
                if (events[0].res < 0) {
                    /*
                     * Underlying operation cannot be completed at the time
                     * of previous submission. Resubmit for the operation.
                     */
                    if (events[0].res == -EBUSY && retry++ < 3) {
                        r = io_read(aio->aio_ctx, 1, &cb);
                        if (r < 0) {
                            ALG_PERR("%s(%d): retry %d for io_read failed : ",
                                     __FILE__, __LINE__, retry);
                            return 0;
                        }
                        continue;
                    } else if (events[0].res == -EBADMSG && gctx->taglen
                               && !EVP_CIPHER_CTX_encrypting(ctx)) {
                        ALG_WARN
                        ("%s: Crypto Operation failed with code %lld\n",
                         __func__, events[0].res);
                        return -EBADMSG;
                    } else {
                        /*
                         * Retries exceed for -EBUSY or unrecoverable error
                         * condition for this instance of operation.
                         */
                        ALG_WARN("%s: Crypto Operation failed with code %lld\n",
                                 __func__, events[0].res);
                        return 0;
                    }
                }
                /* Operation successful. */
                done = 1;
            } else if (r < 0) {
                ALG_PERR("%s(%d); io_getevents failed : ", __FILE__, __LINE__);
                return 0;
            } else {
                ALG_WARN("%s: io_geteventd read 0 bytes\n", __func__);
            }
        }
    } while (!done);

    return 1;
}

static ossl_inline void afalg_set_op_sk(struct cmsghdr *cmsg,
                                        const ALG_OP_TYPE op)
{
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(ALG_OP_LEN);
    memcpy(CMSG_DATA(cmsg), &op, ALG_OP_LEN);
}

static void afalg_set_iv_sk(struct cmsghdr *cmsg, const unsigned char *iv,
                            const unsigned int len)
{
    struct af_alg_iv *aiv;

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(ALG_IV_LEN(len));
    aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = len;
    memcpy(aiv->iv, iv, len);
}

static ossl_inline int afalg_set_key(afalg_ctx *actx, const unsigned char *key,
                                     const int klen)
{
    int ret;
    ret = setsockopt(actx->bfd, SOL_ALG, ALG_SET_KEY, key, klen);
    if (ret < 0) {
        ALG_PERR("%s(%d): Failed to set socket option : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_SET_KEY, AFALG_R_SOCKET_SET_KEY_FAILED);
        return 0;
    }
    return 1;
}

static ossl_inline int afalg_set_aad(EVP_CIPHER_CTX *ctx)
{
    afalg_ctx *actx = (afalg_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret;

    ret = setsockopt(actx->bfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
                     EVP_GCM_TLS_TAG_LEN);
    if (ret < 0) {
        ALG_PERR("%s(%d): Failed to set socket option : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_SET_AAD, AFALG_R_SOCKET_SET_AAD_FAILED);
        return 0;
    }
    return 1;
}

static int afalg_create_sk(EVP_CIPHER_CTX *ctx, const char *ciphertype,
                           const char *ciphername, const unsigned char *key)
{
    struct sockaddr_alg sa;
    int r = -1;
    const EVP_CIPHER *cipher;
    afalg_ctx *actx;

    cipher = EVP_CIPHER_CTX_cipher(ctx);

    actx = EVP_CIPHER_CTX_get_cipher_data(ctx);

    actx->bfd = actx->sfd = -1;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *) sa.salg_type, ciphertype, sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *) sa.salg_name, ciphername, sizeof(sa.salg_name));

    actx->bfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (actx->bfd == -1) {
        ALG_PERR("%s(%d): Failed to open socket : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_CREATE_SK, AFALG_R_SOCKET_CREATE_FAILED);
        goto err;
    }

    r = bind(actx->bfd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0) {
        ALG_PERR("%s(%d): Failed to bind socket : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_CREATE_SK, AFALG_R_SOCKET_BIND_FAILED);
        goto err;
    }
    if (afalg_set_key(actx, key, EVP_CIPHER_CTX_key_length(ctx)) < 1) {
        ALG_PERR("%s(%d): Socket setkey Failed : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_CREATE_SK, AFALG_R_SOCKET_SET_KEY_FAILED);
        goto err;
    }
    if (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        if (afalg_set_aad(ctx) < 1)
            return 0;
    }

    actx->sfd = accept(actx->bfd, NULL, 0);
    if (actx->sfd < 0) {
        ALG_PERR("%s(%d): Socket Accept Failed : ", __FILE__, __LINE__);
        AFALGerr(AFALG_F_AFALG_CREATE_SK, AFALG_R_SOCKET_ACCEPT_FAILED);
        goto err;
    }

    return 1;

 err:
    if (actx->bfd >= 0)
        close(actx->bfd);
    if (actx->sfd >= 0)
        close(actx->sfd);
    actx->bfd = actx->sfd = -1;
    return 0;
}

static int afalg_start_cipher_sk(afalg_ctx *actx, const unsigned char *in,
                                 size_t inl, const unsigned char *iv,
                                 unsigned int enc)
{
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    struct iovec iov;
    ssize_t sbytes;
# ifdef ALG_ZERO_COPY
    int ret;
# endif
    char cbuf[CMSG_SPACE(ALG_IV_LEN(ALG_AES_IV_LEN)) + CMSG_SPACE(ALG_OP_LEN)];

    memset(cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    /*
     * cipher direction (i.e. encrypt or decrypt) and iv are sent to the
     * kernel as part of sendmsg()'s ancillary data
     */
    cmsg = CMSG_FIRSTHDR(&msg);
    afalg_set_op_sk(cmsg, enc);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    afalg_set_iv_sk(cmsg, iv, ALG_AES_IV_LEN);

    /* iov that describes input data */
    iov.iov_base = (unsigned char *)in;
    iov.iov_len = inl;

    msg.msg_flags = MSG_MORE;

# ifdef ALG_ZERO_COPY
    /*
     * ZERO_COPY mode
     * Works best when buffer is 4k aligned
     * OPENS: out of place processing (i.e. out != in)
     */

    /* Input data is not sent as part of call to sendmsg() */
    msg.msg_iovlen = 0;
    msg.msg_iov = NULL;

    /* Sendmsg() sends iv and cipher direction to the kernel */
    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s(%d): sendmsg failed for zero copy cipher operation : ",
                 __FILE__, __LINE__);
        return 0;
    }

    /*
     * vmsplice and splice are used to pin the user space input buffer for
     * kernel space processing avoiding copies from user to kernel space
     */
    ret = vmsplice(actx->zc_pipe[1], &iov, 1, SPLICE_F_GIFT);
    if (ret < 0) {
        ALG_PERR("%s(%d): vmsplice failed : ", __FILE__, __LINE__);
        return 0;
    }

    ret = splice(actx->zc_pipe[0], NULL, actx->sfd, NULL, inl, 0);
    if (ret < 0) {
        ALG_PERR("%s(%d): splice failed : ", __FILE__, __LINE__);
        return 0;
    }
# else
    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;

    /* Sendmsg() sends iv, cipher direction and input data to the kernel */
    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s(%d): sendmsg failed for cipher operation : ", __FILE__,
                 __LINE__);
        return 0;
    }

    if (sbytes != (ssize_t) inl) {
        ALG_WARN("Cipher operation send bytes %zd != inlen %zd\n", sbytes,
                 inl);
        return 0;
    }
# endif

    return 1;
}

static int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ciphertype;
    int ivlen = 0;
    int ret;
    afalg_ctx *actx;
    const char *ciphername;
    const char *algtype;

    if (ctx == NULL || key == NULL) {
        ALG_WARN("%s(%d): Null Parameter\n", __FILE__, __LINE__);
        return 0;
    }

    if (EVP_CIPHER_CTX_cipher(ctx) == NULL) {
        ALG_WARN("%s(%d): Cipher object NULL\n", __FILE__, __LINE__);
        return 0;
    }

    actx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL) {
        ALG_WARN("%s(%d): Cipher data NULL\n", __FILE__, __LINE__);
        return 0;
    }

    ciphertype = EVP_CIPHER_CTX_nid(ctx);
    switch (ciphertype) {
    case NID_aes_128_cbc:
    case NID_aes_192_cbc:
    case NID_aes_256_cbc:
        ciphername = "cbc(aes)";
        algtype = "skcipher";
        ivlen = ALG_AES_IV_LEN;
        break;
    case NID_aes_128_gcm:
    case NID_aes_192_gcm:
    case NID_aes_256_gcm:
        ciphername = "gcm(aes)";
        algtype = "aead";
        ivlen = AES_GCM_IV_LEN;

        break;
    default:
        ALG_WARN("%s(%d): Unsupported Cipher type %d\n", __FILE__, __LINE__,
                 ciphertype);
        return 0;
    }

    if (ivlen != EVP_CIPHER_CTX_iv_length(ctx)) {
        ALG_WARN("%s(%d): Unsupported IV length :%d\n", __FILE__, __LINE__,
                 EVP_CIPHER_CTX_iv_length(ctx));
        return 0;
    }

    /* Setup AFALG socket for crypto processing */
    ret = afalg_create_sk(ctx, algtype, ciphername, key);
    if (ret < 1)
        return 0;

    /* Setup AIO ctx to allow async AFALG crypto processing */
    if (afalg_init_aio(&actx->aio) == 0)
        goto err;

# ifdef ALG_ZERO_COPY
    pipe(actx->zc_pipe);
# endif

    actx->init_done = MAGIC_INIT_NUM;

    return 1;

 err:
    close(actx->sfd);
    close(actx->bfd);
    return 0;
}

static int afalg_aead_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc)
{
    afalg_aead_ctx *actx = (afalg_aead_ctx *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (!iv && !key)
        return 1;

    if (key) {
        afalg_cipher_init(ctx, key, iv, enc);
        if (iv == NULL && actx->iv_set)
            iv = actx->iv;
        if (iv) {
            memcpy(actx->iv, iv, actx->ivlen);
            actx->iv_set = 1;
        }
        actx->key_set = 1;
    } else {
        memcpy(actx->iv, iv, actx->ivlen);
        actx->iv_set = 1;
        actx->iv_gen = 0;
    }
    return 1;
}

static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    afalg_ctx *actx;
    int ret;
    char nxtiv[ALG_AES_IV_LEN] = { 0 };

    if (ctx == NULL || out == NULL || in == NULL) {
        ALG_WARN("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (afalg_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n",
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }

    /*
     * set iv now for decrypt operation as the input buffer can be
     * overwritten for inplace operation where in = out.
     */
    if (EVP_CIPHER_CTX_encrypting(ctx) == 0) {
        memcpy(nxtiv, in + (inl - ALG_AES_IV_LEN), ALG_AES_IV_LEN);
    }

    /* Send input data to kernel space */
    ret = afalg_start_cipher_sk(actx, (unsigned char *)in, inl,
                                EVP_CIPHER_CTX_iv(ctx),
                                EVP_CIPHER_CTX_encrypting(ctx));
    if (ret < 1) {
        return 0;
    }

    /* Perform async crypto operation in kernel space */
    ret = afalg_fin_cipher_aio(&actx->aio, actx->sfd, out, inl);
    if (ret < 1)
        return 0;

    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), out + (inl - ALG_AES_IV_LEN),
               ALG_AES_IV_LEN);
    } else {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), nxtiv, ALG_AES_IV_LEN);
    }

    return 1;
}

static int afalg_start_nontlsaead_sk(EVP_CIPHER_CTX *ctx, struct iovec *iov,
                                     int iovlen, const unsigned char *iv,
                                     int inl, unsigned int enc)
{
    afalg_aead_ctx *gctx = (afalg_aead_ctx *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    afalg_ctx *actx = (afalg_ctx *)&gctx->ctx;
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    ssize_t sbytes;
# ifdef ALG_ZERO_COPY
    int ret;
# endif
    char cbuf[CMSG_SPACE(ALG_IV_LEN(AES_GCM_IV_LEN)) + CMSG_SPACE(ALG_OP_LEN) +
              CMSG_SPACE(sizeof(unsigned int))];

    memset(cbuf, 0, sizeof(cbuf));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    /*
     * cipher direction (i.e. encrypt or decrypt), iv and aad_len are sent to
     * the kernel as part of sendmsg()'s ancillary data
     */
    cmsg = CMSG_FIRSTHDR(&msg);
    afalg_set_op_sk(cmsg, enc);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    afalg_set_iv_sk(cmsg, iv, gctx->ivlen);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    afalg_set_aad_sk(cmsg, gctx->aad_len);

    msg.msg_flags = MSG_MORE;
# ifdef ALG_ZERO_COPY

    /*
     * ZERO_COPY mode
     * Works best when buffer is 4k aligned
     * OPENS: out of place processing (i.e. out != in)
     */

    /* Input data is not sent as part of call to sendmsg() */
    msg.msg_iovlen = 0;
    msg.msg_iov = NULL;

    /* Sendmsg() sends iv and cipher direction to the kernel */
    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s(%d): sendmsg failed for zero copy cipher operation : ",
                 __FILE__, __LINE__);
        return 0;
    }

    /*
     * vmsplice and splice are used to pin the user space input buffer for
     * kernel space processing avoiding copys from user to kernel space
     */
    ret = vmsplice(actx->zc_pipe[1], iov, iovlen, SPLICE_F_GIFT);
    if (ret < 0) {
        ALG_PERR("%s(%d): vmsplice failed : ", __FILE__, __LINE__);
        return 0;
    }

    ret = splice(actx->zc_pipe[0], NULL, actx->sfd, NULL, ret, SPLICE_F_MORE);
    if (ret < 0) {
        ALG_PERR("%s(%d): splice failed : ", __FILE__, __LINE__);
        return 0;
    }
# else
    msg.msg_iovlen = iovlen;
    msg.msg_iov = iov;

    /*
     * Sendmsg() sends iv, cipher direction, aad len and input
     * data to the kernel
     */
    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s(%d): sendmsg failed for cipher operation : ", __FILE__,
                 __LINE__);
        return 0;
    }
    if (sbytes != (ssize_t)(inl + gctx->aad_len + (!enc ?
                                                   EVP_GCM_TLS_TAG_LEN : 0))) {
        ALG_WARN("Cipher operation send bytes %zd != inlen %zd\n", sbytes, inl);
        return 0;
    }
# endif

    return 1;
}

static int aes_gcm_nontls_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len)
{
    afalg_aead_ctx *gctx;
    afalg_ctx *actx;
    struct iovec iov[3];
    int ret = -1;
    int i = 0;

    gctx = (afalg_aead_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    actx = (afalg_ctx *)&gctx->ctx;
    if (in == NULL) {
        /*
         * Final call: Copy Tag to ctx->buf, which is already done in encrypt
         * operation, So nothing to do here
         */
        gctx->iv_set = 0;
        gctx->taglen = 16;
        ret = 0;
        goto end;
    }
    gctx->iov[gctx->iovlen].iov_base = (void *)in;
    gctx->iov[gctx->iovlen].iov_len = len;
    gctx->iovlen++;

    ret = afalg_start_nontlsaead_sk(ctx, gctx->iov, gctx->iovlen,
                                    EVP_CIPHER_CTX_iv(ctx), len,
                                    EVP_CIPHER_CTX_encrypting(ctx));
    if (ret < 0) {
        ALG_WARN("%s: Buffer send fail\n", __func__);
        return -1;
    }
    /* Recv output */
    if (gctx->aad_len) {
        iov[i].iov_base = malloc(gctx->aad_len);
        if (iov[i].iov_base) {
            ALG_WARN("%s: AAD buffer alloc for recv fail\n", __func__);

        }
        iov[i].iov_len = gctx->aad_len;
        i++;
    }
    iov[i].iov_base = out;
    iov[i].iov_len = len;
    i++;
    iov[i].iov_base = (void *)EVP_CIPHER_CTX_buf_noconst(ctx);
    iov[i].iov_len = 16;
    i++;

    ret = afalg_fin_nontlsaead_aio(ctx, actx->sfd, iov, i);
    if (ret < 0) {
        ALG_WARN("%s: Buffer read fail\n", __func__);
        ret = -errno;
        goto clear;
    }
    ret = len;
 clear:
    if (gctx->aad_len)
        free(iov[0].iov_base);
 end:
    gctx->iovlen = 0;
    gctx->aad_len = 0;
    return ret;
}

static int aes_gcm_nontls_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len)
{
    struct iovec iov[3];
    afalg_aead_ctx *gctx;
    afalg_ctx *actx;
    int ret = -1;
    int i = 0;

    gctx = (afalg_aead_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    actx = (afalg_ctx *)&gctx->ctx;
    if (in == NULL) {
        /*
         * Case of cipherfinal, Need to send aad, ciphertext and tag as input
         * again to verify tag present in ctx->buf
         */
        if (gctx->aad_len)
            gctx->iovlen = 3;
        else
            gctx->iovlen = 2;
    } else {
        gctx->iov[gctx->iovlen].iov_base = (void *)in;
        gctx->iov[gctx->iovlen].iov_len = len;
        gctx->iovlen++;
        gctx->iov[gctx->iovlen].iov_base = EVP_CIPHER_CTX_buf_noconst(ctx);
        gctx->iov[gctx->iovlen].iov_len = 16;
        gctx->iovlen++;
        gctx->len = len;
    }
    ret = afalg_start_nontlsaead_sk(ctx, gctx->iov, gctx->iovlen,
                                    EVP_CIPHER_CTX_iv(ctx), len,
                                    EVP_CIPHER_CTX_encrypting(ctx));
    if (ret < 0) {
        ALG_WARN("%s: Decrypt Send fail\n", __func__);
        return -1;
    }
    if (gctx->aad_len) {
        iov[i].iov_base = malloc(gctx->aad_len);
        if (!iov[i].iov_base) {
            ALG_WARN("%s: AAD allocation fail\n", __func__);
            return -1;
        }
        iov[i].iov_len = gctx->aad_len;
        i++;
    }
    iov[i].iov_base = out;
    iov[i].iov_len = gctx->len;
    i++;

    ret = afalg_fin_nontlsaead_aio(ctx, actx->sfd, iov, i);
    if (ret < 0) {
        ALG_WARN("%s: Decrypt Receive fail\n", __func__);
        len = -1;
    }
    if (gctx->aad_len)
        free(iov[0].iov_base);
    gctx->iv_set = 1;

    gctx->iovlen = 0;
    if (in == NULL)
        gctx->aad_len = 0;
    return len;
}

static int aes_gcm_nontls_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t len)
{
    afalg_aead_ctx *gctx;
    int rv;

    gctx = (afalg_aead_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!gctx->iv_set)
        return -1;
    if (in && !out) {
        /* Input contains AAD. Save in iovec */
        if (gctx->iovlen > 16) {
            ALG_WARN("%s: Input has more than 16 entries. Which cannot be \
                  sent in IOV\n", __func__);
            return -1;
        }
        gctx->iov[gctx->iovlen].iov_base = (void *)in;
        gctx->iov[gctx->iovlen].iov_len = len;
        gctx->aad_len += len;
        gctx->iovlen++;
        return len;
    }

    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        rv = aes_gcm_nontls_encrypt(ctx, out, in, len);
    } else {
        rv = aes_gcm_nontls_decrypt(ctx, out, in, len);
    }

    return rv;
}

static int afalg_do_aead(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    afalg_aead_ctx *gctx;
    afalg_ctx *actx;
    int ret = -1;

    if (ctx == NULL) {
        ALG_WARN("NULL parameter passed to function %s\n", __func__);
        return 0;
    }

    gctx = (afalg_aead_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    actx = (afalg_ctx *)&gctx->ctx;
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n",
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }
    ret = aes_gcm_nontls_do_cipher(ctx, out, in, inl);

    return ret;
}

static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    afalg_ctx *actx;

    if (ctx == NULL) {
        ALG_WARN("NULL parameter passed to function %s(%d)\n", __FILE__,
                 __LINE__);
        return 0;
    }

    actx = (afalg_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (actx == NULL || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n",
                 ctx == NULL ? "NULL" : "Uninitialised");
        return 0;
    }

    close(actx->sfd);
    close(actx->bfd);
# ifdef ALG_ZERO_COPY
    close(actx->zc_pipe[0]);
    close(actx->zc_pipe[1]);
# endif
    /* close efd in sync mode, async mode is closed in afalg_waitfd_cleanup() */
    if (actx->aio.mode == MODE_SYNC)
        close(actx->aio.efd);
    io_destroy(actx->aio.aio_ctx);

    return 1;
}

static int afalg_aead_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    afalg_aead_ctx *actx = (afalg_aead_ctx *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret = 1;

    switch (type) {
    case EVP_CTRL_INIT:
        actx->ivlen = EVP_CIPHER_CTX_iv_length(ctx);
        actx->iv = EVP_CIPHER_CTX_iv_noconst(ctx);
        actx->aad_len = 0;
        actx->len = 0;
        actx->iovlen = 0;
        actx->iv_gen = 0;
        break;
    case EVP_CTRL_GCM_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(ctx)) {
            ret = 0;
            break;
        }
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        actx->taglen = arg;
        break;
    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > actx->ivlen)) {
            if (actx->iv != EVP_CIPHER_CTX_iv_noconst(ctx))
                OPENSSL_free(actx->iv);
            if ((actx->iv = OPENSSL_malloc(arg)) == NULL)
                ret = 0;
        }
        actx->ivlen = arg;
        ret = 1;
        break;
    case EVP_CTRL_GCM_GET_TAG:
        if (!EVP_CIPHER_CTX_encrypting(ctx) || arg <= 0 || arg > 16 ||
            actx->taglen < 0) {
            return 0;
        }
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

static aes_handles *get_cipher_handle(int nid)
{
    switch (nid) {
    case NID_aes_128_cbc:
        return &aes_handle[AES_CBC_128];
    case NID_aes_192_cbc:
        return &aes_handle[AES_CBC_192];
    case NID_aes_256_cbc:
        return &aes_handle[AES_CBC_256];
    case NID_aes_128_gcm:
        return &aes_handle[AES_GCM_128];
    case NID_aes_192_gcm:
        return &aes_handle[AES_GCM_192];
    case NID_aes_256_gcm:
        return &aes_handle[AES_GCM_256];
    default:
        return NULL;
    }
}

# define CUSTOM_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                       | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                       | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                       | EVP_CIPH_CUSTOM_COPY)

static const EVP_CIPHER *afalg_aes_aead(int nid)
{
    aes_handles *aead_handle = get_cipher_handle(nid);
    if (aead_handle->_hidden == NULL
        && ((aead_handle->_hidden =
             EVP_CIPHER_meth_new(nid, 1, aead_handle->key_size)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(aead_handle->_hidden,
                                              AES_GCM_IV_LEN)
            || !EVP_CIPHER_meth_set_flags(aead_handle->_hidden,
                                          EVP_CIPH_GCM_MODE | CUSTOM_FLAGS |
                                          EVP_CIPH_FLAG_AEAD_CIPHER)
            || !EVP_CIPHER_meth_set_init(aead_handle->_hidden,
                                         afalg_aead_init)
            || !EVP_CIPHER_meth_set_do_cipher(aead_handle->_hidden,
                                              afalg_do_aead)
            || !EVP_CIPHER_meth_set_cleanup(aead_handle->_hidden,
                                            afalg_cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(aead_handle->_hidden,
                                                  sizeof(afalg_aead_ctx))
            || !EVP_CIPHER_meth_set_ctrl(aead_handle->_hidden,
                                         afalg_aead_ctrl))) {
        EVP_CIPHER_meth_free(aead_handle->_hidden);
        aead_handle->_hidden = NULL;
    }
    return aead_handle->_hidden;
}

static const EVP_CIPHER *afalg_aes_cipher(int nid)
{
    aes_handles *cipher_handle = get_cipher_handle(nid);
    if (cipher_handle->_hidden == NULL
        && ((cipher_handle->_hidden =
         EVP_CIPHER_meth_new(nid,
                             AES_BLOCK_SIZE,
                             cipher_handle->key_size)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(cipher_handle->_hidden,
                                          AES_IV_LEN)
        || !EVP_CIPHER_meth_set_flags(cipher_handle->_hidden,
                                      EVP_CIPH_CBC_MODE |
                                      EVP_CIPH_FLAG_DEFAULT_ASN1)
        || !EVP_CIPHER_meth_set_init(cipher_handle->_hidden,
                                     afalg_cipher_init)
        || !EVP_CIPHER_meth_set_do_cipher(cipher_handle->_hidden,
                                          afalg_do_cipher)
        || !EVP_CIPHER_meth_set_cleanup(cipher_handle->_hidden,
                                        afalg_cipher_cleanup)
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher_handle->_hidden,
                                              sizeof(afalg_ctx)))) {
        EVP_CIPHER_meth_free(cipher_handle->_hidden);
        cipher_handle->_hidden = NULL;
    }
    return cipher_handle->_hidden;
}

static int chk_gcm_kernel_supp(void)
{
    struct sockaddr_alg sa;
    int sock;
    int r;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *) sa.salg_type, "aead", sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *) sa.salg_name, "gcm(aes)", sizeof(sa.salg_name));
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1)
        return 0;

    r = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0)
        return 0;

    close(sock);

    return 1;
}

static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    int r = 1;

    if (cipher == NULL) {
        *nids = afalg_aes_nids;
        if (chk_gcm_kernel_supp())
            return (sizeof(afalg_aes_nids) / sizeof(afalg_aes_nids[0]));
        else
            return (sizeof(afalg_aes_nids) / sizeof(afalg_aes_nids[0]) - 3);
    }

    switch (nid) {
    case NID_aes_128_cbc:
    case NID_aes_192_cbc:
    case NID_aes_256_cbc:
        *cipher = afalg_aes_cipher(nid);
        break;
    case NID_aes_128_gcm:
    case NID_aes_192_gcm:
    case NID_aes_256_gcm:
        *cipher = afalg_aes_aead(nid);
        break;
    default:
        *cipher = NULL;
        r = 0;
    }
    return r;
}

static int bind_afalg(ENGINE *e)
{
    /* Ensure the afalg error handling is set up */
    ERR_load_AFALG_strings();

    if (!ENGINE_set_id(e, engine_afalg_id)
        || !ENGINE_set_name(e, engine_afalg_name)
        || !ENGINE_set_destroy_function(e, afalg_destroy)
        || !ENGINE_set_init_function(e, afalg_init)
        || !ENGINE_set_finish_function(e, afalg_finish)
        || !ENGINE_set_ciphers(e, afalg_ciphers)) {
        AFALGerr(AFALG_F_BIND_AFALG, AFALG_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_afalg_id) != 0))
        return 0;

    if (!afalg_chk_platform())
        return 0;

    if (!bind_afalg(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static int afalg_chk_platform(void)
{
    int ret;
    int i;
    int kver[3] = { -1, -1, -1 };
    int sock;
    char *str;
    struct utsname ut;

    ret = uname(&ut);
    if (ret != 0) {
        AFALGerr(AFALG_F_AFALG_CHK_PLATFORM,
                 AFALG_R_FAILED_TO_GET_PLATFORM_INFO);
        return 0;
    }

    str = strtok(ut.release, ".");
    for (i = 0; i < 3 && str != NULL; i++) {
        kver[i] = atoi(str);
        str = strtok(NULL, ".");
    }

    if (KERNEL_VERSION(kver[0], kver[1], kver[2])
        < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)) {
        ALG_ERR("ASYNC AFALG not supported this kernel(%d.%d.%d)\n",
                 kver[0], kver[1], kver[2]);
        ALG_ERR("ASYNC AFALG requires kernel version %d.%d.%d or later\n",
                 K_MAJ, K_MIN1, K_MIN2);
        AFALGerr(AFALG_F_AFALG_CHK_PLATFORM,
                 AFALG_R_KERNEL_DOES_NOT_SUPPORT_ASYNC_AFALG);
        return 0;
    }

    /* Test if we can actually create an AF_ALG socket */
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        AFALGerr(AFALG_F_AFALG_CHK_PLATFORM, AFALG_R_SOCKET_CREATE_FAILED);
        return 0;
    }
    close(sock);

    return 1;
}

# ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_afalg(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_afalg(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_afalg_int(void)
{
    ENGINE *toadd;

    if (!afalg_chk_platform())
        return;

    toadd = engine_afalg();
    if (toadd == NULL)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
# endif

static int afalg_init(ENGINE *e)
{
    return 1;
}

static int afalg_finish(ENGINE *e)
{
    return 1;
}

static int free_aes(void)
{
    short unsigned int i;
    for (i = 0; i < OSSL_NELEM(afalg_aes_nids); i++) {
        EVP_CIPHER_meth_free(aes_handle[i]._hidden);
        aes_handle[i]._hidden = NULL;
    }
    return 1;
}

static int afalg_destroy(ENGINE *e)
{
    ERR_unload_AFALG_strings();
    free_aes();
    return 1;
}

#endif                          /* KERNEL VERSION */
