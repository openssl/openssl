/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(OPENSSL_SYS_LINUX)
# ifndef OPENSSL_NO_KTLS
#  include <linux/version.h>
#  if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#   define OPENSSL_NO_KTLS
#   ifndef PEDANTIC
#    warning "KTLS requires Kernel Headers >= 4.13.0"
#    warning "Skipping Compilation of KTLS"
#   endif
#  endif
# endif
#endif

#ifndef OPENSSL_NO_KTLS
# ifndef HEADER_INTERNAL_KTLS
#  define HEADER_INTERNAL_KTLS

#  if defined(__FreeBSD__)
#   include <sys/types.h>
#   include <sys/socket.h>
#   include <sys/ktls.h>
#   include <netinet/in.h>
#   include <netinet/tcp.h>
#   include <crypto/cryptodev.h>

/*
 * Only used by the tests in sslapitest.c.
 */
#   define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE             8

/*
 * FreeBSD does not require any additional steps to enable KTLS before
 * setting keys.
 */
static ossl_inline int ktls_enable(int fd)
{
    return 1;
}

/*
 * The TCP_TXTLS_ENABLE socket option marks the outgoing socket buffer
 * as using TLS.  If successful, then data sent using this socket will
 * be encrypted and encapsulated in TLS records using the tls_en.
 * provided here.
 */
static ossl_inline int ktls_start(int fd,
                                  void *tls_en,
                                  size_t len, int is_tx)
{
    if (is_tx)
        return setsockopt(fd, IPPROTO_TCP, TCP_TXTLS_ENABLE,
                          tls_en, len) ? 0 : 1;
    else
        return 0;
}

/*
 * Send a TLS record using the tls_en provided in ktls_start and use
 * record_type instead of the default SSL3_RT_APPLICATION_DATA.
 * When the socket is non-blocking, then this call either returns EAGAIN or
 * the entire record is pushed to TCP. It is impossible to send a partial
 * record using this control message.
 */
static ossl_inline int ktls_send_ctrl_message(int fd, unsigned char record_type,
                                              const void *data, size_t length)
{
    struct msghdr msg = { 0 };
    int cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(cmsg_len)];
    struct iovec msg_iov;   /* Vector of data to send/receive into */

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_TCP;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(cmsg_len);
    *((unsigned char *)CMSG_DATA(cmsg)) = record_type;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = (void *)data;
    msg_iov.iov_len = length;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}

static ossl_inline int ktls_read_record(int fd, void *data, size_t length)
{
    return -1;
}

/*
 * KTLS enables the sendfile system call to send data from a file over
 * TLS.
 */
static ossl_inline ossl_ssize_t ktls_sendfile(int s, int fd, off_t off,
                                              size_t size, int flags)
{
    off_t sbytes;
    int ret;

    ret = sendfile(fd, s, off, size, NULL, &sbytes, flags);
    if (ret == -1) {
	    if (errno == EAGAIN && sbytes != 0)
		    return sbytes;
	    return -1;
    }
    return sbytes;
}
#  endif                         /* __FreeBSD__ */

#  if defined(OPENSSL_SYS_LINUX)

#   include <linux/tls.h>
#   if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#    define OPENSSL_NO_KTLS_RX
#    ifndef PEDANTIC
#     warning "KTLS requires Kernel Headers >= 4.17.0 for receiving"
#     warning "Skipping Compilation of KTLS receive data path"
#    endif
#   endif
#   define OPENSSL_KTLS_AES_GCM_128
#   if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
#    define OPENSSL_KTLS_AES_GCM_256
#    define OPENSSL_KTLS_TLS13
#    if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#     define OPENSSL_KTLS_AES_CCM_128
#    endif
#   endif

#   include <sys/sendfile.h>
#   include <netinet/tcp.h>
#   include <linux/socket.h>
#   include "openssl/ssl3.h"
#   include "openssl/tls1.h"
#   include "openssl/evp.h"

#   ifndef SOL_TLS
#    define SOL_TLS 282
#   endif

#   ifndef TCP_ULP
#    define TCP_ULP 31
#   endif

#   ifndef TLS_RX
#    define TLS_RX                  2
#   endif

struct tls_crypto_info_all {
    union {
#   ifdef OPENSSL_KTLS_AES_GCM_128
        struct tls12_crypto_info_aes_gcm_128 gcm128;
#   endif
#   ifdef OPENSSL_KTLS_AES_GCM_256
        struct tls12_crypto_info_aes_gcm_256 gcm256;
#   endif
#   ifdef OPENSSL_KTLS_AES_CCM_128
        struct tls12_crypto_info_aes_ccm_128 ccm128;
#   endif
    };
    size_t tls_crypto_info_len;
};
/*
 * When successful, this socket option doesn't change the behaviour of the
 * TCP socket, except changing the TCP setsockopt handler to enable the
 * processing of SOL_TLS socket options. All other functionality remains the
 * same.
 */
static ossl_inline int ktls_enable(int fd)
{
    return setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) ? 0 : 1;
}

/*
 * The TLS_TX socket option changes the send/sendmsg handlers of the TCP socket.
 * If successful, then data sent using this socket will be encrypted and
 * encapsulated in TLS records using the crypto_info provided here.
 * The TLS_RX socket option changes the recv/recvmsg handlers of the TCP socket.
 * If successful, then data received using this socket will be decrypted,
 * authenticated and decapsulated using the crypto_info provided here.
 */
static ossl_inline int ktls_start(int fd, void *crypto_info,
                                  size_t len, int is_tx)
{
    return setsockopt(fd, SOL_TLS, is_tx ? TLS_TX : TLS_RX,
                      crypto_info, len) ? 0 : 1;
}

/*
 * Send a TLS record using the crypto_info provided in ktls_start and use
 * record_type instead of the default SSL3_RT_APPLICATION_DATA.
 * When the socket is non-blocking, then this call either returns EAGAIN or
 * the entire record is pushed to TCP. It is impossible to send a partial
 * record using this control message.
 */
static ossl_inline int ktls_send_ctrl_message(int fd, unsigned char record_type,
                                              const void *data, size_t length)
{
    struct msghdr msg;
    int cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(unsigned char))];
    } cmsgbuf;
    struct iovec msg_iov;       /* Vector of data to send/receive into */

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_TLS;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(cmsg_len);
    *((unsigned char *)CMSG_DATA(cmsg)) = record_type;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = (void *)data;
    msg_iov.iov_len = length;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}

/*
 * KTLS enables the sendfile system call to send data from a file over TLS.
 * @flags are ignored on Linux. (placeholder for FreeBSD sendfile)
 * */
static ossl_inline ossl_ssize_t ktls_sendfile(int s, int fd, off_t off, size_t size, int flags)
{
    return sendfile(s, fd, &off, size);
}

#   ifdef OPENSSL_NO_KTLS_RX


static ossl_inline int ktls_read_record(int fd, void *data, size_t length)
{
    return -1;
}

#   else /* !defined(OPENSSL_NO_KTLS_RX) */

/*
 * Receive a TLS record using the crypto_info provided in ktls_start.
 * The kernel strips the TLS record header, IV and authentication tag,
 * returning only the plaintext data or an error on failure.
 * We add the TLS record header here to satisfy routines in rec_layer_s3.c
 */
static ossl_inline int ktls_read_record(int fd, void *data, size_t length)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(unsigned char))];
    } cmsgbuf;
    struct iovec msg_iov;
    int ret;
    unsigned char *p = data;
    const size_t prepend_length = SSL3_RT_HEADER_LENGTH;

    if (length < prepend_length + EVP_GCM_TLS_TAG_LEN) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    msg_iov.iov_base = p + prepend_length;
    msg_iov.iov_len = length - prepend_length - EVP_GCM_TLS_TAG_LEN;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(fd, &msg, 0);
    if (ret < 0)
        return ret;

    if (msg.msg_controllen > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg->cmsg_type == TLS_GET_RECORD_TYPE) {
            p[0] = *((unsigned char *)CMSG_DATA(cmsg));
            p[1] = TLS1_2_VERSION_MAJOR;
            p[2] = TLS1_2_VERSION_MINOR;
            /* returned length is limited to msg_iov.iov_len above */
            p[3] = (ret >> 8) & 0xff;
            p[4] = ret & 0xff;
            ret += prepend_length;
        }
    }

    return ret;
}

#   endif /* OPENSSL_NO_KTLS_RX */

/* Function to check supported ciphers in Linux */
static ossl_inline int ktls_check_supported_cipher(const EVP_CIPHER *c,
                                            const EVP_CIPHER_CTX *dd)
{
    /* check that cipher is AES_GCM_128, AES_GCM_256, AES_CCM_128 */
    switch (EVP_CIPHER_nid(c))
    {
#  ifdef OPENSSL_KTLS_AES_CCM_128
    case NID_aes_128_ccm:
        if (EVP_CIPHER_CTX_tag_length(dd) != EVP_CCM_TLS_TAG_LEN)
          return 0;
#  endif
#  ifdef OPENSSL_KTLS_AES_GCM_128
    case NID_aes_128_gcm:
#  endif
#  ifdef OPENSSL_KTLS_AES_GCM_256
    case NID_aes_256_gcm:
#  endif
        return 1;
    default:
        return 0;
    }
}

/* Function to configure kernel TLS structure */
static ossl_inline int ktls_configure_crypto(const EVP_CIPHER *c, int tls_version,
                                EVP_CIPHER_CTX *dd, void *rl_sequence,
                                struct tls_crypto_info_all *crypto_info,
                                unsigned char **rec_seq, unsigned char *iv,
                                unsigned char *key)
{
    unsigned char geniv[12];
    unsigned char *iiv = iv;

    if (tls_version == TLS1_2_VERSION &&
        EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
        EVP_CIPHER_CTX_ctrl(dd, EVP_CTRL_GET_IV,
                            EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                            geniv);
        iiv = geniv;
    }

    memset(crypto_info, 0, sizeof(*crypto_info));
    switch (EVP_CIPHER_nid(c))
    {
#  ifdef OPENSSL_KTLS_AES_GCM_128
    case NID_aes_128_gcm:
        crypto_info->gcm128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
        crypto_info->gcm128.info.version = tls_version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->gcm128);
        memcpy(crypto_info->gcm128.iv, iiv + EVP_GCM_TLS_FIXED_IV_LEN,
                TLS_CIPHER_AES_GCM_128_IV_SIZE);
        memcpy(crypto_info->gcm128.salt, iiv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(crypto_info->gcm128.key, key, EVP_CIPHER_key_length(c));
        memcpy(crypto_info->gcm128.rec_seq, rl_sequence,
                TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
        if (rec_seq != NULL)
            *rec_seq = crypto_info->gcm128.rec_seq;
        return 1;
#  endif
#  ifdef OPENSSL_KTLS_AES_GCM_256
    case NID_aes_256_gcm:
        crypto_info->gcm256.info.cipher_type = TLS_CIPHER_AES_GCM_256;
        crypto_info->gcm256.info.version = tls_version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->gcm256);
        memcpy(crypto_info->gcm256.iv, iiv + EVP_GCM_TLS_FIXED_IV_LEN,
                TLS_CIPHER_AES_GCM_256_IV_SIZE);
        memcpy(crypto_info->gcm256.salt, iiv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(crypto_info->gcm256.key, key, EVP_CIPHER_key_length(c));
        memcpy(crypto_info->gcm256.rec_seq, rl_sequence,
                TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
        if (rec_seq != NULL)
            *rec_seq = crypto_info->gcm256.rec_seq;
        return 1;
#  endif
#  ifdef OPENSSL_KTLS_AES_CCM_128
    case NID_aes_128_ccm:
        crypto_info->ccm128.info.cipher_type = TLS_CIPHER_AES_CCM_128;
        crypto_info->ccm128.info.version = tls_version;
        crypto_info->tls_crypto_info_len = sizeof(crypto_info->ccm128);
        memcpy(crypto_info->ccm128.iv, iiv + EVP_CCM_TLS_FIXED_IV_LEN,
                TLS_CIPHER_AES_CCM_128_IV_SIZE);
        memcpy(crypto_info->ccm128.salt, iiv, TLS_CIPHER_AES_CCM_128_SALT_SIZE);
        memcpy(crypto_info->ccm128.key, key, EVP_CIPHER_key_length(c));
        memcpy(crypto_info->ccm128.rec_seq, rl_sequence,
                TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE);
        if (rec_seq != NULL)
            *rec_seq = crypto_info->ccm128.rec_seq;
        return 1;
#  endif
    default:
        return 0;
    }

}

#  endif /* OPENSSL_SYS_LINUX */
# endif /* HEADER_INTERNAL_KTLS */
#else /* defined(OPENSSL_NO_KTLS) */
/* Dummy functions here */
static ossl_inline int ktls_enable(int fd)
{
    return 0;
}

static ossl_inline int ktls_start(int fd, void *crypto_info,
                                  size_t len, int is_tx)
{
    return 0;
}

static ossl_inline int ktls_send_ctrl_message(int fd, unsigned char record_type,
                                              const void *data, size_t length)
{
    return -1;
}

static ossl_inline int ktls_read_record(int fd, void *data, size_t length)
{
    return -1;
}

static ossl_inline ossl_ssize_t ktls_sendfile(int s, int fd, off_t off, size_t size, int flags)
{
    return -1;
}
#endif
