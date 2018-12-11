/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_KTLS
# ifndef HEADER_INTERNAL_KTLS
#  define HEADER_INTERNAL_KTLS

#  if defined(OPENSSL_SYS_LINUX)
#   include <linux/version.h>

#   define K_MAJ   4
#   define K_MIN1  13
#   define K_MIN2  0
#   if LINUX_VERSION_CODE < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)

#    ifndef PEDANTIC
#     warning "KTLS requires Kernel Headers >= 4.13.0"
#     warning "Skipping Compilation of KTLS data path"
#    endif

#    define TLS_TX                  1

#    define TLS_CIPHER_AES_GCM_128                          51
#    define TLS_CIPHER_AES_GCM_128_IV_SIZE                  8
#    define TLS_CIPHER_AES_GCM_128_KEY_SIZE                 16
#    define TLS_CIPHER_AES_GCM_128_SALT_SIZE                4
#    define TLS_CIPHER_AES_GCM_128_TAG_SIZE                 16
#    define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE             8

#    define TLS_SET_RECORD_TYPE     1

struct tls_crypto_info {
    unsigned short version;
    unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

/* Dummy functions here */
static ossl_inline int ktls_enable(int fd)
{
    return 0;
}

static ossl_inline int ktls_start(int fd,
                                  struct tls12_crypto_info_aes_gcm_128
                                  *crypto_info, size_t len, int is_tx)
{
    return 0;
}

static ossl_inline int ktls_send_ctrl_message(int fd, unsigned char record_type,
                                              const void *data, size_t length)
{
    return -1;
}

#   else                        /* KERNEL_VERSION */

#    include <netinet/tcp.h>
#    include <linux/tls.h>
#    include <linux/socket.h>

#    ifndef SOL_TLS
#     define SOL_TLS 282
#    endif

#    ifndef TCP_ULP
#     define TCP_ULP 31
#    endif

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
 */
static ossl_inline int ktls_start(int fd,
                                  struct tls12_crypto_info_aes_gcm_128
                                  *crypto_info, size_t len, int is_tx)
{
    if (is_tx)
        return setsockopt(fd, SOL_TLS, TLS_TX, crypto_info,
                          sizeof(*crypto_info)) ? 0 : 1;
    else
        return 0;
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
    struct msghdr msg = { 0 };
    int cmsg_len = sizeof(record_type);
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(cmsg_len)];
    struct iovec msg_iov;       /* Vector of data to send/receive into */

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
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

#   endif                       /* KERNEL_VERSION */
#  endif                        /* OPENSSL_SYS_LINUX */
# endif                         /* HEADER_INTERNAL_KTLS */
#endif                          /* OPENSSL_NO_KTLS */
