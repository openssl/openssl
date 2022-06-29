/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_LOCAL_H
# define OSSL_QUIC_LOCAL_H

# include <openssl/ssl.h>
# include "../ssl_local.h"

# define OSSL_QUIC_ANY_VERSION 0xFFFFF

# define IMPLEMENT_quic_meth_func(version, func_name, q_accept, \
                                 q_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                0, \
                0, \
                ossl_quic_new, \
                ossl_quic_clear, \
                ossl_quic_free, \
                q_accept, \
                q_connect, \
                ossl_quic_read, \
                ossl_quic_peek, \
                ossl_quic_write, \
                ossl_quic_shutdown, \
                NULL /* renegotiate */, \
                ossl_quic_renegotiate_check, \
                NULL /* read_bytes */, \
                NULL /* write_bytes */, \
                NULL /* dispatch_alert */, \
                ossl_quic_ctrl, \
                ossl_quic_ctx_ctrl, \
                NULL /* get_cipher_by_char */, \
                NULL /* put_cipher_by_char */, \
                ossl_quic_pending, \
                ossl_quic_num_ciphers, \
                ossl_quic_get_cipher, \
                ossl_quic_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ossl_quic_callback_ctrl, \
                ossl_quic_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

__owur int ossl_quic_new(SSL *s);
void ossl_quic_free(SSL *s);
int ossl_quic_clear(SSL *s);
__owur int ossl_quic_accept(SSL *s);
__owur int ossl_quic_connect(SSL *s);
__owur int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes);
__owur int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *readbytes);
__owur int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written);
__owur int ossl_quic_shutdown(SSL *s);
__owur long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg);
__owur long ossl_quic_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg);
__owur long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void));
__owur long ossl_quic_ctx_callback_ctrl(SSL_CTX *s, int cmd, void (*fp) (void));
__owur size_t ossl_quic_pending(const SSL *s);
__owur long ossl_quic_default_timeout(void);
__owur int ossl_quic_num_ciphers(void);
__owur const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u);
int ossl_quic_renegotiate_check(SSL *ssl, int initok);

#endif
