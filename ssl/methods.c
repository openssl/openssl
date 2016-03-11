/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

/*
 * TLS/SSLv3 methods
 */

IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_method,
                        ossl_statem_accept,
                        ossl_statem_connect, TLSv1_2_enc_data)

#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        tlsv1_2_method,
                        ossl_statem_accept,
                        ossl_statem_connect, TLSv1_2_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        tlsv1_1_method,
                        ossl_statem_accept,
                        ossl_statem_connect, TLSv1_1_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        tlsv1_method,
                        ossl_statem_accept,
                        ossl_statem_connect, TLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_method, ossl_statem_accept, ossl_statem_connect)
#endif


/*
 * TLS/SSLv3 server methods
 */

IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_server_method,
                        ossl_statem_accept,
                        ssl_undefined_function,
                        TLSv1_2_enc_data)

#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        tlsv1_2_server_method,
                        ossl_statem_accept,
                        ssl_undefined_function,
                        TLSv1_2_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        tlsv1_1_server_method,
                        ossl_statem_accept,
                        ssl_undefined_function,
                        TLSv1_1_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        tlsv1_server_method,
                        ossl_statem_accept,
                        ssl_undefined_function,
                        TLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_server_method,
                         ossl_statem_accept,
                         ssl_undefined_function)
#endif


/*
 * TLS/SSLv3 client methods
 */

IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0,
                        TLS_client_method,
                        ssl_undefined_function,
                        ossl_statem_connect,
                        TLSv1_2_enc_data)

#ifndef OPENSSL_NO_TLS1_2_METHOD
IMPLEMENT_tls_meth_func(TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2,
                        tlsv1_2_client_method,
                        ssl_undefined_function,
                        ossl_statem_connect,
                        TLSv1_2_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_1_METHOD
IMPLEMENT_tls_meth_func(TLS1_1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1_1,
                        tlsv1_1_client_method,
                        ssl_undefined_function,
                        ossl_statem_connect,
                        TLSv1_1_enc_data)
#endif

#ifndef OPENSSL_NO_TLS1_METHOD
IMPLEMENT_tls_meth_func(TLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_TLSv1,
                        tlsv1_client_method,
                        ssl_undefined_function,
                        ossl_statem_connect,
                        TLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_SSL3_METHOD
IMPLEMENT_ssl3_meth_func(sslv3_client_method,
                         ssl_undefined_function,
                         ossl_statem_connect)
#endif


/*
 * DTLS methods
 */

#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          dtlsv1_method,
                          ossl_statem_accept,
                          ossl_statem_connect,
                          DTLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          dtlsv1_2_method,
                          ossl_statem_accept,
                          ossl_statem_connect,
                          DTLSv1_2_enc_data)
#endif

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_method,
                          ossl_statem_accept,
                          ossl_statem_connect,
                          DTLSv1_2_enc_data)

/*
 * DTLS server methods
 */

#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          dtlsv1_server_method,
                          ossl_statem_accept,
                          ssl_undefined_function,
                          DTLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          dtlsv1_2_server_method,
                          ossl_statem_accept,
                          ssl_undefined_function,
                          DTLSv1_2_enc_data)
#endif

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_server_method,
                          ossl_statem_accept,
                          ssl_undefined_function,
                          DTLSv1_2_enc_data)


/*
 * DTLS client methods
 */

#ifndef OPENSSL_NO_DTLS1_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, SSL_METHOD_NO_SUITEB, SSL_OP_NO_DTLSv1,
                          dtlsv1_client_method,
                          ssl_undefined_function,
                          ossl_statem_connect,
                          DTLSv1_enc_data)
#endif

#ifndef OPENSSL_NO_DTLS1_2_METHOD
IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSv1_2,
                          dtlsv1_2_client_method,
                          ssl_undefined_function,
                          ossl_statem_connect,
                          DTLSv1_2_enc_data)
#endif

IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, 0, 0,
                          DTLS_client_method,
                          ssl_undefined_function,
                          ossl_statem_connect,
                          DTLSv1_2_enc_data)

#if OPENSSL_API_COMPAT < 0x10100000L

# ifndef OPENSSL_NO_TLS1_2_METHOD
const SSL_METHOD *TLSv1_2_method(void)
{
    return tlsv1_2_method();
}

const SSL_METHOD *TLSv1_2_server_method(void)
{
    return tlsv1_2_server_method();
}

const SSL_METHOD *TLSv1_2_client_method(void)
{
    return tlsv1_2_client_method();
}
# endif

# ifndef OPENSSL_NO_TLS1_1_METHOD
const SSL_METHOD *TLSv1_1_method(void)
{
    return tlsv1_1_method();
}

const SSL_METHOD *TLSv1_1_server_method(void)
{
    return tlsv1_1_server_method();
}

const SSL_METHOD *TLSv1_1_client_method(void)
{
    return tlsv1_1_client_method();
}
# endif

# ifndef OPENSSL_NO_TLS1_METHOD
const SSL_METHOD *TLSv1_method(void)
{
    return tlsv1_method();
}

const SSL_METHOD *TLSv1_server_method(void)
{
    return tlsv1_server_method();
}

const SSL_METHOD *TLSv1_client_method(void)
{
    return tlsv1_client_method();
}
# endif

# ifndef OPENSSL_NO_SSL3_METHOD
const SSL_METHOD *SSLv3_method(void)
{
    return sslv3_method();
}

const SSL_METHOD *SSLv3_server_method(void)
{
    return sslv3_server_method();
}

const SSL_METHOD *SSLv3_client_method(void)
{
    return sslv3_client_method();
}
# endif

# ifndef OPENSSL_NO_DTLS1_2_METHOD
const SSL_METHOD *DTLSv1_2_method(void)
{
    return dtlsv1_2_method();
}

const SSL_METHOD *DTLSv1_2_server_method(void)
{
    return dtlsv1_2_server_method();
}

const SSL_METHOD *DTLSv1_2_client_method(void)
{
    return dtlsv1_2_client_method();
}
# endif

# ifndef OPENSSL_NO_DTLS1_METHOD
const SSL_METHOD *DTLSv1_method(void)
{
    return dtlsv1_method();
}

const SSL_METHOD *DTLSv1_server_method(void)
{
    return dtlsv1_server_method();
}

const SSL_METHOD *DTLSv1_client_method(void)
{
    return dtlsv1_client_method();
}
# endif

#endif

