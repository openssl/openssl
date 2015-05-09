/* $OpenBSD: s23_meth.c,v 1.13 2014/06/12 15:49:31 deraadt Exp $ */
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

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

static const SSL_METHOD *ssl23_get_method(int ver);

const SSL_METHOD SSLv23_method_data = {
	.version = TLS1_2_VERSION,
	.ssl_new = tls1_new,
	.ssl_clear = tls1_clear,
	.ssl_free = tls1_free,
	.ssl_accept = ssl23_accept,
	.ssl_connect = ssl23_connect,
	.ssl_read = ssl23_read,
	.ssl_peek = ssl23_peek,
	.ssl_write = ssl23_write,
	.ssl_shutdown = ssl_undefined_function,
	.ssl_renegotiate = ssl_undefined_function,
	.ssl_renegotiate_check = ssl_ok,
	.ssl_get_message = ssl3_get_message,
	.ssl_read_bytes = ssl3_read_bytes,
	.ssl_write_bytes = ssl3_write_bytes,
	.ssl_dispatch_alert = ssl3_dispatch_alert,
	.ssl_ctrl = ssl3_ctrl,
	.ssl_ctx_ctrl = ssl3_ctx_ctrl,
	.get_cipher_by_char = ssl3_get_cipher_by_char,
	.put_cipher_by_char = ssl23_put_cipher_by_char,
	.ssl_pending = ssl_undefined_const_function,
	.num_ciphers = ssl3_num_ciphers,
	.get_cipher = ssl3_get_cipher,
	.get_ssl_method = ssl23_get_method,
	.get_timeout = ssl23_default_timeout,
	.ssl3_enc = &ssl3_undef_enc_method,
	.ssl_version = ssl_undefined_void_function,
	.ssl_callback_ctrl = ssl3_callback_ctrl,
	.ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *
SSLv23_method(void)
{
	return &SSLv23_method_data;
}

static const SSL_METHOD *
ssl23_get_method(int ver)
{
	if (ver == SSL3_VERSION)
		return (SSLv3_method());
	if (ver == TLS1_VERSION)
		return (TLSv1_method());
	if (ver == TLS1_1_VERSION)
		return (TLSv1_1_method());
	if (ver == TLS1_2_VERSION)
		return (TLSv1_2_method());
	return (NULL);
}
