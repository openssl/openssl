/* ssl/ssl.c */
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
#include <stdlib.h>
#include <string.h>

#define USE_SOCKETS

#include <openssl/buffer.h>
#include <openssl/stack.h>
#include <openssl/lhash.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include <openssl/bn.h>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/txt_db.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>

#include "ssl_locl.h"

#if !(BUILD_SSLV23) && !defined(BUILD_SSLV2) && !defined(BUILD_SSLV3) && !defined(BUILD_SSL_COMMON) && !defined(BUILD_SSL_BIO) && !defined(BUILD_SSL_OPTIONAL)
#define BUILD_SSLV23
#define BUILD_SSLV2
#define BUILD_SSLV3
#define BUILD_SSL_COMMON
#define BUILD_SSL_BIO
#define BUILD_SSL_OPTIONAL
#endif

#ifdef NO_RSA
#undef BUILD_SSLV2
#undef BUILD_SSLV23
#endif

#ifdef NO_SSL2
#undef BUILD_SSLV2
#undef BUILD_SSLV23
#endif

#ifdef NO_SSL3
#undef BUILD_SSL3
#undef BUILD_SSLV23
#endif

#ifdef BUILD_SSLV23
#include "s23_clnt.c"
#include "s23_srvr.c"
#include "s23_pkt.c"
#include "s23_lib.c"
#include "s23_meth.c"
#endif

#ifdef BUILD_SSLV2
#include "s2_clnt.c"
#include "s2_srvr.c"
#include "s2_pkt.c"
#include "s2_enc.c"
#include "s2_lib.c"
#include "s2_meth.c"
#endif

#ifdef BUILD_SSLV3
#include "s3_clnt.c"
#include "s3_both.c"
#include "s3_srvr.c"
#include "s3_pkt.c"
#include "s3_enc.c"
#include "s3_lib.c"
#include "s3_meth.c"
#endif

#ifdef BUILD_SSL_COMMON
#include "ssl_lib.c"
#include "ssl_algs.c"
#include "ssl_cert.c"
#include "ssl_ciph.c"
#include "ssl_sess.c"
#include "ssl_rsa.c"
#endif

/* Extra things */
#ifdef BUILD_SSL_BIO
#include "bio_ssl.c"
#endif

#ifdef BUILD_SSL_OPTIONAL
#include "ssl_asn1.c"
#include "ssl_txt.c"
#include "ssl_stat.c"
#include "ssl_err.c"
#include "ssl_err2.c"
#endif

