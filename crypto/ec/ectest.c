/* crypto/ec/ectest.c */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>


#ifdef OPENSSL_NO_EC
int main(int argc, char * argv[]) { puts("Elliptic curves are disabled."); return 0; }
#else


#include <openssl/ec.h>
#include <openssl/err.h>

#define ABORT do { \
	fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	exit(1); \
} while (0)

int main(int argc, char *argv[])
	{	
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	unsigned char buf[100];
	size_t i, len;
	
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();

#if 0 /* optional */
	ctx = BN_CTX_new();
	if (!ctx) ABORT;
#endif

	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;

	if (!BN_hex2bn(&p, "D")) ABORT;
	if (!BN_hex2bn(&a, "7")) ABORT;
	if (!BN_hex2bn(&b, "C")) ABORT;
	
	group = EC_GROUP_new(EC_GFp_mont_method());
	if (!group) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;
	if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) ABORT;

	fprintf(stdout, "Curve defined by Weierstrass equation\n     y^2 = x^3 + a*x + b  (mod 0x");
	BN_print_fp(stdout, p);
	fprintf(stdout, ")\n     a = 0x");
	BN_print_fp(stdout, a);
	fprintf(stdout, "\n     b = 0x");
	BN_print_fp(stdout, b);
	fprintf(stdout, "\n");

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;
	
	if (!EC_POINT_set_to_infinity(group, P)) ABORT;
	if (!EC_POINT_is_at_infinity(group, P)) ABORT;

	buf[0] = 0;
	if (!EC_POINT_oct2point(group, Q, buf, 1, ctx)) ABORT;

	if (!EC_POINT_add(group, P, P, Q, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, P)) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

	if (!BN_hex2bn(&x, "C")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, Q, x, 1, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, Q, ctx))
		{
		if (!EC_POINT_get_affine_coordinates_GFp(group, Q, x, y, ctx)) ABORT;
		fprintf(stderr, "Point is not on curve: x = 0x");
		BN_print_fp(stderr, x);
		fprintf(stderr, ", y = 0x");
		BN_print_fp(stderr, y);
		fprintf(stderr, "\n");
		ABORT;
		}

	fprintf(stdout, "A cyclic subgroup:\n");
	do
		{
		if (EC_POINT_is_at_infinity(group, P))
			fprintf(stdout, "     point at infinity\n");
		else
			{
			if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;

			fprintf(stdout, "     x = 0x");
			BN_print_fp(stdout, x);
			fprintf(stdout, ", y = 0x");
			BN_print_fp(stdout, y);
			fprintf(stdout, "\n");
			}
		
		if (!EC_POINT_copy(R, P)) ABORT;
		if (!EC_POINT_add(group, P, P, Q, ctx)) ABORT;

#if 0 /* optional */
		if (!EC_POINT_make_affine(group, P, ctx)) ABORT;
#endif
		}
	while (!EC_POINT_is_at_infinity(group, P));

	if (!EC_POINT_add(group, P, Q, R, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, P)) ABORT;

	len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED, buf, sizeof buf, ctx);
	if (len == 0) ABORT;
	if (!EC_POINT_oct2point(group, P, buf, len, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, P, Q, ctx)) ABORT;
	fprintf(stdout, "Generator as octect string, compressed form:\n     ");
	for (i = 0; i < len; i++) fprintf(stdout, "%02X", buf[i]);
	
	len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof buf, ctx);
	if (len == 0) ABORT;
	if (!EC_POINT_oct2point(group, P, buf, len, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, P, Q, ctx)) ABORT;
	fprintf(stdout, "\nGenerator as octect string, uncompressed form:\n     ");
	for (i = 0; i < len; i++) fprintf(stdout, "%02X", buf[i]);
	
	len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_HYBRID, buf, sizeof buf, ctx);
	if (len == 0) ABORT;
	if (!EC_POINT_oct2point(group, P, buf, len, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, P, Q, ctx)) ABORT;
	fprintf(stdout, "\nGenerator as octect string, hybrid form:\n     ");
	for (i = 0; i < len; i++) fprintf(stdout, "%02X", buf[i]);
	
	if (!EC_POINT_get_Jprojective_coordinates_GFp(group, R, x, y, z, ctx)) ABORT;
	fprintf(stdout, "\nA representation of the inverse of that generator in\nJacobian projective coordinates:\n     X = 0x");
	BN_print_fp(stdout, x);
	fprintf(stdout, ", Y = 0x");
	BN_print_fp(stdout, y);
	fprintf(stdout, ", Z = 0x");
	BN_print_fp(stdout, z);
	fprintf(stdout, "\n");

	if (!EC_POINT_invert(group, P, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, P, R, ctx)) ABORT;

	/* ... */

	if (ctx)
		BN_CTX_free(ctx);
	BN_free(p); BN_free(a);	BN_free(b);
	EC_GROUP_free(group);
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	BN_free(x); BN_free(y); BN_free(z);

	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
	
	return 0;
	}
#endif
