/*	$OpenBSD$	*/

/*
 * Copyright (c) 2014 Miodrag Vallat.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/*
 * Test for proper bn_mul_mont behaviour when operands are of vastly different
 * sizes.
 */

int
main(int argc, char *argv[])
{
	DH *dh;
	unsigned char *key, r[32 + 16 * 8];
	size_t privsz;

	RAND_bytes(r, sizeof r);

	for (privsz = 32; privsz <= sizeof(r); privsz += 8) {
		dh = DH_new();
		if (dh == NULL)
			goto err;
		if (DH_generate_parameters_ex(dh, 32, DH_GENERATOR_2,
		    NULL) == 0)
			goto err;

		/* force private key to be much larger than public one */
		dh->priv_key = BN_bin2bn(r, privsz, NULL);
		if (dh->priv_key == NULL)
			goto err;

		if (DH_generate_key(dh) == 0)
			goto err;
		key = malloc(DH_size(dh));
		if (key == NULL)
			err(1, "malloc");
		if (DH_compute_key(key, dh->pub_key, dh) == -1)
			goto err;

		free(key);
		DH_free(dh);
	}

	return 0;

err:
	ERR_print_errors_fp(stderr);
	return 1;
}
