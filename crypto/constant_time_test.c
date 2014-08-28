/* crypto/constant_time_test.c */
/*
 * Utilities for constant-time cryptography.
 *
 * Author: Emilia Kasper (emilia@openssl.org)
 * Based on previous work by Bodo Moeller, Emilia Kasper, Adam Langley
 * (Google).
 * ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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

#include "../crypto/constant_time_locl.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned int CONSTTIME_TRUE = ~0;
static const unsigned int CONSTTIME_FALSE = 0;
static const unsigned char CONSTTIME_TRUE_8 = ~0;
static const unsigned char CONSTTIME_FALSE_8 = 0;

static int test_binary_op(unsigned int (*op)(unsigned int a, unsigned int b),
	const char* op_name, unsigned int a, unsigned int b, int is_true)
	{
	unsigned c = op(a, b);
	if (is_true && c != CONSTTIME_TRUE)
		{
		fprintf(stderr, "Test failed for %s(%du, %du): expected %du "
			"(TRUE), got %du\n", op_name, a, b, CONSTTIME_TRUE, c);
		return 1;
		}
	else if (!is_true && c != CONSTTIME_FALSE)
		{
		fprintf(stderr, "Test failed for  %s(%du, %du): expected %du "
			"(FALSE), got %du\n", op_name, a, b, CONSTTIME_FALSE,
			c);
		return 1;
		}
        return 0;
	}

static int test_binary_op_8(unsigned char (*op)(unsigned int a, unsigned int b),
	const char* op_name, unsigned int a, unsigned int b, int is_true)
	{
	unsigned char c = op(a, b);
	if (is_true && c != CONSTTIME_TRUE_8)
		{
		fprintf(stderr, "Test failed for %s(%du, %du): expected %u "
			"(TRUE), got %u\n", op_name, a, b, CONSTTIME_TRUE_8, c);
		return 1;
		}
	else if (!is_true && c != CONSTTIME_FALSE_8)
		{
		fprintf(stderr, "Test failed for  %s(%du, %du): expected %u "
			"(FALSE), got %u\n", op_name, a, b, CONSTTIME_FALSE_8,
			c);
		return 1;
		}
        return 0;
	}

static int test_is_zero(unsigned int a)
	{
	unsigned int c = constant_time_is_zero(a);
	if (a == 0 && c != CONSTTIME_TRUE)
		{
		fprintf(stderr, "Test failed for constant_time_is_zero(%du): "
			"expected %du (TRUE), got %du\n", a, CONSTTIME_TRUE, c);
		return 1;
		}
	else if (a != 0 && c != CONSTTIME_FALSE)
		{
		fprintf(stderr, "Test failed for constant_time_is_zero(%du): "
			"expected %du (FALSE), got %du\n", a, CONSTTIME_FALSE,
			c);
		return 1;
		}
        return 0;
	}

static int test_is_zero_8(unsigned int a)
	{
	unsigned char c = constant_time_is_zero_8(a);
	if (a == 0 && c != CONSTTIME_TRUE_8)
		{
		fprintf(stderr, "Test failed for constant_time_is_zero(%du): "
			"expected %u (TRUE), got %u\n", a, CONSTTIME_TRUE_8, c);
		return 1;
		}
	else if (a != 0 && c != CONSTTIME_FALSE)
		{
		fprintf(stderr, "Test failed for constant_time_is_zero(%du): "
			"expected %u (FALSE), got %u\n", a, CONSTTIME_FALSE_8,
			c);
		return 1;
		}
        return 0;
	}

static unsigned int test_values[] = {0, 1, 1024, 12345, 32000, UINT_MAX/2-1,
                                     UINT_MAX/2, UINT_MAX/2+1, UINT_MAX-1,
                                     UINT_MAX};

int main(int argc, char *argv[])
	{
	unsigned int a, b, i, j;
	int num_failed = 0, num_all = 0;
	fprintf(stdout, "Testing constant time operations...\n");

	for (i = 0; i < sizeof(test_values)/sizeof(int); ++i)
		{
		a = test_values[i];
		num_failed += test_is_zero(a);
		num_failed += test_is_zero_8(a);
		num_failed += test_binary_op(&constant_time_lt,
			"constant_time_lt", a, a, 0);
		num_failed += test_binary_op_8(&constant_time_lt_8,
			"constant_time_lt_8", a, a, 0);
		num_failed += test_binary_op(&constant_time_ge,
			"constant_time_ge", a, a, 1);
		num_failed += test_binary_op_8(&constant_time_ge_8,
			"constant_time_ge_8", a, a, 1);
		num_failed += test_binary_op(&constant_time_eq,
			"constant_time_eq", a, a, 1);
		num_failed += test_binary_op_8(&constant_time_eq_8,
			"constant_time_eq_8", a, a, 1);
		num_all += 8;
		for (j = i + 1; j < sizeof(test_values)/sizeof(int); ++j)
			{
			b = test_values[j];
			num_failed += test_binary_op(&constant_time_lt,
				"constant_time_lt", a, b, a < b);
			num_failed += test_binary_op_8(&constant_time_lt_8,
				"constant_time_lt_8", a, b, a < b);
			num_failed += test_binary_op(&constant_time_lt,
				"constant_time_lt_8", b, a, b < a);
			num_failed += test_binary_op_8(&constant_time_lt_8,
				"constant_time_lt_8", b, a, b < a);
			num_failed += test_binary_op(&constant_time_ge,
				"constant_time_ge", a, b, a >= b);
			num_failed += test_binary_op_8(&constant_time_ge_8,
				"constant_time_ge_8", a, b, a >= b);
			num_failed += test_binary_op(&constant_time_ge,
				"constant_time_ge", b, a, b >= a);
			num_failed += test_binary_op_8(&constant_time_ge_8,
				"constant_time_ge_8", b, a, b >= a);
			num_failed += test_binary_op(&constant_time_eq,
				"constant_time_eq", a, b, a == b);
			num_failed += test_binary_op_8(&constant_time_eq_8,
				"constant_time_eq_8", a, b, a == b);
			num_failed += test_binary_op(&constant_time_eq,
				"constant_time_eq", b, a, b == a);
			num_failed += test_binary_op_8(&constant_time_eq_8,
				"constant_time_eq_8", b, a, b == a);
			num_all += 12;
			}
		}

	if (!num_failed)
		{
		fprintf(stdout, "ok (ran %d tests)\n", num_all);
		return EXIT_SUCCESS;
		}
	else
		{
		fprintf(stdout, "%d of %d tests failed!\n", num_failed, num_all);
		return EXIT_FAILURE;
		}
	}
