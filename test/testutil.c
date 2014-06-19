/* test/testutil.c */
/*
 * Utilities for writing OpenSSL unit tests.
 *
 * More information:
 * http://wiki.openssl.org/index.php/How_To_Write_Unit_Tests_For_OpenSSL
 *
 * Author: Mike Bland (mbland@acm.org)
 * Date:   2014-07-15
 * ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 */

#include "testutil.h"

#include <stdlib.h>
#include <stdio.h>

/* Declares the structures needed to register each test case function.
 */
typedef struct test_info
	{
	const char* test_case_name;
	int (*test_fn)();
	} TEST_INFO;

static TEST_INFO all_tests[1024];
static int num_tests = 0;

void add_test(const char* test_case_name, int (*test_fn)())
	{
	all_tests[num_tests].test_case_name = test_case_name;
	all_tests[num_tests].test_fn = test_fn;
	++num_tests;
	}

int run_tests(const char* test_prog_name)
	{
	int num_failed = 0;
	int i = 0;

	printf("%s: %d test case%s\n", test_prog_name, num_tests,
		num_tests == 1 ? "" : "s");
	for (i = 0; i != num_tests; ++i)
		{
		if (all_tests[i].test_fn())
			{
			printf("** %s failed **\n--------\n",
				all_tests[i].test_case_name);
			++num_failed;
			}
		}

	if (num_failed != 0)
		{
		printf("%s: %d test%s failed (out of %d)\n", test_prog_name,
			num_failed, num_failed != 1 ? "s" : "", num_tests);
		return EXIT_FAILURE;
		}
	printf("  All tests passed.\n");
	return EXIT_SUCCESS;
	}
