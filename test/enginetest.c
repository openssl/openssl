/*
 * Copyright 2000-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/e_os2.h>

#ifdef OPENSSL_NO_ENGINE
int main(int argc, char *argv[])
{
    printf("No ENGINE support\n");
    return EXIT_SUCCESS;
}
#else
# include <openssl/buffer.h>
# include <openssl/crypto.h>
# include <openssl/engine.h>
# include <openssl/err.h>
# include "testutil.h"

static void display_engine_list(void)
{
    ENGINE *h;
    int loop;

    loop = 0;
    for (h = ENGINE_get_first(); h != NULL; h = ENGINE_get_next(h)) {
        TEST_info("#%d: id = \"%s\", name = \"%s\"",
               loop++, ENGINE_get_id(h), ENGINE_get_name(h));
    }

    /*
     * ENGINE_get_first() increases the struct_ref counter, so we must call
     * ENGINE_free() to decrease it again
     */
    ENGINE_free(h);
}

#define NUMTOADD 512

static int test_engines(void)
{
    ENGINE *block[NUMTOADD];
    char buf[256];
    const char *id, *name;
    ENGINE *ptr;
    int loop;
    int to_return = 0;
    ENGINE *new_h1 = NULL;
    ENGINE *new_h2 = NULL;
    ENGINE *new_h3 = NULL;
    ENGINE *new_h4 = NULL;

    memset(block, 0, sizeof(block));
    if (!TEST_ptr(new_h1 = ENGINE_new())
            || !TEST_true(ENGINE_set_id(new_h1, "test_id0"))
            || !TEST_true(ENGINE_set_name(new_h1, "First test item"))
            || !TEST_ptr(new_h2 = ENGINE_new())
            || !TEST_true(ENGINE_set_id(new_h2, "test_id1"))
            || !TEST_true(ENGINE_set_name(new_h2, "Second test item"))
            || !TEST_ptr(new_h3 = ENGINE_new())
            || !TEST_true(ENGINE_set_id(new_h3, "test_id2"))
            || !TEST_true(ENGINE_set_name(new_h3, "Third test item"))
            || !TEST_ptr(new_h4 = ENGINE_new())
            || !TEST_true(ENGINE_set_id(new_h4, "test_id3"))
            || !TEST_true(ENGINE_set_name(new_h4, "Fourth test item")))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_add(new_h1)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    ptr = ENGINE_get_first();
    if (!TEST_true(ENGINE_remove(ptr)))
        goto end;
    ENGINE_free(ptr);
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_add(new_h3))
            || !TEST_true(ENGINE_add(new_h2)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_remove(new_h2)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_add(new_h4)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    /* Should fail. */
    if (!TEST_false(ENGINE_add(new_h3)))
        goto end;
    ERR_clear_error();

    /* Should fail. */
    if (!TEST_false(ENGINE_remove(new_h2)))
        goto end;
    ERR_clear_error();

    if (!TEST_true(ENGINE_remove(new_h3)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_remove(new_h4)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    /*
     * Depending on whether there's any hardware support compiled in, this
     * remove may be destined to fail.
     */
    if ((ptr = ENGINE_get_first()) != NULL) {
        if (!ENGINE_remove(ptr))
            TEST_info("Remove failed - probably no hardware support present");
    }
    ENGINE_free(ptr);
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(ENGINE_add(new_h1))
            || !TEST_true(ENGINE_remove(new_h1)))
        goto end;

    TEST_info("About to beef up the engine-type list");
    for (loop = 0; loop < NUMTOADD; loop++) {
        sprintf(buf, "id%d", loop);
        id = OPENSSL_strdup(buf);
        sprintf(buf, "Fake engine type %d", loop);
        name = OPENSSL_strdup(buf);
        if (!TEST_ptr(block[loop] = ENGINE_new())
                || !TEST_true(ENGINE_set_id(block[loop], id))
                || !TEST_true(ENGINE_set_name(block[loop], name)))
            goto end;
    }
    for (loop = 0; loop < NUMTOADD; loop++) {
        if (!TEST_true(ENGINE_add(block[loop]))) {
            test_note("Adding stopped at %d, (%s,%s)",
                      loop, ENGINE_get_id(block[loop]),
                      ENGINE_get_name(block[loop]));
            goto cleanup_loop;
        }
    }
 cleanup_loop:
    TEST_info("About to empty the engine-type list");
    while ((ptr = ENGINE_get_first()) != NULL) {
        if (!TEST_true(ENGINE_remove(ptr)))
            goto end;
        ENGINE_free(ptr);
    }
    for (loop = 0; loop < NUMTOADD; loop++) {
        OPENSSL_free((void *)ENGINE_get_id(block[loop]));
        OPENSSL_free((void *)ENGINE_get_name(block[loop]));
    }
    to_return = 1;

 end:
    ENGINE_free(new_h1);
    ENGINE_free(new_h2);
    ENGINE_free(new_h3);
    ENGINE_free(new_h4);
    for (loop = 0; loop < NUMTOADD; loop++)
        ENGINE_free(block[loop]);
    return to_return;
}

void register_tests(void)
{
    ADD_TEST(test_engines);
}
#endif
