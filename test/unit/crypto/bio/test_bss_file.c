/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef OPENSSL_NO_STDIO

int main(void)
{
    return 0;
}

#else

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "bio_local.h"

#include <openssl/bio.h>
#include <openssl/err.h>

static char fake_file_a;
static char fake_file_b;
#define FAKE_FP ((FILE *)&fake_file_a)
#define FAKE_FP2 ((FILE *)&fake_file_b)

/* wraps */

FILE *__wrap_openssl_fopen(const char *filename, const char *mode);
size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb,
    FILE *stream);
int __wrap_fseek(FILE *stream, long offset, int whence);
long __wrap_ftell(FILE *stream);
int __wrap_feof(FILE *stream);
int __wrap_ferror(FILE *stream);
int __wrap_fclose(FILE *stream);
int __wrap_fflush(FILE *stream);
char *__wrap_fgets(char *s, int size, FILE *stream);

FILE *__wrap_openssl_fopen(const char *filename, const char *mode)
{
    FILE *fp;

    function_called();
    check_expected(filename);
    check_expected(mode);
    fp = mock_ptr_type(FILE *);
    if (fp == NULL)
        errno = mock_type(int);
    return fp;
}

size_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    function_called();
    check_expected_ptr(ptr);
    check_expected(size);
    check_expected(nmemb);
    check_expected_ptr(stream);
    return mock_type(size_t);
}

size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    function_called();
    check_expected_ptr(ptr);
    check_expected(size);
    check_expected(nmemb);
    check_expected_ptr(stream);
    return mock_type(size_t);
}

int __wrap_fseek(FILE *stream, long offset, int whence)
{
    function_called();
    check_expected_ptr(stream);
    check_expected(offset);
    check_expected(whence);
    return mock_type(int);
}

long __wrap_ftell(FILE *stream)
{
    function_called();
    check_expected_ptr(stream);
    return mock_type(long);
}

int __wrap_feof(FILE *stream)
{
    function_called();
    check_expected_ptr(stream);
    return mock_type(int);
}

int __wrap_ferror(FILE *stream)
{
    function_called();
    check_expected_ptr(stream);
    return mock_type(int);
}

int __wrap_fclose(FILE *stream)
{
    function_called();
    check_expected_ptr(stream);
    return mock_type(int);
}

int __wrap_fflush(FILE *stream)
{
    function_called();
    check_expected_ptr(stream);
    return mock_type(int);
}

char *__wrap_fgets(char *s, int size, FILE *stream)
{
    const char *data;

    function_called();
    check_expected_ptr(s);
    check_expected(size);
    check_expected_ptr(stream);
    data = mock_ptr_type(const char *);
    if (data == NULL)
        return NULL;
    assert_true(strlen(data) < (size_t)size);
    strcpy(s, data);
    return s;
}

/* expectations */

/* errnoval is consumed by __wrap_openssl_fopen only when rc == NULL */
static void expect_openssl_fopen(const char *filename, const char *mode,
    FILE *rc, int errnoval)
{
    expect_function_call(__wrap_openssl_fopen);
    expect_string(__wrap_openssl_fopen, filename, filename);
    expect_string(__wrap_openssl_fopen, mode, mode);
    will_return(__wrap_openssl_fopen, rc);
    if (rc == NULL)
        will_return(__wrap_openssl_fopen, errnoval);
}

static void expect_fread(void *ptr, size_t nmemb, FILE *stream, size_t rc)
{
    expect_function_call(__wrap_fread);
    expect_value(__wrap_fread, ptr, ptr);
    expect_value(__wrap_fread, size, 1);
    expect_value(__wrap_fread, nmemb, nmemb);
    expect_value(__wrap_fread, stream, stream);
    will_return(__wrap_fread, rc);
}

static void expect_fwrite(const void *ptr, size_t nmemb, FILE *stream,
    size_t rc)
{
    expect_function_call(__wrap_fwrite);
    expect_value(__wrap_fwrite, ptr, ptr);
    expect_value(__wrap_fwrite, size, 1);
    expect_value(__wrap_fwrite, nmemb, nmemb);
    expect_value(__wrap_fwrite, stream, stream);
    will_return(__wrap_fwrite, rc);
}

static void expect_fseek(FILE *stream, long offset, int whence, int rc)
{
    expect_function_call(__wrap_fseek);
    expect_value(__wrap_fseek, stream, stream);
    expect_value(__wrap_fseek, offset, offset);
    expect_value(__wrap_fseek, whence, whence);
    will_return(__wrap_fseek, rc);
}

static void expect_ftell(FILE *stream, long rc)
{
    expect_function_call(__wrap_ftell);
    expect_value(__wrap_ftell, stream, stream);
    will_return(__wrap_ftell, rc);
}

static void expect_feof(FILE *stream, int rc)
{
    expect_function_call(__wrap_feof);
    expect_value(__wrap_feof, stream, stream);
    will_return(__wrap_feof, rc);
}

static void expect_ferror(FILE *stream, int rc)
{
    expect_function_call(__wrap_ferror);
    expect_value(__wrap_ferror, stream, stream);
    will_return(__wrap_ferror, rc);
}

static void expect_fclose(FILE *stream, int rc)
{
    expect_function_call(__wrap_fclose);
    expect_value(__wrap_fclose, stream, stream);
    will_return(__wrap_fclose, rc);
}

static void expect_fflush(FILE *stream, int rc)
{
    expect_function_call(__wrap_fflush);
    expect_value(__wrap_fflush, stream, stream);
    will_return(__wrap_fflush, rc);
}

/* data is copied into the caller's buffer by __wrap_fgets; NULL means EOF */
static void expect_fgets(char *s, int size, FILE *stream, const char *data)
{
    expect_function_call(__wrap_fgets);
    expect_value(__wrap_fgets, s, s);
    expect_value(__wrap_fgets, size, size);
    expect_value(__wrap_fgets, stream, stream);
    will_return(__wrap_fgets, data);
}

/* setup / teardown */

static int setup(void **state)
{
    BIO *bio = BIO_new(BIO_s_file());

    assert_non_null(bio);
    BIO_set_fp(bio, FAKE_FP, BIO_NOCLOSE);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

/* BIO_new_file */

static void test_new_file_success(void **state)
{
    BIO *bio;
    FILE *fp = NULL;

    (void)state;
    expect_openssl_fopen("test.txt", "r", FAKE_FP, 0);
    bio = BIO_new_file("test.txt", "r");
    assert_non_null(bio);
    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP);
    assert_int_equal(BIO_get_close(bio), BIO_CLOSE);

    expect_fclose(FAKE_FP, 0);
    BIO_free(bio);
}

static void test_new_file_binary_mode(void **state)
{
    BIO *bio;

    (void)state;
    expect_openssl_fopen("test.bin", "rb", FAKE_FP, 0);
    bio = BIO_new_file("test.bin", "rb");
    assert_non_null(bio);

    expect_fclose(FAKE_FP, 0);
    BIO_free(bio);
}

static void test_new_file_no_such_file(void **state)
{
    (void)state;
    ERR_clear_error();
    expect_openssl_fopen("missing.txt", "r", NULL, ENOENT);
    assert_null(BIO_new_file("missing.txt", "r"));
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()),
        BIO_R_NO_SUCH_FILE);
}

static void test_new_file_sys_error(void **state)
{
    (void)state;
    ERR_clear_error();
    expect_openssl_fopen("secret.txt", "r", NULL, EACCES);
    assert_null(BIO_new_file("secret.txt", "r"));
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()), ERR_R_SYS_LIB);
}

static void test_new_file_null_filename(void **state)
{
    (void)state;
    ERR_clear_error();
    assert_null(BIO_new_file(NULL, "r"));
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()),
        ERR_R_PASSED_NULL_PARAMETER);
}

/* BIO_new_fp */

static void test_new_fp_noclose(void **state)
{
    BIO *bio;
    FILE *fp = NULL;

    (void)state;
    bio = BIO_new_fp(FAKE_FP, BIO_NOCLOSE);
    assert_non_null(bio);
    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP);
    assert_int_equal(BIO_get_close(bio), BIO_NOCLOSE);
    BIO_free(bio);
}

static void test_new_fp_close(void **state)
{
    BIO *bio;

    (void)state;
    bio = BIO_new_fp(FAKE_FP, BIO_CLOSE);
    assert_non_null(bio);
    assert_int_equal(BIO_get_close(bio), BIO_CLOSE);

    expect_fclose(FAKE_FP, 0);
    BIO_free(bio);
}

/* file_read (via BIO_read) */

static void test_file_read_success(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fread(buf, 8, FAKE_FP, 8);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
}

static void test_file_read_short(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fread(buf, 8, FAKE_FP, 3);
    assert_int_equal(BIO_read(bio, buf, 8), 3);
}

static void test_file_read_eof(void **state)
{
    /*
     * fread returns 0 without ferror: plain EOF, no error is raised.
     * The two trailing feof calls come from outside bss_file.c: one from
     * bread_conv and one from bio_read_intern, which both query
     * BIO_CTRL_EOF when the method's read reports 0 bytes.
     */
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fread(buf, 8, FAKE_FP, 0);
    expect_ferror(FAKE_FP, 0);
    expect_feof(FAKE_FP, 1);
    expect_feof(FAKE_FP, 1);
    assert_int_equal(BIO_read(bio, buf, 8), 0);
}

static void test_file_read_error(void **state)
{
    /* fread returns 0 with ferror set: -1 and ERR_R_SYS_LIB is raised */
    BIO *bio = *state;
    char buf[8] = { 0 };

    ERR_clear_error();
    expect_fread(buf, 8, FAKE_FP, 0);
    expect_ferror(FAKE_FP, 1);
    assert_int_equal(BIO_read(bio, buf, 8), -1);
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()), ERR_R_SYS_LIB);
}

static void test_file_read_zero_length(void **state)
{
    /* outl == 0 never reaches fread */
    BIO *bio = *state;
    char buf[8] = { 0 };

    assert_true(BIO_read(bio, buf, 0) <= 0);
}

/* file_write (via BIO_write) */

static void test_file_write_success(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fwrite(buf, 5, FAKE_FP, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
}

static void test_file_write_partial(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fwrite(buf, 5, FAKE_FP, 3);
    assert_int_equal(BIO_write(bio, buf, 5), 3);
}

static void test_file_write_fails(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fwrite(buf, 5, FAKE_FP, 0);
    assert_true(BIO_write(bio, buf, 5) <= 0);
}

/* file_ctrl (via BIO_ctrl) */

static void test_file_ctrl_reset(void **state)
{
    BIO *bio = *state;

    expect_fseek(FAKE_FP, 0, 0, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL), 0);
}

static void test_file_ctrl_seek(void **state)
{
    BIO *bio = *state;

    expect_fseek(FAKE_FP, 512, 0, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_SEEK, 512, NULL), 0);
}

static void test_file_ctrl_seek_fails(void **state)
{
    BIO *bio = *state;

    expect_fseek(FAKE_FP, 512, 0, -1);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_SEEK, 512, NULL), -1);
}

static void test_file_ctrl_tell(void **state)
{
    BIO *bio = *state;

    expect_ftell(FAKE_FP, 256);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_TELL, 0, NULL), 256);
}

static void test_file_ctrl_info(void **state)
{
    BIO *bio = *state;

    /* BIO_CTRL_INFO shares the ftell branch with FILE_TELL */
    expect_ftell(FAKE_FP, 128);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_INFO, 0, NULL), 128);
}

static void test_file_ctrl_eof_clear(void **state)
{
    BIO *bio = *state;

    expect_feof(FAKE_FP, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);
}

static void test_file_ctrl_eof_set(void **state)
{
    /* any non-zero feof result is mapped to 1 by double negation */
    BIO *bio = *state;

    expect_feof(FAKE_FP, 7);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
}

static void test_file_ctrl_set_fp_replaces(void **state)
{
    /* shutdown=BIO_NOCLOSE: the old fp is dropped without fclose */
    BIO *bio = *state;
    FILE *fp = NULL;

    BIO_set_fp(bio, FAKE_FP2, BIO_NOCLOSE);
    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP2);
    assert_int_equal(bio->init, 1);
}

static void test_file_ctrl_set_fp_closes_old(void **state)
{
    /* shutdown=BIO_CLOSE: the old fp is fclosed before the replacement */
    BIO *bio = *state;
    FILE *fp = NULL;

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    expect_fclose(FAKE_FP, 0);
    BIO_set_fp(bio, FAKE_FP2, BIO_NOCLOSE);
    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP2);
    assert_int_equal(BIO_get_close(bio), BIO_NOCLOSE);
}

static void test_file_ctrl_get_fp(void **state)
{
    BIO *bio = *state;
    FILE *fp = NULL;

    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP);
}

static void set_filename_test(BIO *bio, long flags, const char *mode)
{
    FILE *fp = NULL;

    expect_openssl_fopen("file.txt", mode, FAKE_FP2, 0);
    assert_int_equal(
        BIO_ctrl(bio, BIO_C_SET_FILENAME, flags, (void *)"file.txt"), 1);
    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP2);
}

static void test_file_ctrl_set_filename_read(void **state)
{
    set_filename_test(*state, BIO_FP_READ, "r");
}

static void test_file_ctrl_set_filename_write(void **state)
{
    set_filename_test(*state, BIO_FP_WRITE, "w");
}

static void test_file_ctrl_set_filename_read_write(void **state)
{
    set_filename_test(*state, BIO_FP_READ | BIO_FP_WRITE, "r+");
}

static void test_file_ctrl_set_filename_append(void **state)
{
    set_filename_test(*state, BIO_FP_APPEND, "a");
}

static void test_file_ctrl_set_filename_append_read(void **state)
{
    set_filename_test(*state, BIO_FP_APPEND | BIO_FP_READ, "a+");
}

static void test_file_ctrl_set_filename_close_flag(void **state)
{
    BIO *bio = *state;

    expect_openssl_fopen("file.txt", "r", FAKE_FP2, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_FILENAME,
                         BIO_CLOSE | BIO_FP_READ, (void *)"file.txt"),
        1);
    assert_int_equal(BIO_get_close(bio), BIO_CLOSE);
    /* Restore before teardown to avoid an unexpected fclose call. */
    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
}

static void test_file_ctrl_set_filename_bad_mode(void **state)
{
    /* no BIO_FP_* mode flag at all: BIO_R_BAD_FOPEN_MODE, no fopen call */
    BIO *bio = *state;

    ERR_clear_error();
    assert_int_equal(
        BIO_ctrl(bio, BIO_C_SET_FILENAME, 0, (void *)"file.txt"), 0);
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()),
        BIO_R_BAD_FOPEN_MODE);
}

static void test_file_ctrl_set_filename_null(void **state)
{
    BIO *bio = *state;

    ERR_clear_error();
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_FILENAME, BIO_FP_READ, NULL), 0);
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()),
        ERR_R_PASSED_NULL_PARAMETER);
}

static void test_file_ctrl_set_filename_fopen_fails(void **state)
{
    BIO *bio = *state;

    ERR_clear_error();
    expect_openssl_fopen("file.txt", "r", NULL, EACCES);
    assert_int_equal(
        BIO_ctrl(bio, BIO_C_SET_FILENAME, BIO_FP_READ, (void *)"file.txt"),
        0);
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()), ERR_R_SYS_LIB);
}

static void test_file_ctrl_get_close(void **state)
{
    BIO *bio = *state;

    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL),
        BIO_NOCLOSE);
    bio->shutdown = BIO_CLOSE;
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL), BIO_CLOSE);
    bio->shutdown = BIO_NOCLOSE;
}

static void test_file_ctrl_set_close(void **state)
{
    BIO *bio = *state;

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    assert_int_equal(bio->shutdown, BIO_CLOSE);
    /* Restore before teardown to avoid an unexpected fclose call. */
    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL);
}

static void test_file_ctrl_flush(void **state)
{
    BIO *bio = *state;

    expect_fflush(FAKE_FP, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 1);
}

static void test_file_ctrl_flush_fails(void **state)
{
    BIO *bio = *state;

    ERR_clear_error();
    expect_fflush(FAKE_FP, EOF);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL), 0);
    assert_int_equal(ERR_GET_REASON(ERR_peek_last_error()), ERR_R_SYS_LIB);
}

static void test_file_ctrl_dup(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_DUP, 0, NULL), 1);
}

static void test_file_ctrl_pending(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_PENDING, 0, NULL), 0);
}

static void test_file_ctrl_wpending(void **state)
{
    assert_int_equal(BIO_ctrl(*state, BIO_CTRL_WPENDING, 0, NULL), 0);
}

static void test_file_ctrl_default(void **state)
{
    assert_int_equal(BIO_ctrl(*state, 9999, 0, NULL), 0);
}

/* file_gets (via BIO_gets) */

static void test_file_gets_success(void **state)
{
    BIO *bio = *state;
    char buf[16] = { 0 };

    expect_fgets(buf, (int)sizeof(buf), FAKE_FP, "hi\n");
    assert_int_equal(BIO_gets(bio, buf, (int)sizeof(buf)), 3);
    assert_string_equal(buf, "hi\n");
}

static void test_file_gets_empty(void **state)
{
    /* fgets succeeds but stores an empty string: 0 is returned */
    BIO *bio = *state;
    char buf[16] = { 'x' };

    expect_fgets(buf, (int)sizeof(buf), FAKE_FP, "");
    assert_int_equal(BIO_gets(bio, buf, (int)sizeof(buf)), 0);
    assert_int_equal(buf[0], '\0');
}

static void test_file_gets_eof(void **state)
{
    /* fgets returns NULL: 0 is returned and the buffer is cleared */
    BIO *bio = *state;
    char buf[16] = { 'x' };

    expect_fgets(buf, (int)sizeof(buf), FAKE_FP, NULL);
    assert_int_equal(BIO_gets(bio, buf, (int)sizeof(buf)), 0);
    assert_int_equal(buf[0], '\0');
}

/* file_puts (via BIO_puts) */

static void test_file_puts_success(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_fwrite(str, 5, FAKE_FP, 5);
    assert_int_equal(BIO_puts(bio, str), 5);
}

static void test_file_puts_write_fails(void **state)
{
    BIO *bio = *state;
    const char *str = "hello";

    expect_fwrite(str, 5, FAKE_FP, 0);
    assert_true(BIO_puts(bio, str) <= 0);
}

/* file_free (via BIO_free) */

static void test_file_free_shutdown_closes(void **state)
{
    /* shutdown=1, init=1 and ptr set: fclose must be called */
    BIO *bio = BIO_new(BIO_s_file());

    (void)state;
    assert_non_null(bio);
    bio->ptr = FAKE_FP;
    bio->init = 1;
    bio->shutdown = BIO_CLOSE;

    expect_fclose(FAKE_FP, 0);
    BIO_free(bio);
}

static void test_file_free_no_shutdown(void **state)
{
    /* shutdown=0: fclose must NOT be called regardless of init */
    BIO *bio = BIO_new(BIO_s_file());

    (void)state;
    assert_non_null(bio);
    bio->ptr = FAKE_FP;
    bio->init = 1;
    bio->shutdown = BIO_NOCLOSE;

    BIO_free(bio);
}

static void test_file_free_shutdown_no_init(void **state)
{
    /* shutdown=1 but init=0: fclose must NOT be called */
    BIO *bio = BIO_new(BIO_s_file());

    (void)state;
    assert_non_null(bio);
    bio->ptr = FAKE_FP;
    bio->init = 0;
    bio->shutdown = BIO_CLOSE;

    BIO_free(bio);
}

static void test_file_free_shutdown_null_ptr(void **state)
{
    /* shutdown=1, init=1 but ptr=NULL: fclose must NOT be called */
    BIO *bio = BIO_new(BIO_s_file());

    (void)state;
    assert_non_null(bio);
    bio->ptr = NULL;
    bio->init = 1;
    bio->shutdown = BIO_CLOSE;

    BIO_free(bio);
}

/* main */

#define FILE_TEST(name) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

#define FILE_TEST_PLAIN(name) \
    cmocka_unit_test(name)

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* BIO_new_file */
        FILE_TEST_PLAIN(test_new_file_success),
        FILE_TEST_PLAIN(test_new_file_binary_mode),
        FILE_TEST_PLAIN(test_new_file_no_such_file),
        FILE_TEST_PLAIN(test_new_file_sys_error),
        FILE_TEST_PLAIN(test_new_file_null_filename),
        /* BIO_new_fp */
        FILE_TEST_PLAIN(test_new_fp_noclose),
        FILE_TEST_PLAIN(test_new_fp_close),
        /* file_read */
        FILE_TEST(test_file_read_success),
        FILE_TEST(test_file_read_short),
        FILE_TEST(test_file_read_eof),
        FILE_TEST(test_file_read_error),
        FILE_TEST(test_file_read_zero_length),
        /* file_write */
        FILE_TEST(test_file_write_success),
        FILE_TEST(test_file_write_partial),
        FILE_TEST(test_file_write_fails),
        /* file_ctrl */
        FILE_TEST(test_file_ctrl_reset),
        FILE_TEST(test_file_ctrl_seek),
        FILE_TEST(test_file_ctrl_seek_fails),
        FILE_TEST(test_file_ctrl_tell),
        FILE_TEST(test_file_ctrl_info),
        FILE_TEST(test_file_ctrl_eof_clear),
        FILE_TEST(test_file_ctrl_eof_set),
        FILE_TEST(test_file_ctrl_set_fp_replaces),
        FILE_TEST(test_file_ctrl_set_fp_closes_old),
        FILE_TEST(test_file_ctrl_get_fp),
        FILE_TEST(test_file_ctrl_set_filename_read),
        FILE_TEST(test_file_ctrl_set_filename_write),
        FILE_TEST(test_file_ctrl_set_filename_read_write),
        FILE_TEST(test_file_ctrl_set_filename_append),
        FILE_TEST(test_file_ctrl_set_filename_append_read),
        FILE_TEST(test_file_ctrl_set_filename_close_flag),
        FILE_TEST(test_file_ctrl_set_filename_bad_mode),
        FILE_TEST(test_file_ctrl_set_filename_null),
        FILE_TEST(test_file_ctrl_set_filename_fopen_fails),
        FILE_TEST(test_file_ctrl_get_close),
        FILE_TEST(test_file_ctrl_set_close),
        FILE_TEST(test_file_ctrl_flush),
        FILE_TEST(test_file_ctrl_flush_fails),
        FILE_TEST(test_file_ctrl_dup),
        FILE_TEST(test_file_ctrl_pending),
        FILE_TEST(test_file_ctrl_wpending),
        FILE_TEST(test_file_ctrl_default),
        /* file_gets */
        FILE_TEST(test_file_gets_success),
        FILE_TEST(test_file_gets_empty),
        FILE_TEST(test_file_gets_eof),
        /* file_puts */
        FILE_TEST(test_file_puts_success),
        FILE_TEST(test_file_puts_write_fails),
        /* file_free */
        FILE_TEST_PLAIN(test_file_free_shutdown_closes),
        FILE_TEST_PLAIN(test_file_free_no_shutdown),
        FILE_TEST_PLAIN(test_file_free_shutdown_no_init),
        FILE_TEST_PLAIN(test_file_free_shutdown_null_ptr),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif /* OPENSSL_NO_STDIO */
