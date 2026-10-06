/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Windows-only side test for bss_file.c Windows-specific paths.
 * Uses Microsoft Detours to intercept CRT stdio calls at runtime.
 * Does NOT replace the normal --wrap-based bss_file test; it only
 * covers branches that differ under OPENSSL_SYS_WINDOWS: the feof
 * EINVAL quirk, the GetFileType guard around ftell, the _setmode
 * text/binary handling, the "b"/"t" fopen mode suffix, and (on
 * uplink builds) the UP_* applink dispatch.
 *
 * The CRT interception relies on the test executable and libcrypto
 * resolving stdio to the same CRT (the /MD default, where both use
 * ucrtbase.dll); Detours patches the function bodies there, so calls
 * from either module land in the mocks, and errno set by a mock is
 * visible to libcrypto since the per-thread errno lives in the shared
 * CRT. On uplink builds the applink table is populated with this
 * executable's CRT functions (ms/applink.c is linked in), which the
 * same detours intercept.
 *
 * NOTE: not compiled/verified by the author's toolchain. The first
 * test (detour_probe) is a hard gate: if Detours does not intercept
 * cross-module CRT calls, every other result is meaningless.
 */

#include "openssl/e_os2.h"

#if defined(OPENSSL_NO_STDIO) || !defined(OPENSSL_SYS_WINDOWS)
int main(void)
{
    return 0;
}
#else

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <wchar.h>
#include <errno.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <detours/detours.h>

#include "internal/sockets.h"
#include "bio_local.h"

#include <openssl/bio.h>
#include <openssl/err.h>

static char fake_file_a;
static char fake_file_b;
#define FAKE_FP ((FILE *)&fake_file_a)
#define FAKE_FP2 ((FILE *)&fake_file_b)
#define FAKE_FD 7
#define FAKE_OSFHANDLE ((intptr_t)0x1234)

/*
 * Real function pointers. After DetourAttach commits, Detours rewrites
 * these to trampolines pointing at the original code.
 */
static int(__cdecl *real_feof)(FILE *) = feof;
static long(__cdecl *real_ftell)(FILE *) = ftell;
static size_t(__cdecl *real_fread)(void *, size_t, size_t, FILE *) = fread;
static size_t(__cdecl *real_fwrite)(const void *, size_t, size_t, FILE *)
    = fwrite;
static int(__cdecl *real_fclose)(FILE *) = fclose;
static int(__cdecl *real_fileno)(FILE *) = _fileno;
static int(__cdecl *real_setmode)(int, int) = _setmode;
static intptr_t(__cdecl *real_get_osfhandle)(int) = _get_osfhandle;
static FILE *(__cdecl *real_wfopen)(const wchar_t *, const wchar_t *)
    = _wfopen;
static DWORD(WINAPI *real_GetFileType)(HANDLE) = GetFileType;

/*
 * The detours are installed process-wide for the whole run, but the CRT
 * (and cmocka itself) call some of these functions internally -- most
 * importantly _fileno, which the stdio write path invokes on every
 * printf/fwrite used to emit the TAP output. If a mock enforced cmocka
 * expectations on those internal calls it would recurse (an unexpected
 * call makes cmocka print an error, which calls _fileno again, ...) and
 * blow the stack. So a mock only enforces expectations while a test has
 * explicitly armed it via g_mocks_armed; otherwise it forwards to the
 * real function through the Detours trampoline. Each mock also disarms
 * around its own cmocka calls so that a failing expectation can report
 * cleanly (its error output would otherwise re-enter the mock).
 */
static int g_mocks_armed;

static void mocks_arm(void)
{
    g_mocks_armed = 1;
}

static void mocks_disarm(void)
{
    g_mocks_armed = 0;
}

/*
 * detour_probe uses this to confirm the mock actually fired. It is the
 * only place a mock is allowed to run outside a cmocka expectation, so
 * mock_feof special-cases it.
 */
static int g_probe_active;
static int g_probe_feof_hits;

/* mocks */

static int __cdecl mock_feof(FILE *stream)
{
    int rc;

    /* Probe path: no expectations queued, just record and answer. */
    if (g_probe_active) {
        g_probe_feof_hits++;
        return 0;
    }
    if (!g_mocks_armed)
        return real_feof(stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(stream);
    rc = mock_type(int);
    /*
     * bss_file.c inspects errno after feof to detect the invalid-stream
     * case, so the mock always programs it (0 for the normal case).
     */
    errno = mock_type(int);
    g_mocks_armed = 1;
    return rc;
}

static long __cdecl mock_ftell(FILE *stream)
{
    long rc;

    if (!g_mocks_armed)
        return real_ftell(stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(stream);
    rc = mock_type(long);
    g_mocks_armed = 1;
    return rc;
}

static size_t __cdecl mock_fread(void *ptr, size_t size, size_t nmemb,
    FILE *stream)
{
    size_t rc;

    if (!g_mocks_armed)
        return real_fread(ptr, size, nmemb, stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(ptr);
    check_expected(size);
    check_expected(nmemb);
    check_expected_ptr(stream);
    rc = mock_type(size_t);
    g_mocks_armed = 1;
    return rc;
}

static size_t __cdecl mock_fwrite(const void *ptr, size_t size, size_t nmemb,
    FILE *stream)
{
    size_t rc;

    if (!g_mocks_armed)
        return real_fwrite(ptr, size, nmemb, stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(ptr);
    check_expected(size);
    check_expected(nmemb);
    check_expected_ptr(stream);
    rc = mock_type(size_t);
    g_mocks_armed = 1;
    return rc;
}

static int __cdecl mock_fclose(FILE *stream)
{
    int rc;

    if (!g_mocks_armed)
        return real_fclose(stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(stream);
    rc = mock_type(int);
    g_mocks_armed = 1;
    return rc;
}

static int __cdecl mock_fileno(FILE *stream)
{
    int rc;

    if (!g_mocks_armed)
        return real_fileno(stream);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(stream);
    rc = mock_type(int);
    g_mocks_armed = 1;
    return rc;
}

static int __cdecl mock_setmode(int fd, int mode)
{
    int rc;

    if (!g_mocks_armed)
        return real_setmode(fd, mode);

    g_mocks_armed = 0;
    function_called();
    check_expected(fd);
    check_expected(mode);
    rc = mock_type(int);
    g_mocks_armed = 1;
    return rc;
}

static intptr_t __cdecl mock_get_osfhandle(int fd)
{
    intptr_t rc;

    if (!g_mocks_armed)
        return real_get_osfhandle(fd);

    g_mocks_armed = 0;
    function_called();
    check_expected(fd);
    rc = mock_type(intptr_t);
    g_mocks_armed = 1;
    return rc;
}

static FILE *__cdecl mock_wfopen(const wchar_t *filename,
    const wchar_t *mode)
{
    const wchar_t *exp_filename;
    const wchar_t *exp_mode;
    FILE *rc;

    if (!g_mocks_armed)
        return real_wfopen(filename, mode);

    g_mocks_armed = 0;
    function_called();
    exp_filename = mock_ptr_type(const wchar_t *);
    exp_mode = mock_ptr_type(const wchar_t *);
    assert_int_equal(wcscmp(filename, exp_filename), 0);
    assert_int_equal(wcscmp(mode, exp_mode), 0);
    rc = mock_ptr_type(FILE *);
    if (rc == NULL)
        errno = mock_type(int);
    g_mocks_armed = 1;
    return rc;
}

static DWORD WINAPI mock_GetFileType(HANDLE h)
{
    DWORD rc;

    if (!g_mocks_armed)
        return real_GetFileType(h);

    g_mocks_armed = 0;
    function_called();
    check_expected_ptr(h);
    rc = mock_type(DWORD);
    g_mocks_armed = 1;
    return rc;
}

/* expectations */

/*
 * errnoval is always consumed by mock_feof; pass 0 unless the test
 * exercises the invalid-stream (EINVAL) quirk.
 */
static void expect_feof(FILE *stream, int rc, int errnoval)
{
    expect_function_call(mock_feof);
    expect_value(mock_feof, stream, stream);
    will_return(mock_feof, rc);
    will_return(mock_feof, errnoval);
}

static void expect_ftell(FILE *stream, long rc)
{
    expect_function_call(mock_ftell);
    expect_value(mock_ftell, stream, stream);
    will_return(mock_ftell, rc);
}

static void expect_fread(void *ptr, size_t nmemb, FILE *stream, size_t rc)
{
    expect_function_call(mock_fread);
    expect_value(mock_fread, ptr, ptr);
    expect_value(mock_fread, size, 1);
    expect_value(mock_fread, nmemb, nmemb);
    expect_value(mock_fread, stream, stream);
    will_return(mock_fread, rc);
}

static void expect_fwrite(const void *ptr, size_t nmemb, FILE *stream,
    size_t rc)
{
    expect_function_call(mock_fwrite);
    expect_value(mock_fwrite, ptr, ptr);
    expect_value(mock_fwrite, size, 1);
    expect_value(mock_fwrite, nmemb, nmemb);
    expect_value(mock_fwrite, stream, stream);
    will_return(mock_fwrite, rc);
}

static void expect_fclose(FILE *stream, int rc)
{
    expect_function_call(mock_fclose);
    expect_value(mock_fclose, stream, stream);
    will_return(mock_fclose, rc);
}

static void expect_fileno(FILE *stream, int rc)
{
    expect_function_call(mock_fileno);
    expect_value(mock_fileno, stream, stream);
    will_return(mock_fileno, rc);
}

static void expect_setmode(int fd, int mode, int rc)
{
    expect_function_call(mock_setmode);
    expect_value(mock_setmode, fd, fd);
    expect_value(mock_setmode, mode, mode);
    will_return(mock_setmode, rc);
}

static void expect_get_osfhandle(int fd, intptr_t rc)
{
    expect_function_call(mock_get_osfhandle);
    expect_value(mock_get_osfhandle, fd, fd);
    will_return(mock_get_osfhandle, rc);
}

static void expect_wfopen(const wchar_t *filename, const wchar_t *mode,
    FILE *rc, int errnoval)
{
    expect_function_call(mock_wfopen);
    will_return(mock_wfopen, filename);
    will_return(mock_wfopen, mode);
    will_return(mock_wfopen, rc);
    if (rc == NULL)
        will_return(mock_wfopen, errnoval);
}

static void expect_GetFileType(intptr_t h, DWORD rc)
{
    expect_function_call(mock_GetFileType);
    expect_value(mock_GetFileType, h, (HANDLE)h);
    will_return(mock_GetFileType, rc);
}

/*
 * Setting a FILE pointer always routes through the text/binary mode
 * setup: _setmode on the non-uplink path, UP_fsetmod -> applink ->
 * _setmode on the uplink path. Either way the same two CRT calls are
 * observed.
 */
static void expect_set_fp_mode(FILE *fp, int fd, int mode)
{
    expect_fileno(fp, fd);
    expect_setmode(fd, mode, 0);
}

/* detours */

static int attach_detours(void)
{
    if (DetourTransactionBegin() != NO_ERROR)
        return 0;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_feof, mock_feof) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_ftell, mock_ftell) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_fread, mock_fread) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_fwrite, mock_fwrite) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_fclose, mock_fclose) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_fileno, mock_fileno) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_setmode, mock_setmode) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_get_osfhandle, mock_get_osfhandle)
        != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_wfopen, mock_wfopen) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_GetFileType, mock_GetFileType)
        != NO_ERROR)
        return 0;
    return DetourTransactionCommit() == NO_ERROR;
}

static int detach_detours(void)
{
    if (DetourTransactionBegin() != NO_ERROR)
        return 0;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        return 0;
    DetourDetach((PVOID *)&real_feof, mock_feof);
    DetourDetach((PVOID *)&real_ftell, mock_ftell);
    DetourDetach((PVOID *)&real_fread, mock_fread);
    DetourDetach((PVOID *)&real_fwrite, mock_fwrite);
    DetourDetach((PVOID *)&real_fclose, mock_fclose);
    DetourDetach((PVOID *)&real_fileno, mock_fileno);
    DetourDetach((PVOID *)&real_setmode, mock_setmode);
    DetourDetach((PVOID *)&real_get_osfhandle, mock_get_osfhandle);
    DetourDetach((PVOID *)&real_wfopen, mock_wfopen);
    DetourDetach((PVOID *)&real_GetFileType, mock_GetFileType);
    return DetourTransactionCommit() == NO_ERROR;
}

/* setup / teardown */

/*
 * A BIO in the state BIO_new_file leaves it in: the UPLINK flag is
 * cleared, so all Windows-specific non-uplink branches are reachable.
 */
static int setup_internal(void **state)
{
    BIO *bio = BIO_new(BIO_s_file());

    assert_non_null(bio);
    BIO_clear_flags(bio, BIO_FLAGS_UPLINK_INTERNAL);
    mocks_arm();
    expect_set_fp_mode(FAKE_FP, FAKE_FD, _O_BINARY);
    BIO_set_fp(bio, FAKE_FP, BIO_NOCLOSE);
    *state = bio;
    return 0;
}

static int teardown(void **state)
{
    /*
     * Disarm before BIO_free (and before cmocka prints the test result):
     * once disarmed the mocks forward to the real CRT, so neither the
     * NOCLOSE teardown nor the TAP output re-enters an expectation.
     */
    mocks_disarm();
    if (*state != NULL)
        BIO_free(*state);
    return 0;
}

static int group_setup(void **state)
{
    (void)state;
    assert_true(attach_detours());
    return 0;
}

static int group_teardown(void **state)
{
    (void)state;
    assert_true(detach_detours());
    return 0;
}

/*
 * GATE: prove Detours intercepts a CRT call. If this fails, fix the
 * linkage (e.g. the test and libcrypto using different CRTs) before
 * trusting any other test below.
 */
static void detour_probe(void **state)
{
    (void)state;
    g_probe_feof_hits = 0;
    g_probe_active = 1;
    feof(stdin);
    g_probe_active = 0;

    assert_int_equal(g_probe_feof_hits, 1);
}

/*
 * BIO_CTRL_EOF: feof returning 0 on an invalid stream sets errno to
 * EINVAL, which bss_file.c maps to -EINVAL (Windows only).
 */

static void test_win_eof_invalid_stream(void **state)
{
    BIO *bio = *state;

    expect_feof(FAKE_FP, 0, EINVAL);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), -EINVAL);
}

static void test_win_eof_not_eof(void **state)
{
    BIO *bio = *state;

    expect_feof(FAKE_FP, 0, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 0);
}

static void test_win_eof_at_eof(void **state)
{
    /* any non-zero feof result is mapped to 1 by double negation */
    BIO *bio = *state;

    expect_feof(FAKE_FP, 7, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL), 1);
}

/*
 * BIO_C_FILE_TELL: on Windows the non-uplink path refuses to ftell
 * non-seekable files (GetFileType != FILE_TYPE_DISK), e.g. stdin.
 */

static void test_win_tell_non_disk(void **state)
{
    BIO *bio = *state;

    expect_fileno(FAKE_FP, FAKE_FD);
    expect_get_osfhandle(FAKE_FD, FAKE_OSFHANDLE);
    expect_GetFileType(FAKE_OSFHANDLE, FILE_TYPE_PIPE);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_TELL, 0, NULL), -1);
}

static void test_win_tell_disk(void **state)
{
    BIO *bio = *state;

    expect_fileno(FAKE_FP, FAKE_FD);
    expect_get_osfhandle(FAKE_FD, FAKE_OSFHANDLE);
    expect_GetFileType(FAKE_OSFHANDLE, FILE_TYPE_DISK);
    expect_ftell(FAKE_FP, 12345);
    assert_int_equal(BIO_ctrl(bio, BIO_C_FILE_TELL, 0, NULL), 12345);
}

/* BIO_C_SET_FILE_PTR: text/binary mode is applied with _setmode */

static void test_win_set_fp_text_mode(void **state)
{
    BIO *bio = *state;

    expect_set_fp_mode(FAKE_FP2, FAKE_FD, _O_TEXT);
    BIO_set_fp(bio, FAKE_FP2, BIO_NOCLOSE | BIO_FP_TEXT);
}

static void test_win_set_fp_binary_mode(void **state)
{
    BIO *bio = *state;

    expect_set_fp_mode(FAKE_FP2, FAKE_FD, _O_BINARY);
    BIO_set_fp(bio, FAKE_FP2, BIO_NOCLOSE);
}

/*
 * BIO_C_SET_FILENAME: on Windows an explicit "b" or "t" is appended to
 * the fopen mode. The filename and mode are checked in mock_wfopen,
 * where openssl_fopen's UTF-8 conversion of plain ASCII input lands.
 */

static void test_win_set_filename_appends_b(void **state)
{
    BIO *bio = *state;

    expect_wfopen(L"file.txt", L"rb", FAKE_FP2, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_FILENAME, BIO_FP_READ,
                         (void *)"file.txt"),
        1);
}

static void test_win_set_filename_appends_t(void **state)
{
    BIO *bio = *state;

    expect_wfopen(L"file.txt", L"rt", FAKE_FP2, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_C_SET_FILENAME,
                         BIO_FP_READ | BIO_FP_TEXT, (void *)"file.txt"),
        1);
}

#if BIO_FLAGS_UPLINK_INTERNAL != 0

/*
 * Uplink-only behaviour (requires an applink-enabled build; this test
 * links ms/applink.c, so UP_* calls resolve to this executable's CRT).
 */

static int setup_uplink(void **state)
{
    BIO *bio;

    mocks_arm();
    /* BIO_new_fp keeps the UPLINK flag, so UP_fsetmod is dispatched */
    expect_set_fp_mode(FAKE_FP, FAKE_FD, _O_BINARY);
    bio = BIO_new_fp(FAKE_FP, BIO_NOCLOSE);
    assert_non_null(bio);
    assert_true(BIO_test_flags(bio, BIO_FLAGS_UPLINK_INTERNAL));
    *state = bio;
    return 0;
}

static void test_win_uplink_read(void **state)
{
    BIO *bio = *state;
    char buf[8] = { 0 };

    expect_fread(buf, 8, FAKE_FP, 8);
    assert_int_equal(BIO_read(bio, buf, 8), 8);
}

static void test_win_uplink_write(void **state)
{
    BIO *bio = *state;
    const char buf[] = "hello";

    expect_fwrite(buf, 5, FAKE_FP, 5);
    assert_int_equal(BIO_write(bio, buf, 5), 5);
}

static void test_win_uplink_free_closes(void **state)
{
    BIO *bio = *state;

    BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_CLOSE, NULL);
    expect_fclose(FAKE_FP, 0);
    BIO_free(bio);
    *state = NULL;
}

static void test_win_uplink_get_fp_visible(void **state)
{
    /* an application-owned FILE (UPLINK set) is returned to the app */
    BIO *bio = *state;
    FILE *fp = NULL;

    assert_int_equal(BIO_get_fp(bio, &fp), 1);
    assert_ptr_equal(fp, FAKE_FP);
}

static void test_win_get_fp_internal_hidden(void **state)
{
    /*
     * A FILE opened inside libcrypto (UPLINK cleared) belongs to the
     * library CRT and must not be handed back to the application.
     */
    BIO *bio = *state;
    FILE *fp = FAKE_FP;

    assert_int_equal(BIO_get_fp(bio, &fp), 0);
    assert_null(fp);
}

#if defined(_MSC_VER) && _MSC_VER >= 1900

static void test_win_set_fp_stdio_clears_uplink(void **state)
{
    /*
     * Safety net: passing one of the standard streams to BIO_set_fp
     * clears the UPLINK flag, after which the mode is set with a plain
     * _setmode call.
     */
    BIO *bio = BIO_new(BIO_s_file());

    (void)state;
    assert_non_null(bio);
    assert_true(BIO_test_flags(bio, BIO_FLAGS_UPLINK_INTERNAL));
    mocks_arm();
    expect_set_fp_mode(stdout, 1, _O_BINARY);
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    mocks_disarm();
    assert_false(BIO_test_flags(bio, BIO_FLAGS_UPLINK_INTERNAL));
    BIO_free(bio);
}

#endif /* _MSC_VER >= 1900 */

#endif /* BIO_FLAGS_UPLINK_INTERNAL != 0 */

/* main */

#define FILE_WIN(name) \
    cmocka_unit_test_setup_teardown(name, setup_internal, teardown)

#if BIO_FLAGS_UPLINK_INTERNAL != 0
#define FILE_WIN_UPLINK(name) \
    cmocka_unit_test_setup_teardown(name, setup_uplink, teardown)
#endif

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* no fixture: the gate must not touch the CRT with a fake FILE */
        cmocka_unit_test(detour_probe),
        FILE_WIN(test_win_eof_invalid_stream),
        FILE_WIN(test_win_eof_not_eof),
        FILE_WIN(test_win_eof_at_eof),
        FILE_WIN(test_win_tell_non_disk),
        FILE_WIN(test_win_tell_disk),
        FILE_WIN(test_win_set_fp_text_mode),
        FILE_WIN(test_win_set_fp_binary_mode),
        FILE_WIN(test_win_set_filename_appends_b),
        FILE_WIN(test_win_set_filename_appends_t),
#if BIO_FLAGS_UPLINK_INTERNAL != 0
        FILE_WIN_UPLINK(test_win_uplink_read),
        FILE_WIN_UPLINK(test_win_uplink_write),
        FILE_WIN_UPLINK(test_win_uplink_free_closes),
        FILE_WIN_UPLINK(test_win_uplink_get_fp_visible),
        FILE_WIN(test_win_get_fp_internal_hidden),
#if defined(_MSC_VER) && _MSC_VER >= 1900
        cmocka_unit_test(test_win_set_fp_stdio_clears_uplink),
#endif
#endif
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#endif
