/*
 * test/bss_dgram_win_test.c
 *
 * Windows-only side test for bss_dgram.c Windows-specific paths.
 * Uses Microsoft Detours to intercept Winsock calls at runtime.
 * Does NOT replace the normal --wrap-based bss_dgram test; it only
 * covers branches that differ under OPENSSL_SYS_WINDOWS.
 *
 * NOTE: not compiled/verified by the author's toolchain. The first
 * test (detour_probe) is a hard gate: if Detours does not intercept
 * cross-module Winsock calls, every other result is meaningless.
 */

#include "openssl/e_os2.h"

#if defined(OPENSSL_NO_SOCK) || defined(OPENSSL_NO_DGRAM) \
    || !defined(OPENSSL_SYS_WINDOWS)
int main(void) { return 0; }
#else

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <detours/detours.h>

#include "internal/sockets.h"
#include "bio_local.h"
#include <openssl/bio.h>

#define FAKE_SOCKET ((SOCKET)42)

/*
 * Real function pointers. After DetourAttach commits, Detours rewrites
 * these to trampolines pointing at the original code.
 */
static int(WSAAPI *real_getsockname)(SOCKET, struct sockaddr *, int *)
    = getsockname;
static int(WSAAPI *real_getpeername)(SOCKET, struct sockaddr *, int *)
    = getpeername;
static int(WSAAPI *real_setsockopt)(SOCKET, int, int, const char *, int)
    = setsockopt;
static int(WSAAPI *real_getsockopt)(SOCKET, int, int, char *, int *)
    = getsockopt;
static int(WSAAPI *real_recvfrom)(SOCKET, char *, int, int,
    struct sockaddr *, int *)
    = recvfrom;

static struct sockaddr_in g_sin;

/*
 * detour_probe uses this to confirm the mock actually fired. It is the
 * only place a mock is allowed to run outside a cmocka expectation, so
 * the mocks below special-case it.
 */
static int g_probe_active;
static int g_probe_getsockopt_hits;

/* mocks */

static int WSAAPI mock_getsockname(SOCKET s, struct sockaddr *name,
    int *namelen)
{
    int rc;

    function_called();
    check_expected_uint(s);

    rc = mock_type(int);
    if (rc == 0) {
        const struct sockaddr *sa = mock_ptr_type(const struct sockaddr *);
        int sl = mock_type(int);

        assert_non_null(name);
        assert_non_null(namelen);
        assert_true(*namelen >= sl);
        memcpy(name, sa, (size_t)sl);
        *namelen = sl;
    } else {
        WSASetLastError(mock_type(int));
    }
    return rc;
}

static int WSAAPI mock_getpeername(SOCKET s, struct sockaddr *name,
    int *namelen)
{
    int rc;

    function_called();
    check_expected_uint(s);

    rc = mock_type(int);
    if (rc == 0) {
        assert_non_null(name);
        assert_non_null(namelen);
        assert_true(*namelen >= (int)sizeof(g_sin));
        memcpy(name, &g_sin, sizeof(g_sin));
        *namelen = (int)sizeof(g_sin);
    } else {
        WSASetLastError(mock_type(int));
    }
    return rc;
}

static int WSAAPI mock_setsockopt(SOCKET s, int level, int optname,
    const char *optval, int optlen)
{
    int expected_int;
    int rc;

    function_called();
    check_expected_uint(s);
    check_expected_int(level);
    check_expected_int(optname);
    check_expected_int(optlen);

    /* Every Windows path routed here passes a single int. */
    assert_int_equal(optlen, (int)sizeof(int));
    expected_int = mock_type(int);
    assert_int_equal(*(const int *)optval, expected_int);

    rc = mock_type(int);
    if (rc == SOCKET_ERROR)
        WSASetLastError(mock_type(int));
    return rc;
}

static int WSAAPI mock_getsockopt(SOCKET s, int level, int optname,
    char *optval, int *optlen)
{
    int out_value;
    int rc;

    /* Probe path: no expectations queued, just record and answer. */
    if (g_probe_active) {
        g_probe_getsockopt_hits++;
        if (optval != NULL && optlen != NULL && *optlen >= (int)sizeof(int)) {
            *(int *)optval = 0;
            *optlen = (int)sizeof(int);
        }
        return 0;
    }

    function_called();
    check_expected_uint(s);
    check_expected_int(level);
    check_expected_int(optname);

    assert_non_null(optval);
    assert_non_null(optlen);
    assert_int_equal(*optlen, (int)sizeof(int));

    out_value = mock_type(int);
    rc = mock_type(int);
    if (rc == 0) {
        *(int *)optval = out_value;
        *optlen = (int)sizeof(int);
    } else {
        WSASetLastError(mock_type(int));
    }
    return rc;
}

static int WSAAPI mock_recvfrom(SOCKET s, char *buf, int len, int flags,
    struct sockaddr *from, int *fromlen)
{
    int rc;

    (void)from;
    (void)fromlen;

    function_called();
    check_expected_uint(s);
    check_expected_ptr(buf);
    check_expected_int(len);
    check_expected_int(flags);

    rc = mock_type(int);
    if (rc == SOCKET_ERROR)
        WSASetLastError(mock_type(int));
    return rc;
}

/* expectations */

static void expect_getsockname_ok(void)
{
    expect_function_call(mock_getsockname);
    expect_uint_value(mock_getsockname, s, FAKE_SOCKET);
    will_return_int(mock_getsockname, 0);
    will_return_ptr(mock_getsockname, (const struct sockaddr *)&g_sin);
    will_return_int(mock_getsockname, (int)sizeof(g_sin));
}

static void expect_getpeername_fail(void)
{
    expect_function_call(mock_getpeername);
    expect_uint_value(mock_getpeername, s, FAKE_SOCKET);
    will_return_int(mock_getpeername, SOCKET_ERROR);
    will_return_int(mock_getpeername, WSAENOTCONN);
}

static void expect_setsockopt_int(int level, int optname, int value, int rc)
{
    expect_function_call(mock_setsockopt);
    expect_uint_value(mock_setsockopt, s, FAKE_SOCKET);
    expect_int_value(mock_setsockopt, level, level);
    expect_int_value(mock_setsockopt, optname, optname);
    expect_int_value(mock_setsockopt, optlen, (int)sizeof(int));
    will_return_int(mock_setsockopt, value);
    will_return_int(mock_setsockopt, rc);
    if (rc == SOCKET_ERROR)
        will_return(mock_setsockopt, WSAEINVAL);
}

static void expect_getsockopt_int(int level, int optname, int value, int rc)
{
    expect_function_call(mock_getsockopt);
    expect_uint_value(mock_getsockopt, s, FAKE_SOCKET);
    expect_int_value(mock_getsockopt, level, level);
    expect_int_value(mock_getsockopt, optname, optname);
    will_return_int(mock_getsockopt, value);
    will_return_int(mock_getsockopt, rc);
    if (rc == SOCKET_ERROR)
        will_return_int(mock_getsockopt, WSAEINVAL);
}

static void expect_recvfrom_error(char *buf, int len, int flags, int wsaerr)
{
    expect_function_call(mock_recvfrom);
    expect_uint_value(mock_recvfrom, s, FAKE_SOCKET);
    expect_value(mock_recvfrom, buf, buf);
    expect_int_value(mock_recvfrom, len, len);
    expect_int_value(mock_recvfrom, flags, flags);
    will_return_int(mock_recvfrom, SOCKET_ERROR);
    will_return_int(mock_recvfrom, wsaerr);
}

/* detours */

static int attach_detours(void)
{
    if (DetourTransactionBegin() != NO_ERROR)
        return 0;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_getsockname, mock_getsockname) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_getpeername, mock_getpeername) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_setsockopt, mock_setsockopt) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_getsockopt, mock_getsockopt) != NO_ERROR)
        return 0;
    if (DetourAttach((PVOID *)&real_recvfrom, mock_recvfrom) != NO_ERROR)
        return 0;
    return DetourTransactionCommit() == NO_ERROR;
}

static int detach_detours(void)
{
    if (DetourTransactionBegin() != NO_ERROR)
        return 0;
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        return 0;
    DetourDetach((PVOID *)&real_getsockname, mock_getsockname);
    DetourDetach((PVOID *)&real_getpeername, mock_getpeername);
    DetourDetach((PVOID *)&real_setsockopt, mock_setsockopt);
    DetourDetach((PVOID *)&real_getsockopt, mock_getsockopt);
    DetourDetach((PVOID *)&real_recvfrom, mock_recvfrom);
    return DetourTransactionCommit() == NO_ERROR;
}

/* setup / teardown */

static int setup_io(void **state)
{
    BIO *bio = BIO_new(BIO_s_datagram());

    assert_non_null(bio);
    expect_getsockname_ok();
    expect_getpeername_fail();
    BIO_set_fd(bio, (int)FAKE_SOCKET, BIO_NOCLOSE);
    *state = bio;
    return 0;
}

static int teardown_io(void **state)
{
    if (*state != NULL) {
        BIO *bio = *state;

        bio->num = (int)INVALID_SOCKET;
        bio->shutdown = BIO_NOCLOSE;
        BIO_free(bio);
    }
    return 0;
}

static int group_setup(void **state)
{
    WSADATA wsa;

    (void)state;
    memset(&g_sin, 0, sizeof(g_sin));
    g_sin.sin_family = AF_INET;
    g_sin.sin_port = htons(443);
    g_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    assert_int_equal(WSAStartup(MAKEWORD(2, 2), &wsa), 0);
    assert_true(attach_detours());
    return 0;
}

static int group_teardown(void **state)
{
    (void)state;
    assert_true(detach_detours());
    WSACleanup();
    return 0;
}

/*
 * GATE: prove Detours intercepts a Winsock call made through the same
 * import machinery the production library uses. If this fails, fix the
 * linkage (e.g. DetourFindFunction on ws2_32.dll) before trusting any
 * other test below.
 */
static void detour_probe(void **state)
{
    int val = -1;
    int len = (int)sizeof(val);
    int rc;

    (void)state;
    g_probe_getsockopt_hits = 0;
    g_probe_active = 1;
    rc = getsockopt(FAKE_SOCKET, SOL_SOCKET, SO_TYPE, (char *)&val, &len);
    g_probe_active = 0;

    assert_int_equal(rc, 0);
    assert_int_equal(g_probe_getsockopt_hits, 1);
}

/* SO_RCVTIMEO / SO_SNDTIMEO use int milliseconds on Windows. */

static void test_win_set_recv_timeout_uses_milliseconds(void **state)
{
    BIO *bio = *state;
    struct timeval tv = { 1, 500000 };

    expect_setsockopt_int(SOL_SOCKET, SO_RCVTIMEO, 1500, 0);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv), 0);
}

static void test_win_get_recv_timeout_converts_milliseconds(void **state)
{
    BIO *bio = *state;
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));
    expect_getsockopt_int(SOL_SOCKET, SO_RCVTIMEO, 2500, 0);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, &tv),
        (int)sizeof(tv));
    assert_int_equal(tv.tv_sec, 2);
    assert_int_equal(tv.tv_usec, 500000);
}

static void test_win_set_send_timeout_uses_milliseconds(void **state)
{
    BIO *bio = *state;
    struct timeval tv = { 3, 250000 };

    expect_setsockopt_int(SOL_SOCKET, SO_SNDTIMEO, 3250, 0);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv), 0);
}

static void test_win_get_send_timeout_converts_milliseconds(void **state)
{
    BIO *bio = *state;
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));
    expect_getsockopt_int(SOL_SOCKET, SO_SNDTIMEO, 4250, 0);
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, 0, &tv),
        (int)sizeof(tv));
    assert_int_equal(tv.tv_sec, 4);
    assert_int_equal(tv.tv_usec, 250000);
}

/*
 * GET_RECV_TIMER_EXP checks data->_errno == WSAETIMEDOUT on Windows
 * (EAGAIN elsewhere), then consumes/clears it. WSAETIMEDOUT is treated
 * as fatal by BIO_dgram_non_fatal_error, so we set _errno directly
 * rather than driving it through a recvfrom retry that never sets it.
 */
static void test_win_recv_timer_exp_consumes_errno(void **state)
{
    BIO *bio = *state;
    bio_dgram_data *data = (bio_dgram_data *)bio->ptr;

    data->_errno = WSAETIMEDOUT;
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL), 1);
    /* second read reports 0: the ctrl cleared _errno */
    assert_int_equal(
        BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL), 0);
}

/*
 * A fatal recvfrom error (WSAECONNRESET) must NOT set a retry flag.
 * This exercises the real Windows recvfrom signature through Detours.
 */
static void test_win_recvfrom_fatal_no_retry(void **state)
{
    BIO *bio = *state;
    char buf[16];

    memset(buf, 0, sizeof(buf));
    expect_recvfrom_error(buf, (int)sizeof(buf), 0, WSAECONNRESET);
    assert_true(BIO_read(bio, buf, (int)sizeof(buf)) <= 0);
    assert_false(BIO_should_retry(bio));
}

#if defined(IP_DONTFRAGMENT)
/*
 * IPv4 don't-fragment falls to IP_DONTFRAGMENT on Windows. This branch
 * is reached only when IP_DONTFRAG is NOT defined (it is the #elif).
 */
static void test_win_set_dont_frag_ipv4(void **state)
{
    BIO *bio = *state;
    struct sockaddr_in peer;

    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &peer);

    expect_setsockopt_int(IPPROTO_IP, IP_DONTFRAGMENT, 1, 0);
    assert_int_equal(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_DONT_FRAG, 1, NULL), 0);
}
#endif

#define DG_WIN(name) \
    cmocka_unit_test_setup_teardown(name, setup_io, teardown_io)

int main(void)
{
    const struct CMUnitTest tests[] = {
        DG_WIN(detour_probe),
        DG_WIN(test_win_set_recv_timeout_uses_milliseconds),
        DG_WIN(test_win_get_recv_timeout_converts_milliseconds),
        DG_WIN(test_win_set_send_timeout_uses_milliseconds),
        DG_WIN(test_win_get_send_timeout_converts_milliseconds),
        DG_WIN(test_win_recv_timer_exp_consumes_errno),
        DG_WIN(test_win_recvfrom_fatal_no_retry),
#if defined(IP_DONTFRAGMENT)
        DG_WIN(test_win_set_dont_frag_ipv4),
#endif
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#endif
