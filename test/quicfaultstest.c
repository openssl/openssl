/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ssl.h>
#include "helpers/quictestlib.h"
#include "internal/quic_error.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

/*
 * Basic test that just creates a connection and sends some data without any
 * faults injected.
 */
static int test_basic(void)
{
    int testresult = 0;
    SSL_CTX *cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    QUIC_TSERVER *qtserv = NULL;
    SSL *cssl = NULL;
    char *msg = "Hello World!";
    size_t msglen = strlen(msg);
    unsigned char buf[80];
    size_t bytesread;

    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_true(qtest_create_quic_objects(NULL, cctx, cert, privkey, 0,
                                             &qtserv, &cssl, NULL)))
        goto err;

    if (!TEST_true(qtest_create_quic_connection(qtserv, cssl)))
        goto err;

    if (!TEST_int_eq(SSL_write(cssl, msg, msglen), msglen))
        goto err;

    ossl_quic_tserver_tick(qtserv);
    if (!TEST_true(ossl_quic_tserver_read(qtserv, 0, buf, sizeof(buf), &bytesread)))
        goto err;

    /*
     * We assume the entire message is read from the server in one go. In
     * theory this could get fragmented but its a small message so we assume
     * not.
     */
    if (!TEST_mem_eq(msg, msglen, buf, bytesread))
        goto err;

    testresult = 1;
 err:
    SSL_free(cssl);
    ossl_quic_tserver_free(qtserv);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test that sends data using iovec and checks that the data is received
 */
static int test_iov(void)
{
    int testresult = 0;
    size_t i;
    SSL_CTX *cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    QUIC_TSERVER *qtserv = NULL;
    SSL *cssl = NULL;
    char *msg = "Hello World!";
    size_t msglen = strlen(msg);
    unsigned char buf[80];
    size_t num_iov, written, bytesread;
    struct iovec iov[4];

    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_true(qtest_create_quic_objects(NULL, cctx, cert, privkey, 0,
                                             &qtserv, &cssl, NULL)))
        goto err;

    if (!TEST_true(qtest_create_quic_connection(qtserv, cssl)))
        goto err;

    num_iov = OSSL_NELEM(iov);
    for (i = 0; i < num_iov; i++) {
        iov[i].iov_base = (void *)msg;
        iov[i].iov_len = msglen;
    }

    if (!TEST_true(SSL_writev(cssl, iov, num_iov, &written)))
        goto err;

    if (!TEST_size_t_eq(written, msglen * num_iov))
        goto err;

    ossl_quic_tserver_tick(qtserv);
    if (!TEST_true(ossl_quic_tserver_read(qtserv, 0, buf, sizeof(buf), &bytesread)))
        goto err;

    /*
     * We assume the entire message is read from the server in one go. In
     * theory this could get fragmented but its a small message so we assume
     * not.
     */
    for (i = 0; i < num_iov; i++) {
        if (!TEST_mem_eq(msg, msglen, buf + (i * msglen), bytesread / num_iov))
            goto err;
    }

    testresult = 1;
 err:
    SSL_free(cssl);
    ossl_quic_tserver_free(qtserv);
    SSL_CTX_free(cctx);
    return testresult; 
}

/*
 * Test that adding an unknown frame type is handled correctly
 */
static int add_unknown_frame_cb(QTEST_FAULT *fault, QUIC_PKT_HDR *hdr,
                                unsigned char *buf, size_t len, void *cbarg)
{
    static size_t done = 0;
    /*
     * There are no "reserved" frame types which are definitately safe for us
     * to use for testing purposes - but we just use the highest possible
     * value (8 byte length integer) and with no payload bytes
     */
    unsigned char unknown_frame[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    /* We only ever add the unknown frame to one packet */
    if (done++)
        return 1;

    return qtest_fault_prepend_frame(fault, unknown_frame,
                                     sizeof(unknown_frame));
}

static int test_unknown_frame(void)
{
    int testresult = 0, ret;
    SSL_CTX *cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    QUIC_TSERVER *qtserv = NULL;
    SSL *cssl = NULL;
    char *msg = "Hello World!";
    size_t msglen = strlen(msg);
    unsigned char buf[80];
    size_t byteswritten;
    QTEST_FAULT *fault = NULL;
    uint64_t sid = UINT64_MAX;

    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_true(qtest_create_quic_objects(NULL, cctx, cert, privkey, 0,
                                             &qtserv, &cssl, &fault)))
        goto err;

    if (!TEST_true(qtest_create_quic_connection(qtserv, cssl)))
        goto err;

    /*
     * Write a message from the server to the client and add an unknown frame
     * type
     */
    if (!TEST_true(qtest_fault_set_packet_plain_listener(fault,
                                                         add_unknown_frame_cb,
                                                         NULL)))
        goto err;

    if (!TEST_true(ossl_quic_tserver_stream_new(qtserv, /*is_uni=*/0, &sid))
        || !TEST_uint64_t_eq(sid, 1))
        goto err;

    if (!TEST_true(ossl_quic_tserver_write(qtserv, sid, (unsigned char *)msg, msglen,
                                           &byteswritten)))
        goto err;

    if (!TEST_size_t_eq(msglen, byteswritten))
        goto err;

    ossl_quic_tserver_tick(qtserv);
    if (!TEST_true(SSL_handle_events(cssl)))
        goto err;

    if (!TEST_int_le(ret = SSL_read(cssl, buf, sizeof(buf)), 0))
        goto err;

    if (!TEST_int_eq(SSL_get_error(cssl, ret), SSL_ERROR_SSL))
        goto err;

#if 0
    /*
     * TODO(QUIC): We should expect an error on the queue after this - but we
     * don't have it yet.
     * Note, just raising the error in the obvious place causes
     * SSL_handle_events() to succeed, but leave a suprious error on the stack.
     * We need to either allow SSL_handle_events() to fail, or somehow delay the
     * raising of the error until the SSL_read() call.
     */
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_error()),
                     SSL_R_UNKNOWN_FRAME_TYPE_RECEIVED))
        goto err;
#endif

    if (!TEST_true(qtest_check_server_protocol_err(qtserv)))
        goto err;

    testresult = 1;
 err:
    qtest_fault_free(fault);
    SSL_free(cssl);
    ossl_quic_tserver_free(qtserv);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test that a server that fails to provide transport params cannot be
 * connected to.
 */
static int drop_transport_params_cb(QTEST_FAULT *fault,
                                    QTEST_ENCRYPTED_EXTENSIONS *ee,
                                    size_t eelen, void *encextcbarg)
{
    if (!qtest_fault_delete_extension(fault,
                                      TLSEXT_TYPE_quic_transport_parameters,
                                      ee->extensions, &ee->extensionslen))
        return 0;

    return 1;
}

static int test_no_transport_params(void)
{
    int testresult = 0;
    SSL_CTX *cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    QUIC_TSERVER *qtserv = NULL;
    SSL *cssl = NULL;
    QTEST_FAULT *fault = NULL;

    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_true(qtest_create_quic_objects(NULL, cctx, cert, privkey, 0,
                                             &qtserv, &cssl, &fault)))
        goto err;

    if (!TEST_true(qtest_fault_set_hand_enc_ext_listener(fault,
                                                         drop_transport_params_cb,
                                                         NULL)))
        goto err;

    /*
     * We expect the connection to fail because the server failed to provide
     * transport parameters
     */
    if (!TEST_false(qtest_create_quic_connection(qtserv, cssl)))
        goto err;

    if (!TEST_true(qtest_check_server_protocol_err(qtserv)))
        goto err;

    testresult = 1;
 err:
    qtest_fault_free(fault);
    SSL_free(cssl);
    ossl_quic_tserver_free(qtserv);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test that corrupted packets/datagrams are dropped and retransmitted
 */
static int docorrupt = 0;

static int on_packet_cipher_cb(QTEST_FAULT *fault, QUIC_PKT_HDR *hdr,
                               unsigned char *buf, size_t len, void *cbarg)
{
    if (!docorrupt || len == 0)
        return 1;

    buf[(size_t)test_random() % len] ^= 0xff;
    docorrupt = 0;

    return 1;
}

static int on_datagram_cb(QTEST_FAULT *fault, BIO_MSG *m, size_t stride,
                          void *cbarg)
{
    if (!docorrupt || m->data_len == 0)
        return 1;

    if (!qtest_fault_resize_datagram(fault, m->data_len - 1))
        return 1;

    docorrupt = 0;

    return 1;
}

/*
 * Test 1: Corrupt by flipping bits in an encrypted packet
 * Test 2: Corrupt by truncating an entire datagram
 */
static int test_corrupted_data(int idx)
{
    QTEST_FAULT *fault = NULL;
    int testresult = 0;
    SSL_CTX *cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    QUIC_TSERVER *qtserv = NULL;
    SSL *cssl = NULL;
    char *msg = "Hello World!";
    size_t msglen = strlen(msg);
    unsigned char buf[80];
    size_t bytesread, byteswritten;
    uint64_t sid = UINT64_MAX;

    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_true(qtest_create_quic_objects(NULL, cctx, cert, privkey, 0,
                                             &qtserv, &cssl, &fault)))
        goto err;

    if (idx == 0) {
        /* Listen for encrypted packets being sent */
        if (!TEST_true(qtest_fault_set_packet_cipher_listener(fault,
                                                              on_packet_cipher_cb,
                                                              NULL)))
            goto err;
    } else {
        /* Listen for datagrams being sent */
        if (!TEST_true(qtest_fault_set_datagram_listener(fault,
                                                         on_datagram_cb,
                                                         NULL)))
            goto err;
    }
    if (!TEST_true(qtest_create_quic_connection(qtserv, cssl)))
        goto err;

    /* Corrupt the next server packet*/
    docorrupt = 1;

    if (!TEST_true(ossl_quic_tserver_stream_new(qtserv, /*is_uni=*/0, &sid))
        || !TEST_uint64_t_eq(sid, 1))
        goto err;

    /*
     * Send first 5 bytes of message. This will get corrupted and is treated as
     * "lost"
     */
    if (!TEST_true(ossl_quic_tserver_write(qtserv, sid, (unsigned char *)msg, 5,
                                           &byteswritten)))
        goto err;

    if (!TEST_size_t_eq(byteswritten, 5))
        goto err;

    /*
     * Introduce a small delay so that the above packet has time to be detected
     * as lost. Loss detection times are based on RTT which should be very
     * fast for us since there isn't really a network. The loss delay timer is
     * always at least 1ms though. We sleep for 100ms.
     * TODO(QUIC): This assumes the calculated RTT will always be way less than
     * 100ms - which it should be...but can we always guarantee this? An
     * alternative might be to put in our own ossl_time_now() implementation for
     * these tests and control the timer as part of the test. This approach has
     * the added advantage that the test will behave reliably when run in a
     * debugger. Without it may get unreliable debugging results. This would
     * require some significant refactoring of the ssl/quic code though.
     */
    OSSL_sleep(100);

    /* Send rest of message */
    if (!TEST_true(ossl_quic_tserver_write(qtserv, sid, (unsigned char *)msg + 5,
                                           msglen - 5, &byteswritten)))
        goto err;

    if (!TEST_size_t_eq(byteswritten, msglen - 5))
        goto err;

    /*
     * Receive the corrupted packet. This should get dropped and is effectively
     * "lost". We also process the second packet which should be decrypted
     * successfully. Therefore we ack the frames in it
     */
    if (!TEST_true(SSL_handle_events(cssl)))
        goto err;

    /*
     * Process the ack. Detect that the first part of the message must have
     * been lost due to the time elapsed since it was sent and resend it
     */
    ossl_quic_tserver_tick(qtserv);

    /* Receive and process the newly arrived message data resend */
    if (!TEST_true(SSL_handle_events(cssl)))
        goto err;

    /* The whole message should now have arrived */
    if (!TEST_true(SSL_read_ex(cssl, buf, sizeof(buf), &bytesread)))
        goto err;

    if (!TEST_mem_eq(msg, msglen, buf, bytesread))
        goto err;

    /*
     * If the test was successful then we corrupted exactly one packet and
     * docorrupt was reset
     */
    if (!TEST_false(docorrupt))
        goto err;

    testresult = 1;
 err:
    qtest_fault_free(fault);
    SSL_free(cssl);
    ossl_quic_tserver_free(qtserv);
    SSL_CTX_free(cctx);
    return testresult;
}

OPT_TEST_DECLARE_USAGE("certsdir\n")

int setup_tests(void)
{
    char *certsdir = NULL;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    ADD_TEST(test_basic);
    ADD_TEST(test_iov);
    ADD_TEST(test_unknown_frame);
    ADD_TEST(test_no_transport_params);
    ADD_ALL_TESTS(test_corrupted_data, 2);

    return 1;

 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
}
