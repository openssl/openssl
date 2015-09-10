/* ssl/statem.c */
/*
 * Written by Matt Caswell for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2015 The OpenSSL Project.  All rights reserved.
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

#include <openssl/rand.h>
#include "ssl_locl.h"

/*
 * This file implements the SSL/TLS/DTLS state machines.
 *
 * There are two primary state machines:
 *
 * 1) Message flow state machine
 * 2) Handshake state machine
 *
 * The Message flow state machine controls the reading and sending of messages
 * including handling of non-blocking IO events, flushing of the underlying
 * write BIO, handling unexpected messages, etc. It is itself broken into two
 * separate sub-state machines which control reading and writing respectively.
 *
 * The Handshake state machine keeps track of the current SSL/TLS handshake
 * state. Transitions of the handshake state are the result of events that
 * occur within the Message flow state machine.
 *
 * Overall it looks like this:
 *
 * ---------------------------------------------            -------------------
 * |                                           |            |                 |
 * | Message flow state machine                |            |                 |
 * |                                           |            |                 |
 * | -------------------- -------------------- | Transition | Handshake state |
 * | | MSG_FLOW_READING    | | MSG_FLOW_WRITING    | | Event      | machine         |
 * | | sub-state        | | sub-state        | |----------->|                 |
 * | | machine for      | | machine for      | |            |                 |
 * | | reading messages | | writing messages | |            |                 |
 * | -------------------- -------------------- |            |                 |
 * |                                           |            |                 |
 * ---------------------------------------------            -------------------
 *
 */

/* Sub state machine return values */
enum SUB_STATE_RETURN {
    /* Something bad happened or NBIO */
    SUB_STATE_ERROR,
    /* Sub state finished go to the next sub state */
    SUB_STATE_FINISHED,
    /* Sub state finished and handshake was completed */
    SUB_STATE_END_HANDSHAKE
};

static int state_machine(SSL *s, int server);
static void init_read_state_machine(SSL *s);
static enum SUB_STATE_RETURN read_state_machine(SSL *s);
static void init_write_state_machine(SSL *s);
static enum SUB_STATE_RETURN write_state_machine(SSL *s);
static inline int cert_req_allowed(SSL *s);
static inline int key_exchange_skip_allowed(SSL *s);
static int client_read_transition(SSL *s, int mt);
static enum WRITE_TRAN client_write_transition(SSL *s);
static enum WORK_STATE client_pre_work(SSL *s, enum WORK_STATE wst);
static enum WORK_STATE client_post_work(SSL *s, enum WORK_STATE wst);
static int client_construct_message(SSL *s);
static unsigned long client_max_message_size(SSL *s);
static enum MSG_PROCESS_RETURN client_process_message(SSL *s, PACKET *pkt);
static enum WORK_STATE client_post_process_message(SSL *s, enum WORK_STATE wst);
static int server_read_transition(SSL *s, int mt);
static inline int send_server_key_exchange(SSL *s);
static inline int send_certificate_request(SSL *s);
static enum WRITE_TRAN server_write_transition(SSL *s);
static enum WORK_STATE server_pre_work(SSL *s, enum WORK_STATE wst);
static enum WORK_STATE server_post_work(SSL *s, enum WORK_STATE wst);
static int server_construct_message(SSL *s);
static unsigned long server_max_message_size(SSL *s);
static enum MSG_PROCESS_RETURN server_process_message(SSL *s, PACKET *pkt);
static enum WORK_STATE server_post_process_message(SSL *s, enum WORK_STATE wst);


enum HANDSHAKE_STATE SSL_state(const SSL *ssl)
{
    return ssl->statem.hand_state;
}

void SSL_set_state(SSL *ssl, enum HANDSHAKE_STATE state)
{
    /*
     * This function seems like a really bad idea. Should we remove it
     * completely?
     */
    ssl->statem.hand_state = state;
}

int SSL_in_init(SSL *s)
{
    return s->statem.in_init;
}

int SSL_is_init_finished(SSL *s)
{
    return !(s->statem.in_init) && (s->statem.hand_state == TLS_ST_OK);
}

int SSL_in_before(SSL *s)
{
    /*
     * Historically being "in before" meant before anything had happened. In the
     * current code though we remain in the "before" state for a while after we
     * have started the handshake process (e.g. as a server waiting for the
     * first message to arrive). There "in before" is taken to mean "in before"
     * and not started any handshake process yet.
     */
    return (s->statem.hand_state == TLS_ST_BEFORE)
        && (s->statem.state == MSG_FLOW_UNINITED);
}

/*
 * Clear the state machine state and reset back to MSG_FLOW_UNINITED
 */
void statem_clear(SSL *s)
{
    s->statem.state = MSG_FLOW_UNINITED;
    s->statem.hand_state = TLS_ST_BEFORE;
    s->statem.in_init = 1;
}

/*
 * Set the state machine up ready for a renegotiation handshake
 */
void statem_set_renegotiate(SSL *s)
{
    s->statem.state = MSG_FLOW_RENEGOTIATE;
    s->statem.in_init = 1;
}

/*
 * Put the state machine into an error state. This is a permanent error for
 * the current connection.
 */
void statem_set_error(SSL *s)
{
    s->statem.state = MSG_FLOW_ERROR;
}

/*
 * Discover whether the current connection is in the error state.
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
int statem_in_error(const SSL *s)
{
    if (s->statem.state == MSG_FLOW_ERROR)
        return 1;

    return 0;
}

void statem_set_in_init(SSL *s, int init)
{
    s->statem.in_init = init;
}

int ssl3_connect(SSL *s) {
    return state_machine(s, 0);
}

int dtls1_connect(SSL *s)
{
    return state_machine(s, 0);
}

int ssl3_accept(SSL *s)
{
    return state_machine(s, 1);
}

int dtls1_accept(SSL *s)
{
    return state_machine(s, 1);
}

/*
 * The main message flow state machine. We start in the MSG_FLOW_UNINITED or
 * MSG_FLOW_RENEGOTIATE state and finish in MSG_FLOW_FINISHED. Valid states and
 * transitions are as follows:
 *
 * MSG_FLOW_UNINITED     MSG_FLOW_RENEGOTIATE
 *        |                       |
 *        +-----------------------+
 *        v
 * MSG_FLOW_WRITING <---> MSG_FLOW_READING
 *        |
 *        V
 * MSG_FLOW_FINISHED
 *        |
 *        V
 *    [SUCCESS]
 *
 * We may exit at any point due to an error or NBIO event. If an NBIO event
 * occurs then we restart at the point we left off when we are recalled.
 * MSG_FLOW_WRITING and MSG_FLOW_READING have sub-state machines associated with them.
 *
 * In addition to the above there is also the MSG_FLOW_ERROR state. We can move
 * into that state at any point in the event that an irrecoverable error occurs.
 *
 * Valid return values are:
 *   1: Success
 * <=0: NBIO or error
 */
static int state_machine(SSL *s, int server) {
    BUF_MEM *buf = NULL;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    STATEM *st = &s->statem;
    int ret = -1;
    int ssret;

    if (st->state == MSG_FLOW_ERROR) {
        /* Shouldn't have been called if we're already in the error state */
        return -1;
    }

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s)) {
        if (!SSL_clear(s))
            return -1;
    }

#ifndef OPENSSL_NO_SCTP
    if (SSL_IS_DTLS(s)) {
        /*
         * Notify SCTP BIO socket to enter handshake mode and prevent stream
         * identifier other than 0. Will be ignored if no SCTP is used.
         */
        BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
                 s->in_handshake, NULL);
    }
#endif

#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        if (SSL_IS_DTLS(s))
            dtls1_stop_timer(s);
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    /* Initialise state machine */

    if (st->state == MSG_FLOW_RENEGOTIATE) {
        s->renegotiate = 1;
        if (!server)
            s->ctx->stats.sess_connect_renegotiate++;
    }

    if (st->state == MSG_FLOW_UNINITED || st->state == MSG_FLOW_RENEGOTIATE) {
        if (st->state == MSG_FLOW_UNINITED) {
            st->hand_state = TLS_ST_BEFORE;
        }

        s->server = server;
        if (cb != NULL)
            cb(s, SSL_CB_HANDSHAKE_START, 1);

        if (SSL_IS_DTLS(s)) {
            if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00) &&
                    (server
                    || (s->version & 0xff00) != (DTLS1_BAD_VER & 0xff00))) {
                SSLerr(SSL_F_STATE_MACHINE, ERR_R_INTERNAL_ERROR);
                goto end;
            }
        } else {
            if ((s->version >> 8) != SSL3_VERSION_MAJOR
                    && s->version != TLS_ANY_VERSION) {
                SSLerr(SSL_F_STATE_MACHINE, ERR_R_INTERNAL_ERROR);
                goto end;
            }
        }

        if (!SSL_IS_DTLS(s)) {
            if (s->version != TLS_ANY_VERSION &&
                    !ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
                SSLerr(SSL_F_STATE_MACHINE, SSL_R_VERSION_TOO_LOW);
                goto end;
            }
        }

        if (s->init_buf == NULL) {
            if ((buf = BUF_MEM_new()) == NULL) {
                goto end;
            }
            if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                goto end;
            }
            s->init_buf = buf;
            buf = NULL;
        }

        if (!ssl3_setup_buffers(s)) {
            goto end;
        }
        s->init_num = 0;

        /*
         * Should have been reset by tls_process_finished, too.
         */
        s->s3->change_cipher_spec = 0;

        if (!server || st->state != MSG_FLOW_RENEGOTIATE) {
                /*
                 * Ok, we now need to push on a buffering BIO ...but not with
                 * SCTP
                 */
#ifndef OPENSSL_NO_SCTP
                if (!SSL_IS_DTLS(s) || !BIO_dgram_is_sctp(SSL_get_wbio(s)))
#endif
                    if (!ssl_init_wbio_buffer(s, server ? 1 : 0)) {
                        goto end;
                    }

            ssl3_init_finished_mac(s);
        }

        if (server) {
            if (st->state != MSG_FLOW_RENEGOTIATE) {
                s->ctx->stats.sess_accept++;
            } else if (!s->s3->send_connection_binding &&
                       !(s->options &
                         SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
                /*
                 * Server attempting to renegotiate with client that doesn't
                 * support secure renegotiation.
                 */
                SSLerr(SSL_F_STATE_MACHINE,
                       SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                statem_set_error(s);
                goto end;
            } else {
                /*
                 * s->state == SSL_ST_RENEGOTIATE, we will just send a
                 * HelloRequest
                 */
                s->ctx->stats.sess_accept_renegotiate++;
            }
        } else {
            s->ctx->stats.sess_connect++;

            /* mark client_random uninitialized */
            memset(s->s3->client_random, 0, sizeof(s->s3->client_random));
            s->hit = 0;

            s->s3->tmp.cert_request = 0;

            if (SSL_IS_DTLS(s)) {
                st->use_timer = 1;
            }
        }

        st->state = MSG_FLOW_WRITING;
        init_write_state_machine(s);
        st->read_state_first_init = 1;
    }

    while(st->state != MSG_FLOW_FINISHED) {
        if(st->state == MSG_FLOW_READING) {
            ssret = read_state_machine(s);
            if (ssret == SUB_STATE_FINISHED) {
                st->state = MSG_FLOW_WRITING;
                init_write_state_machine(s);
            } else {
                /* NBIO or error */
                goto end;
            }
        } else if (st->state == MSG_FLOW_WRITING) {
            ssret = write_state_machine(s);
            if (ssret == SUB_STATE_FINISHED) {
                st->state = MSG_FLOW_READING;
                init_read_state_machine(s);
            } else if (ssret == SUB_STATE_END_HANDSHAKE) {
                st->state = MSG_FLOW_FINISHED;
            } else {
                /* NBIO or error */
                goto end;
            }
        } else {
            /* Error */
            statem_set_error(s);
            goto end;
        }
    }

    st->state = MSG_FLOW_UNINITED;
    ret = 1;

 end:
    s->in_handshake--;

#ifndef OPENSSL_NO_SCTP
    if (SSL_IS_DTLS(s)) {
        /*
         * Notify SCTP BIO socket to leave handshake mode and allow stream
         * identifier other than 0. Will be ignored if no SCTP is used.
         */
        BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
                 s->in_handshake, NULL);
    }
#endif

    BUF_MEM_free(buf);
    if (cb != NULL) {
        if (server)
            cb(s, SSL_CB_ACCEPT_EXIT, ret);
        else
            cb(s, SSL_CB_CONNECT_EXIT, ret);
    }
    return ret;
}

/*
 * Initialise the MSG_FLOW_READING sub-state machine
 */
static void init_read_state_machine(SSL *s)
{
    STATEM *st = &s->statem;

    st->read_state = READ_STATE_HEADER;
}

/*
 * This function implements the sub-state machine when the message flow is in
 * MSG_FLOW_READING. The valid sub-states and transitions are:
 *
 * READ_STATE_HEADER <--+<-------------+
 *        |             |              |
 *        v             |              |
 * READ_STATE_BODY -----+-->READ_STATE_POST_PROCESS
 *        |                            |
 *        +----------------------------+
 *        v
 * [SUB_STATE_FINISHED]
 *
 * READ_STATE_HEADER has the responsibility for reading in the message header
 * and transitioning the state of the handshake state machine.
 *
 * READ_STATE_BODY reads in the rest of the message and then subsequently
 * processes it.
 *
 * READ_STATE_POST_PROCESS is an optional step that may occur if some post
 * processing activity performed on the message may block.
 *
 * Any of the above states could result in an NBIO event occuring in which case
 * control returns to the calling application. When this function is recalled we
 * will resume in the same state where we left off.
 */
static enum SUB_STATE_RETURN read_state_machine(SSL *s) {
    STATEM *st = &s->statem;
    int ret, mt;
    unsigned long len;
    int (*transition)(SSL *s, int mt);
    PACKET pkt;
    enum MSG_PROCESS_RETURN (*process_message)(SSL *s, PACKET *pkt);
    enum WORK_STATE (*post_process_message)(SSL *s, enum WORK_STATE wst);
    unsigned long (*max_message_size)(SSL *s);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    if(s->server) {
        transition = server_read_transition;
        process_message = server_process_message;
        max_message_size = server_max_message_size;
        post_process_message = server_post_process_message;
    } else {
        transition = client_read_transition;
        process_message = client_process_message;
        max_message_size = client_max_message_size;
        post_process_message = client_post_process_message;
    }

    if (st->read_state_first_init) {
        s->first_packet = 1;
        st->read_state_first_init = 0;
    }

    while(1) {
        switch(st->read_state) {
        case READ_STATE_HEADER:
            s->init_num = 0;
            /* Get the state the peer wants to move to */
            if (SSL_IS_DTLS(s)) {
                /*
                 * In DTLS we get the whole message in one go - header and body
                 */
                ret = dtls_get_message(s, &mt, &len);
            } else {
                ret = tls_get_message_header(s, &mt);
            }

            if (ret == 0) {
                /* Could be non-blocking IO */
                return SUB_STATE_ERROR;
            }

            if (cb != NULL) {
                /* Notify callback of an impending state change */
                if (s->server)
                    cb(s, SSL_CB_ACCEPT_LOOP, 1);
                else
                    cb(s, SSL_CB_CONNECT_LOOP, 1);
            }
            /*
             * Validate that we are allowed to move to the new state and move
             * to that state if so
             */
            if(!transition(s, mt)) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL3_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_READ_STATE_MACHINE, SSL_R_UNEXPECTED_MESSAGE);
                return SUB_STATE_ERROR;
            }

            if (s->s3->tmp.message_size > max_message_size(s)) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
                SSLerr(SSL_F_READ_STATE_MACHINE, SSL_R_EXCESSIVE_MESSAGE_SIZE);
                return SUB_STATE_ERROR;
            }

            st->read_state = READ_STATE_BODY;
            /* Fall through */

        case READ_STATE_BODY:
            if (!SSL_IS_DTLS(s)) {
                /* We already got this above for DTLS */
                ret = tls_get_message_body(s, &len);
                if (ret == 0) {
                    /* Could be non-blocking IO */
                    return SUB_STATE_ERROR;
                }
            }

            s->first_packet = 0;
            if (!PACKET_buf_init(&pkt, s->init_msg, len)) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                SSLerr(SSL_F_READ_STATE_MACHINE, ERR_R_INTERNAL_ERROR);
                return SUB_STATE_ERROR;
            }
            ret = process_message(s, &pkt);
            if (ret == MSG_PROCESS_ERROR) {
                return SUB_STATE_ERROR;
            }

            if (ret == MSG_PROCESS_FINISHED_READING) {
                if (SSL_IS_DTLS(s)) {
                    dtls1_stop_timer(s);
                }
                return SUB_STATE_FINISHED;
            }

            if (ret == MSG_PROCESS_CONTINUE_PROCESSING) {
                st->read_state = READ_STATE_POST_PROCESS;
                st->read_state_work = WORK_MORE_A;
            } else {
                st->read_state = READ_STATE_HEADER;
            }
            break;

        case READ_STATE_POST_PROCESS:
            st->read_state_work = post_process_message(s, st->read_state_work);
            switch(st->read_state_work) {
            default:
                return SUB_STATE_ERROR;

            case WORK_FINISHED_CONTINUE:
                st->read_state = READ_STATE_HEADER;
                break;

            case WORK_FINISHED_STOP:
                if (SSL_IS_DTLS(s)) {
                    dtls1_stop_timer(s);
                }
                return SUB_STATE_FINISHED;
            }
            break;

        default:
            /* Shouldn't happen */
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_READ_STATE_MACHINE, ERR_R_INTERNAL_ERROR);
            statem_set_error(s);
            return SUB_STATE_ERROR;
        }
    }
}

/*
 * Send a previously constructed message to the peer.
 */
static int statem_do_write(SSL *s)
{
    STATEM *st = &s->statem;

    if (st->hand_state == TLS_ST_CW_CHANGE
            || st->hand_state == TLS_ST_SW_CHANGE) {
        if (SSL_IS_DTLS(s))
            return dtls1_do_write(s, SSL3_RT_CHANGE_CIPHER_SPEC);
        else
            return ssl3_do_write(s, SSL3_RT_CHANGE_CIPHER_SPEC);
    } else {
        return ssl_do_write(s);
    }
}

/*
 * Initialise the MSG_FLOW_WRITING sub-state machine
 */
static void init_write_state_machine(SSL *s)
{
    STATEM *st = &s->statem;

    st->write_state = WRITE_STATE_TRANSITION;
}

/*
 * This function implements the sub-state machine when the message flow is in
 * MSG_FLOW_WRITING. The valid sub-states and transitions are:
 *
 * +-> WRITE_STATE_TRANSITION ------> [SUB_STATE_FINISHED]
 * |             |
 * |             v
 * |      WRITE_STATE_PRE_WORK -----> [SUB_STATE_END_HANDSHAKE]
 * |             |
 * |             v
 * |       WRITE_STATE_SEND
 * |             |
 * |             v
 * |     WRITE_STATE_POST_WORK
 * |             |
 * +-------------+
 *
 * WRITE_STATE_TRANSITION transitions the state of the handshake state machine

 * WRITE_STATE_PRE_WORK performs any work necessary to prepare the later
 * sending of the message. This could result in an NBIO event occuring in
 * which case control returns to the calling application. When this function
 * is recalled we will resume in the same state where we left off.
 *
 * WRITE_STATE_SEND sends the message and performs any work to be done after
 * sending.
 *
 * WRITE_STATE_POST_WORK performs any work necessary after the sending of the
 * message has been completed. As for WRITE_STATE_PRE_WORK this could also
 * result in an NBIO event.
 */
static enum SUB_STATE_RETURN write_state_machine(SSL *s)
{
    STATEM *st = &s->statem;
    int ret;
    enum WRITE_TRAN (*transition)(SSL *s);
    enum WORK_STATE (*pre_work)(SSL *s, enum WORK_STATE wst);
    enum WORK_STATE (*post_work)(SSL *s, enum WORK_STATE wst);
    int (*construct_message)(SSL *s);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    if(s->server) {
        transition = server_write_transition;
        pre_work = server_pre_work;
        post_work = server_post_work;
        construct_message = server_construct_message;
    } else {
        transition = client_write_transition;
        pre_work = client_pre_work;
        post_work = client_post_work;
        construct_message = client_construct_message;
    }

    while(1) {
        switch(st->write_state) {
        case WRITE_STATE_TRANSITION:
            if (cb != NULL) {
                /* Notify callback of an impending state change */
                if (s->server)
                    cb(s, SSL_CB_ACCEPT_LOOP, 1);
                else
                    cb(s, SSL_CB_CONNECT_LOOP, 1);
            }
            switch(transition(s)) {
            case WRITE_TRAN_CONTINUE:
                st->write_state = WRITE_STATE_PRE_WORK;
                st->write_state_work = WORK_MORE_A;
                break;

            case WRITE_TRAN_FINISHED:
                return SUB_STATE_FINISHED;
                break;

            default:
                return SUB_STATE_ERROR;
            }
            break;

        case WRITE_STATE_PRE_WORK:
            switch(st->write_state_work = pre_work(s, st->write_state_work)) {
            default:
                return SUB_STATE_ERROR;

            case WORK_FINISHED_CONTINUE:
                st->write_state = WRITE_STATE_SEND;
                break;

            case WORK_FINISHED_STOP:
                return SUB_STATE_END_HANDSHAKE;
            }
            if(construct_message(s) == 0)
                return SUB_STATE_ERROR;

            /* Fall through */

        case WRITE_STATE_SEND:
            if (SSL_IS_DTLS(s) && st->use_timer) {
                dtls1_start_timer(s);
            }
            ret = statem_do_write(s);
            if (ret <= 0) {
                return SUB_STATE_ERROR;
            }
            st->write_state = WRITE_STATE_POST_WORK;
            st->write_state_work = WORK_MORE_A;
            /* Fall through */

        case WRITE_STATE_POST_WORK:
            switch(st->write_state_work = post_work(s, st->write_state_work)) {
            default:
                return SUB_STATE_ERROR;

            case WORK_FINISHED_CONTINUE:
                st->write_state = WRITE_STATE_TRANSITION;
                break;

            case WORK_FINISHED_STOP:
                return SUB_STATE_END_HANDSHAKE;
            }
            break;

        default:
            return SUB_STATE_ERROR;
        }
    }
}

/*
 * Flush the write BIO
 */
static int statem_flush(SSL *s)
{
    s->rwstate = SSL_WRITING;
    if (BIO_flush(s->wbio) <= 0) {
        return 0;
    }
    s->rwstate = SSL_NOTHING;

    return 1;
}

/*
 * Called by the record layer to determine whether application data is
 * allowed to be sent in the current handshake state or not.
 *
 * Return values are:
 *   1: Yes (application data allowed)
 *   0: No (application data not allowed)
 */
int statem_app_data_allowed(SSL *s)
{
    STATEM *st = &s->statem;

    if (st->state == MSG_FLOW_UNINITED || st->state == MSG_FLOW_RENEGOTIATE)
        return 0;

    if (!s->s3->in_read_app_data || (s->s3->total_renegotiations == 0))
        return 0;

    if (s->server) {
        /*
         * If we're a server and we haven't got as far as writing our
         * ServerHello yet then we allow app data
         */
        if (st->hand_state == TLS_ST_BEFORE
                || st->hand_state == TLS_ST_SR_CLNT_HELLO)
            return 1;
    } else {
        /*
         * If we're a client and we haven't read the ServerHello yet then we
         * allow app data
         */
        if (st->hand_state == TLS_ST_CW_CLNT_HELLO)
            return 1;
    }

    return 0;
}


#ifndef OPENSSL_NO_SCTP
/*
 * Set flag used by SCTP to determine whether we are in the read sock state
 */
void statem_set_sctp_read_sock(SSL *s, int read_sock)
{
    s->statem.in_sctp_read_sock = read_sock;
}

/*
 * Called by the record layer to determine whether we are in the read sock
 * state or not.
 *
 * Return values are:
 *   1: Yes (we are in the read sock state)
 *   0: No (we are not in the read sock state)
 */
int statem_in_sctp_read_sock(SSL *s)
{
    return s->statem.in_sctp_read_sock;
}
#endif

/*
 * Is a CertificateRequest message allowed at the moment or not?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static inline int cert_req_allowed(SSL *s)
{
    /* TLS does not like anon-DH with client cert */
    if (s->version > SSL3_VERSION
            && (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL))
        return 0;

    return 1;
}

/*
 * Are we allowed to skip the ServerKeyExchange message?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static inline int key_exchange_skip_allowed(SSL *s)
{
    long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * Can't skip server key exchange if this is an ephemeral
     * ciphersuite.
     */
    if (alg_k & (SSL_kDHE | SSL_kECDHE)) {
        return 0;
    }

    return 1;
}

/*
 * client_read_transition() encapsulates the logic for the allowed handshake
 * state transitions when the client is reading messages from the server. The
 * message type that the server has sent is provided in |mt|. The current state
 * is in |s->statem.hand_state|.
 *
 *  Return values are:
 *  1: Success (transition allowed)
 *  0: Error (transition not allowed)
 */
static int client_read_transition(SSL *s, int mt)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_CW_CLNT_HELLO:
        if (mt == SSL3_MT_SERVER_HELLO) {
            st->hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }

        if (SSL_IS_DTLS(s)) {
            if (mt == DTLS1_MT_HELLO_VERIFY_REQUEST) {
                st->hand_state = DTLS_ST_CR_HELLO_VERIFY_REQUEST;
                return 1;
            }
        }
        break;

    case TLS_ST_CR_SRVR_HELLO:
        if (s->hit) {
            if (s->tlsext_ticket_expected) {
                if (mt == SSL3_MT_NEWSESSION_TICKET) {
                    st->hand_state = TLS_ST_CR_SESSION_TICKET;
                    return 1;
                }
            } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                st->hand_state = TLS_ST_CR_CHANGE;
                return 1;
            }
        } else {
            if (SSL_IS_DTLS(s) && mt == DTLS1_MT_HELLO_VERIFY_REQUEST) {
                st->hand_state = DTLS_ST_CR_HELLO_VERIFY_REQUEST;
                return 1;
            } else if (!(s->s3->tmp.new_cipher->algorithm_auth
                        & (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                if (mt == SSL3_MT_CERTIFICATE) {
                    st->hand_state = TLS_ST_CR_CERT;
                    return 1;
                }
            } else {
                if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                    st->hand_state = TLS_ST_CR_KEY_EXCH;
                    return 1;
                } else if (key_exchange_skip_allowed(s)) {
                    if (mt == SSL3_MT_CERTIFICATE_REQUEST
                            && cert_req_allowed(s)) {
                        st->hand_state = TLS_ST_CR_CERT_REQ;
                        return 1;
                    } else if (mt == SSL3_MT_SERVER_DONE) {
                        st->hand_state = TLS_ST_CR_SRVR_DONE;
                        return 1;
                    }
                }
            }
        }
        break;

    case TLS_ST_CR_CERT:
        if (s->tlsext_status_expected) {
            if (mt == SSL3_MT_CERTIFICATE_STATUS) {
                st->hand_state = TLS_ST_CR_CERT_STATUS;
                return 1;
            }
        } else {
            if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                st->hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            } else if (key_exchange_skip_allowed(s)) {
                if (mt == SSL3_MT_CERTIFICATE_REQUEST && cert_req_allowed(s)) {
                    st->hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                } else if (mt == SSL3_MT_SERVER_DONE) {
                    st->hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
        }
        break;

    case TLS_ST_CR_CERT_STATUS:
        if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
            st->hand_state = TLS_ST_CR_KEY_EXCH;
            return 1;
        } else if (key_exchange_skip_allowed(s)) {
            if (mt == SSL3_MT_CERTIFICATE_REQUEST && cert_req_allowed(s)) {
                st->hand_state = TLS_ST_CR_CERT_REQ;
                return 1;
            } else if (mt == SSL3_MT_SERVER_DONE) {
                st->hand_state = TLS_ST_CR_SRVR_DONE;
                return 1;
            }
        }
        break;

    case TLS_ST_CR_KEY_EXCH:
        if (mt == SSL3_MT_CERTIFICATE_REQUEST && cert_req_allowed(s)) {
            st->hand_state = TLS_ST_CR_CERT_REQ;
            return 1;
        } else if (mt == SSL3_MT_SERVER_DONE) {
            st->hand_state = TLS_ST_CR_SRVR_DONE;
            return 1;
        }
        break;

    case TLS_ST_CR_CERT_REQ:
        if (mt == SSL3_MT_SERVER_DONE) {
            st->hand_state = TLS_ST_CR_SRVR_DONE;
            return 1;
        }
        break;

    case TLS_ST_CW_FINISHED:
        if (mt == SSL3_MT_NEWSESSION_TICKET && s->tlsext_ticket_expected) {
            st->hand_state = TLS_ST_CR_SESSION_TICKET;
            return 1;
        } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_SESSION_TICKET:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_CHANGE:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_CR_FINISHED;
            return 1;
        }
        break;

    default:
        break;
    }

    /* No valid transition found */
    return 0;
}

/*
 * client_write_transition() works out what handshake state to move to next
 * when the client is writing messages to be sent to the server.
 */
static enum WRITE_TRAN client_write_transition(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
        case TLS_ST_OK:
            /* Renegotiation - fall through */
        case TLS_ST_BEFORE:
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_CLNT_HELLO:
            /*
             * No transition at the end of writing because we don't know what
             * we will be sent
             */
            return WRITE_TRAN_FINISHED;

        case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CR_SRVR_DONE:
            if (s->s3->tmp.cert_req)
                st->hand_state = TLS_ST_CW_CERT;
            else
                st->hand_state = TLS_ST_CW_KEY_EXCH;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_CERT:
            st->hand_state = TLS_ST_CW_KEY_EXCH;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_KEY_EXCH:
            /*
             * For TLS, cert_req is set to 2, so a cert chain of nothing is
             * sent, but no verify packet is sent
             */
            /*
             * XXX: For now, we do not support client authentication in ECDH
             * cipher suites with ECDH (rather than ECDSA) certificates. We
             * need to skip the certificate verify message when client's
             * ECDH public key is sent inside the client certificate.
             */
            if (s->s3->tmp.cert_req == 1) {
                st->hand_state = TLS_ST_CW_CERT_VRFY;
            } else {
                st->hand_state = TLS_ST_CW_CHANGE;
            }
            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                st->hand_state = TLS_ST_CW_CHANGE;
            }
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_CERT_VRFY:
            st->hand_state = TLS_ST_CW_CHANGE;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_CHANGE:
#if defined(OPENSSL_NO_NEXTPROTONEG)
            st->hand_state = TLS_ST_CW_FINISHED;
#else
            if (!SSL_IS_DTLS(s) && s->s3->next_proto_neg_seen)
                st->hand_state = TLS_ST_CW_NEXT_PROTO;
            else
                st->hand_state = TLS_ST_CW_FINISHED;
#endif
            return WRITE_TRAN_CONTINUE;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
        case TLS_ST_CW_NEXT_PROTO:
            st->hand_state = TLS_ST_CW_FINISHED;
            return WRITE_TRAN_CONTINUE;
#endif

        case TLS_ST_CW_FINISHED:
            if (s->hit) {
                st->hand_state = TLS_ST_OK;
                statem_set_in_init(s, 0);
                return WRITE_TRAN_CONTINUE;
            } else {
                return WRITE_TRAN_FINISHED;
            }

        case TLS_ST_CR_FINISHED:
            if (s->hit) {
                st->hand_state = TLS_ST_CW_CHANGE;
                return WRITE_TRAN_CONTINUE;
            } else {
                st->hand_state = TLS_ST_OK;
                statem_set_in_init(s, 0);
                return WRITE_TRAN_CONTINUE;
            }

        default:
            /* Shouldn't happen */
            return WRITE_TRAN_ERROR;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the client to the server.
 */
static enum WORK_STATE client_pre_work(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_CW_CLNT_HELLO:
        s->shutdown = 0;
        if (SSL_IS_DTLS(s)) {
            /* every DTLS ClientHello resets Finished MAC */
            ssl3_init_finished_mac(s);
        }
        break;

    case TLS_ST_CW_CERT:
        return tls_prepare_client_certificate(s, wst);

    case TLS_ST_CW_CHANGE:
        if (SSL_IS_DTLS(s)) {
            if (s->hit) {
                /*
                 * We're into the last flight so we don't retransmit these
                 * messages unless we need to.
                 */
                st->use_timer = 0;
            }
#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s)))
                return dtls_wait_for_dry(s);
#endif
        }
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_OK:
        return tls_finish_handshake(s, wst);

    default:
        /* No pre work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * client to the server.
 */
static enum WORK_STATE client_post_work(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    s->init_num = 0;

    switch(st->hand_state) {
    case TLS_ST_CW_CLNT_HELLO:
        if (SSL_IS_DTLS(s) && s->d1->cookie_len > 0 && statem_flush(s) != 1)
            return WORK_MORE_A;
#ifndef OPENSSL_NO_SCTP
        /* Disable buffering for SCTP */
        if (!SSL_IS_DTLS(s) || !BIO_dgram_is_sctp(SSL_get_wbio(s))) {
#endif
            /*
             * turn on buffering for the next lot of output
             */
            if (s->bbio != s->wbio)
                s->wbio = BIO_push(s->bbio, s->wbio);
#ifndef OPENSSL_NO_SCTP
            }
#endif
        if (SSL_IS_DTLS(s)) {
            /* Treat the next message as the first packet */
            s->first_packet = 1;
        }
        break;

    case TLS_ST_CW_KEY_EXCH:
        if (tls_client_key_exchange_post_work(s) == 0)
            return WORK_ERROR;
        break;

    case TLS_ST_CW_CHANGE:
        s->session->cipher = s->s3->tmp.new_cipher;
#ifdef OPENSSL_NO_COMP
        s->session->compress_meth = 0;
#else
        if (s->s3->tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3->tmp.new_compression->id;
#endif
        if (!s->method->ssl3_enc->setup_key_block(s))
            return WORK_ERROR;

        if (!s->method->ssl3_enc->change_cipher_state(s,
                                                      SSL3_CHANGE_CIPHER_CLIENT_WRITE))
            return WORK_ERROR;

        if (SSL_IS_DTLS(s)) {
#ifndef OPENSSL_NO_SCTP
            if (s->hit) {
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
            }
#endif

            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
        }
        break;

    case TLS_ST_CW_FINISHED:
#ifndef OPENSSL_NO_SCTP
        if (wst == WORK_MORE_A && SSL_IS_DTLS(s) && s->hit == 0) {
            /*
             * Change to new shared key of SCTP-Auth, will be ignored if
             * no SCTP used.
             */
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                     0, NULL);
        }
#endif
        if (statem_flush(s) != 1)
            return WORK_MORE_B;

        if (s->hit && tls_finish_handshake(s, WORK_MORE_A) != 1)
                return WORK_ERROR;
        break;

    default:
        /* No post work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Construct a message to be sent from the client to the server.
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
static int client_construct_message(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_CW_CLNT_HELLO:
        return tls_construct_client_hello(s);

    case TLS_ST_CW_CERT:
        return tls_construct_client_certificate(s);

    case TLS_ST_CW_KEY_EXCH:
        return tls_construct_client_key_exchange(s);

    case TLS_ST_CW_CERT_VRFY:
        return tls_construct_client_verify(s);

    case TLS_ST_CW_CHANGE:
        if (SSL_IS_DTLS(s))
            return dtls_construct_change_cipher_spec(s);
        else
            return tls_construct_change_cipher_spec(s);

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    case TLS_ST_CW_NEXT_PROTO:
        return tls_construct_next_proto(s);
#endif
    case TLS_ST_CW_FINISHED:
        return tls_construct_finished(s,
                                      s->method->
                                      ssl3_enc->client_finished_label,
                                      s->method->
                                      ssl3_enc->client_finished_label_len);

    default:
        /* Shouldn't happen */
        break;
    }

    return 0;
}

/* The spec allows for a longer length than this, but we limit it */
#define HELLO_VERIFY_REQUEST_MAX_LENGTH 258
#define SERVER_HELLO_MAX_LENGTH         20000
#define SERVER_KEY_EXCH_MAX_LENGTH      102400
#define SERVER_HELLO_DONE_MAX_LENGTH    0
#define CCS_MAX_LENGTH                  1
/* Max should actually be 36 but we are generous */
#define FINISHED_MAX_LENGTH             64

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
static unsigned long client_max_message_size(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
        case TLS_ST_CR_SRVR_HELLO:
            return SERVER_HELLO_MAX_LENGTH;

        case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
            return HELLO_VERIFY_REQUEST_MAX_LENGTH;

        case TLS_ST_CR_CERT:
            return s->max_cert_list;

        case TLS_ST_CR_CERT_STATUS:
            return SSL3_RT_MAX_PLAIN_LENGTH;

        case TLS_ST_CR_KEY_EXCH:
            return SERVER_KEY_EXCH_MAX_LENGTH;

        case TLS_ST_CR_CERT_REQ:
            return SSL3_RT_MAX_PLAIN_LENGTH;

        case TLS_ST_CR_SRVR_DONE:
            return SERVER_HELLO_DONE_MAX_LENGTH;

        case TLS_ST_CR_CHANGE:
            return CCS_MAX_LENGTH;

        case TLS_ST_CR_SESSION_TICKET:
            return SSL3_RT_MAX_PLAIN_LENGTH;

        case TLS_ST_CR_FINISHED:
            return FINISHED_MAX_LENGTH;

        default:
            /* Shouldn't happen */
            break;
    }

    return 0;
}

/*
 * Process a message that the client has been received from the server.
 */
static enum MSG_PROCESS_RETURN client_process_message(SSL *s, PACKET *pkt)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
        case TLS_ST_CR_SRVR_HELLO:
            return tls_process_server_hello(s, pkt);

        case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
            return dtls_process_hello_verify(s, pkt);

        case TLS_ST_CR_CERT:
            return tls_process_server_certificate(s, pkt);

        case TLS_ST_CR_CERT_STATUS:
            return tls_process_cert_status(s, pkt);

        case TLS_ST_CR_KEY_EXCH:
            return tls_process_key_exchange(s, pkt);

        case TLS_ST_CR_CERT_REQ:
            return tls_process_certificate_request(s, pkt);

        case TLS_ST_CR_SRVR_DONE:
            return tls_process_server_done(s, pkt);

        case TLS_ST_CR_CHANGE:
            return tls_process_change_cipher_spec(s, pkt);

        case TLS_ST_CR_SESSION_TICKET:
            return tls_process_new_session_ticket(s, pkt);

        case TLS_ST_CR_FINISHED:
            return tls_process_finished(s, pkt);

        default:
            /* Shouldn't happen */
            break;
    }

    return MSG_PROCESS_ERROR;
}

/*
 * Perform any further processing required following the receipt of a message
 * from the server
 */
static enum WORK_STATE client_post_process_message(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
#ifndef OPENSSL_NO_SCTP
    case TLS_ST_CR_SRVR_DONE:
        /* We only get here if we are using SCTP and we are renegotiating */
        if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
            s->s3->in_read_app_data = 2;
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            statem_set_sctp_read_sock(s, 1);
            return WORK_MORE_A;
        }
        statem_set_sctp_read_sock(s, 0);
        return WORK_FINISHED_STOP;
#endif

    case TLS_ST_CR_FINISHED:
        if (!s->hit)
            return tls_finish_handshake(s, wst);
        else
            return WORK_FINISHED_STOP;
    default:
        break;
    }

    /* Shouldn't happen */
    return WORK_ERROR;
}


/*
 * server_read_transition() encapsulates the logic for the allowed handshake
 * state transitions when the server is reading messages from the client. The
 * message type that the client has sent is provided in |mt|. The current state
 * is in |s->statem.hand_state|.
 *
 *  Valid return values are:
 *  1: Success (transition allowed)
 *  0: Error (transition not allowed)
 */
static int server_read_transition(SSL *s, int mt)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_BEFORE:
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        if (mt == SSL3_MT_CLIENT_HELLO) {
            st->hand_state = TLS_ST_SR_CLNT_HELLO;
            return 1;
        }
        break;

    case TLS_ST_SW_SRVR_DONE:
        /*
         * If we get a CKE message after a ServerDone then either
         * 1) We didn't request a Certificate
         * OR
         * 2) If we did request one then
         *      a) We allow no Certificate to be returned
         *      AND
         *      b) We are running SSL3 (in TLS1.0+ the client must return a 0
         *         list if we requested a certificate)
         */
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE
                && (!s->s3->tmp.cert_request
                    || (!((s->verify_mode & SSL_VERIFY_PEER) &&
                          (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
                        && (s->version == SSL3_VERSION)))) {
            st->hand_state = TLS_ST_SR_KEY_EXCH;
            return 1;
        } else if (s->s3->tmp.cert_request) {
            if (mt == SSL3_MT_CERTIFICATE) {
                st->hand_state = TLS_ST_SR_CERT;
                return 1;
            } 
        }
        break;

    case TLS_ST_SR_CERT:
        if (mt == SSL3_MT_CLIENT_KEY_EXCHANGE) {
            st->hand_state = TLS_ST_SR_KEY_EXCH;
            return 1;
        }
        break;

    case TLS_ST_SR_KEY_EXCH:
        /*
         * We should only process a CertificateVerify message if we have
         * received a Certificate from the client. If so then |s->session->peer|
         * will be non NULL. In some instances a CertificateVerify message is
         * not required even if the peer has sent a Certificate (e.g. such as in
         * the case of static DH). In that case |s->no_cert_verify| should be
         * set.
         */
        if (s->session->peer == NULL || s->no_cert_verify) {
            if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent. Also for GOST ciphersuites when the client uses
                 * its key from the certificate for key exchange.
                 */
                st->hand_state = TLS_ST_SR_CHANGE;
                return 1;
            }
        } else {
            if (mt == SSL3_MT_CERTIFICATE_VERIFY) {
                st->hand_state = TLS_ST_SR_CERT_VRFY;
                return 1;
            }
        }
        break;

    case TLS_ST_SR_CERT_VRFY:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_SR_CHANGE:
#ifndef OPENSSL_NO_NEXTPROTONEG
        if (s->s3->next_proto_neg_seen) {
            if (mt == SSL3_MT_NEXT_PROTO) {
                st->hand_state = TLS_ST_SR_NEXT_PROTO;
                return 1;
            }
        } else {
#endif
            if (mt == SSL3_MT_FINISHED) {
                st->hand_state = TLS_ST_SR_FINISHED;
                return 1;
            }
#ifndef OPENSSL_NO_NEXTPROTONEG
        }
#endif
        break;

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_SR_FINISHED;
            return 1;
        }
        break;
#endif

    case TLS_ST_SW_FINISHED:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_SR_CHANGE;
            return 1;
        }
        break;

    default:
        break;
    }

    /* No valid transition found */
    return 0;
}

/*
 * Should we send a ServerKeyExchange message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
static inline int send_server_key_exchange(SSL *s)
{
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * only send a ServerKeyExchange if DH, fortezza or RSA but we have a
     * sign only certificate PSK: may send PSK identity hints For
     * ECC ciphersuites, we send a serverKeyExchange message only if
     * the cipher suite is either ECDH-anon or ECDHE. In other cases,
     * the server certificate contains the server's public key for
     * key exchange.
     */
    if (   (alg_k & SSL_kDHE)
        || (alg_k & SSL_kECDHE)
        || ((alg_k & SSL_kRSA)
            && (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
                || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
                    && EVP_PKEY_size(s->cert->pkeys
                                     [SSL_PKEY_RSA_ENC].privatekey) *
                    8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
                   )
               )
           )
        /*
         * PSK: send ServerKeyExchange if PSK identity hint if
         * provided
         */
#ifndef OPENSSL_NO_PSK
        /* Only send SKE if we have identity hint for plain PSK */
        || ((alg_k & (SSL_kPSK | SSL_kRSAPSK))
            && s->cert->psk_identity_hint)
        /* For other PSK always send SKE */
        || (alg_k & (SSL_PSK & (SSL_kDHEPSK | SSL_kECDHEPSK)))
#endif
#ifndef OPENSSL_NO_SRP
        /* SRP: send ServerKeyExchange */
        || (alg_k & SSL_kSRP)
#endif
       ) {
        return 1;
    }

    return 0;
}

/*
 * Should we send a CertificateRequest message?
 *
 * Valid return values are:
 *   1: Yes
 *   0: No
 */
static inline int send_certificate_request(SSL *s)
{
    if (
           /* don't request cert unless asked for it: */
           s->verify_mode & SSL_VERIFY_PEER
           /*
            * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
            * during re-negotiation:
            */
           && ((s->session->peer == NULL) ||
               !(s->verify_mode & SSL_VERIFY_CLIENT_ONCE))
           /*
            * never request cert in anonymous ciphersuites (see
            * section "Certificate request" in SSL 3 drafts and in
            * RFC 2246):
            */
           && (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
           /*
            * ... except when the application insists on
            * verification (against the specs, but s3_clnt.c accepts
            * this for SSL 3)
            */
               || (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))
           /* don't request certificate for SRP auth */
           && !(s->s3->tmp.new_cipher->algorithm_auth & SSL_aSRP)
           /*
            * With normal PSK Certificates and Certificate Requests
            * are omitted
            */
           && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_PSK)) {
        return 1;
    }

    return 0;
}

/*
 * server_write_transition() works out what handshake state to move to next
 * when the server is writing messages to be sent to the client.
 */
static enum WRITE_TRAN server_write_transition(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
        case TLS_ST_BEFORE:
            /* Just go straight to trying to read from the client */;
            return WRITE_TRAN_FINISHED;

        case TLS_ST_OK:
            /* We must be trying to renegotiate */
            st->hand_state = TLS_ST_SW_HELLO_REQ;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_HELLO_REQ:
            st->hand_state = TLS_ST_OK;
            statem_set_in_init(s, 0);
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SR_CLNT_HELLO:
            if (SSL_IS_DTLS(s) && !s->d1->cookie_verified
                    && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
                st->hand_state = DTLS_ST_SW_HELLO_VERIFY_REQUEST;
            else
                st->hand_state = TLS_ST_SW_SRVR_HELLO;
            return WRITE_TRAN_CONTINUE;

        case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
            return WRITE_TRAN_FINISHED;

        case TLS_ST_SW_SRVR_HELLO:
            if (s->hit) {
                if (s->tlsext_ticket_expected)
                    st->hand_state = TLS_ST_SW_SESSION_TICKET;
                else
                    st->hand_state = TLS_ST_SW_CHANGE;
            } else {
                /* Check if it is anon DH or anon ECDH, */
                /* normal PSK or SRP */
                if (!(s->s3->tmp.new_cipher->algorithm_auth &
                     (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                    st->hand_state = TLS_ST_SW_CERT;
                } else if (send_server_key_exchange(s)) {
                    st->hand_state = TLS_ST_SW_KEY_EXCH;
                } else if (send_certificate_request(s)) {
                    st->hand_state = TLS_ST_SW_CERT_REQ;
                } else {
                    st->hand_state = TLS_ST_SW_SRVR_DONE;
                }
            }
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_CERT:
            if (s->tlsext_status_expected) {
                st->hand_state = TLS_ST_SW_CERT_STATUS;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_CERT_STATUS:
            if (send_server_key_exchange(s)) {
                st->hand_state = TLS_ST_SW_KEY_EXCH;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_KEY_EXCH:
            if (send_certificate_request(s)) {
                st->hand_state = TLS_ST_SW_CERT_REQ;
                return WRITE_TRAN_CONTINUE;
            }
            /* Fall through */

        case TLS_ST_SW_CERT_REQ:
            st->hand_state = TLS_ST_SW_SRVR_DONE;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_SRVR_DONE:
            return WRITE_TRAN_FINISHED;

        case TLS_ST_SR_FINISHED:
            if (s->hit) {
                st->hand_state = TLS_ST_OK;
                statem_set_in_init(s, 0);
                return WRITE_TRAN_CONTINUE;
            } else if (s->tlsext_ticket_expected) {
                st->hand_state = TLS_ST_SW_SESSION_TICKET;
            } else {
                st->hand_state = TLS_ST_SW_CHANGE;
            }
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_SESSION_TICKET:
            st->hand_state = TLS_ST_SW_CHANGE;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_CHANGE:
            st->hand_state = TLS_ST_SW_FINISHED;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_SW_FINISHED:
            if (s->hit) {
                return WRITE_TRAN_FINISHED;
            }
            st->hand_state = TLS_ST_OK;
            statem_set_in_init(s, 0);
            return WRITE_TRAN_CONTINUE;

        default:
            /* Shouldn't happen */
            return WRITE_TRAN_ERROR;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the server to the client.
 */
static enum WORK_STATE server_pre_work(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SW_HELLO_REQ:
        s->shutdown = 0;
        if (SSL_IS_DTLS(s))
            dtls1_clear_record_buffer(s);
        break;

    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        s->shutdown = 0;
        if (SSL_IS_DTLS(s)) {
            dtls1_clear_record_buffer(s);
            /* We don't buffer this message so don't use the timer */
            st->use_timer = 0;
        }
        break;

    case TLS_ST_SW_SRVR_HELLO:
        if (SSL_IS_DTLS(s)) {
            /*
             * Messages we write from now on should be bufferred and
             * retransmitted if necessary, so we need to use the timer now
             */
            st->use_timer = 1;
        }
        break;

    case TLS_ST_SW_SRVR_DONE:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && BIO_dgram_is_sctp(SSL_get_wbio(s)))
            return dtls_wait_for_dry(s);
#endif
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_SW_SESSION_TICKET:
        if (SSL_IS_DTLS(s)) {
            /*
             * We're into the last flight. We don't retransmit the last flight
             * unless we need to, so we don't use the timer
             */
            st->use_timer = 0;
        }
        break;

    case TLS_ST_SW_CHANGE:
        s->session->cipher = s->s3->tmp.new_cipher;
        if (!s->method->ssl3_enc->setup_key_block(s)) {
            statem_set_error(s);
            return WORK_ERROR;
        }
        if (SSL_IS_DTLS(s)) {
            /*
             * We're into the last flight. We don't retransmit the last flight
             * unless we need to, so we don't use the timer. This might have
             * already been set to 0 if we sent a NewSessionTicket message,
             * but we'll set it again here in case we didn't.
             */
            st->use_timer = 0;
        }
        return WORK_FINISHED_CONTINUE;

    case TLS_ST_OK:
        return tls_finish_handshake(s, wst);

    default:
        /* No pre work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * server to the client.
 */
static enum WORK_STATE server_post_work(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    s->init_num = 0;

    switch(st->hand_state) {
    case TLS_ST_SW_HELLO_REQ:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        ssl3_init_finished_mac(s);
        break;

    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        /* HelloVerifyRequest resets Finished MAC */
        if (s->version != DTLS1_BAD_VER)
            ssl3_init_finished_mac(s);
        /*
         * The next message should be another ClientHello which we need to
         * treat like it was the first packet
         */
        s->first_packet = 1;
        break;

    case TLS_ST_SW_SRVR_HELLO:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && s->hit) {
            unsigned char sctpauthkey[64];
            char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];

            /*
             * Add new shared key for SCTP-Auth, will be ignored if no
             * SCTP used.
             */
            snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                     DTLS1_SCTP_AUTH_LABEL);

            if (SSL_export_keying_material(s, sctpauthkey,
                    sizeof(sctpauthkey), labelbuffer,
                    sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                statem_set_error(s);
                return WORK_ERROR;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
        }
#endif
        break;

    case TLS_ST_SW_CHANGE:
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && !s->hit) {
            /*
             * Change to new shared key of SCTP-Auth, will be ignored if
             * no SCTP used.
             */
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                     0, NULL);
        }
#endif
        if (!s->method->ssl3_enc->change_cipher_state(s,
                SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
            statem_set_error(s);
            return WORK_ERROR;
        }

        if (SSL_IS_DTLS(s))
            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
        break;

    case TLS_ST_SW_SRVR_DONE:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
        break;

    case TLS_ST_SW_FINISHED:
        if (statem_flush(s) != 1)
            return WORK_MORE_A;
#ifndef OPENSSL_NO_SCTP
        if (SSL_IS_DTLS(s) && s->hit) {
            /*
             * Change to new shared key of SCTP-Auth, will be ignored if
             * no SCTP used.
             */
            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                     0, NULL);
        }
#endif
        break;

    default:
        /* No post work to be done */
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Construct a message to be sent from the server to the client.
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
static int server_construct_message(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case DTLS_ST_SW_HELLO_VERIFY_REQUEST:
        return dtls_construct_hello_verify_request(s);

    case TLS_ST_SW_HELLO_REQ:
        return tls_construct_hello_request(s);

    case TLS_ST_SW_SRVR_HELLO:
        return tls_construct_server_hello(s);

    case TLS_ST_SW_CERT:
        return tls_construct_server_certificate(s);

    case TLS_ST_SW_KEY_EXCH:
        return tls_construct_server_key_exchange(s);

    case TLS_ST_SW_CERT_REQ:
        return tls_construct_certificate_request(s);

    case TLS_ST_SW_SRVR_DONE:
        return tls_construct_server_done(s);

    case TLS_ST_SW_SESSION_TICKET:
        return tls_construct_new_session_ticket(s);

    case TLS_ST_SW_CERT_STATUS:
        return tls_construct_cert_status(s);

    case TLS_ST_SW_CHANGE:
        if (SSL_IS_DTLS(s))
            return dtls_construct_change_cipher_spec(s);
        else
            return tls_construct_change_cipher_spec(s);

    case TLS_ST_SW_FINISHED:
        return tls_construct_finished(s,
                                      s->method->
                                      ssl3_enc->server_finished_label,
                                      s->method->
                                      ssl3_enc->server_finished_label_len);

    default:
        /* Shouldn't happen */
        break;
    }

    return 0;
}

#define CLIENT_KEY_EXCH_MAX_LENGTH      2048
#define NEXT_PROTO_MAX_LENGTH           514

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
static unsigned long server_max_message_size(SSL *s)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_SR_CERT:
        return s->max_cert_list;

    case TLS_ST_SR_KEY_EXCH:
        return CLIENT_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_SR_CERT_VRFY:
        return SSL3_RT_MAX_PLAIN_LENGTH;

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return NEXT_PROTO_MAX_LENGTH;
#endif

    case TLS_ST_SR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_SR_FINISHED:
        return FINISHED_MAX_LENGTH;

    default:
        /* Shouldn't happen */
        break;
    }

    return 0;
}

/*
 * Process a message that the server has received from the client.
 */
static enum MSG_PROCESS_RETURN  server_process_message(SSL *s, PACKET *pkt)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return tls_process_client_hello(s, pkt);

    case TLS_ST_SR_CERT:
        return tls_process_client_certificate(s, pkt);

    case TLS_ST_SR_KEY_EXCH:
        return tls_process_client_key_exchange(s, pkt);

    case TLS_ST_SR_CERT_VRFY:
        return tls_process_cert_verify(s, pkt);

#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLS_ST_SR_NEXT_PROTO:
        return tls_process_next_proto(s, pkt);
#endif

    case TLS_ST_SR_CHANGE:
        return tls_process_change_cipher_spec(s, pkt);

    case TLS_ST_SR_FINISHED:
        return tls_process_finished(s, pkt);

    default:
        /* Shouldn't happen */
        break;
    }

    return MSG_PROCESS_ERROR;
}

/*
 * Perform any further processing required following the receipt of a message
 * from the client
 */
static enum WORK_STATE server_post_process_message(SSL *s, enum WORK_STATE wst)
{
    STATEM *st = &s->statem;

    switch(st->hand_state) {
    case TLS_ST_SR_CLNT_HELLO:
        return tls_post_process_client_hello(s, wst);

    case TLS_ST_SR_KEY_EXCH:
        return tls_post_process_client_key_exchange(s, wst);

    case TLS_ST_SR_CERT_VRFY:
#ifndef OPENSSL_NO_SCTP
        if (    /* Is this SCTP? */
                BIO_dgram_is_sctp(SSL_get_wbio(s))
                /* Are we renegotiating? */
                && s->renegotiate
                && BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
            s->s3->in_read_app_data = 2;
            s->rwstate = SSL_READING;
            BIO_clear_retry_flags(SSL_get_rbio(s));
            BIO_set_retry_read(SSL_get_rbio(s));
            statem_set_sctp_read_sock(s, 1);
            return WORK_MORE_A;
        } else {
            statem_set_sctp_read_sock(s, 0);
        }
#endif
        return WORK_FINISHED_CONTINUE;


    case TLS_ST_SR_FINISHED:
        if (s->hit)
            return tls_finish_handshake(s, wst);
        else
            return WORK_FINISHED_STOP;
    default:
        break;
    }

    /* Shouldn't happen */
    return WORK_ERROR;
}
