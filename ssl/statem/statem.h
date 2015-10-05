/* ssl/statem/statem.h */
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

/*****************************************************************************
 *                                                                           *
 * These emums should be considered PRIVATE to the state machine. No         *
 * non-state machine code should need to use these                           *
 *                                                                           *
 *****************************************************************************/
/*
 * Valid return codes used for functions performing work prior to or after
 * sending or receiving a message
 */
enum WORK_STATE {
    /* Something went wrong */
    WORK_ERROR,
    /* We're done working and there shouldn't be anything else to do after */
    WORK_FINISHED_STOP,
    /* We're done working move onto the next thing */
    WORK_FINISHED_CONTINUE,
    /* We're working on phase A */
    WORK_MORE_A,
    /* We're working on phase B */
    WORK_MORE_B
};

/* Write transition return codes */
enum WRITE_TRAN {
    /* Something went wrong */
    WRITE_TRAN_ERROR,
    /* A transition was successfully completed and we should continue */
    WRITE_TRAN_CONTINUE,
    /* There is no more write work to be done */
    WRITE_TRAN_FINISHED
};

/* Message flow states */
enum MSG_FLOW_STATE {
    /* No handshake in progress */
    MSG_FLOW_UNINITED,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR,
    /* We are about to renegotiate */
    MSG_FLOW_RENEGOTIATE,
    /* We are reading messages */
    MSG_FLOW_READING,
    /* We are writing messages */
    MSG_FLOW_WRITING,
    /* Handshake has finished */
    MSG_FLOW_FINISHED
};

/* Read states */
enum READ_STATE {
    READ_STATE_HEADER,
    READ_STATE_BODY,
    READ_STATE_POST_PROCESS
};

/* Write states */
enum WRITE_STATE {
    WRITE_STATE_TRANSITION,
    WRITE_STATE_PRE_WORK,
    WRITE_STATE_SEND,
    WRITE_STATE_POST_WORK
};


/*****************************************************************************
 *                                                                           *
 * This structure should be considered "opaque" to anything outside of the   *
 * state machine. No non-state machine code should be accessing the members  *
 * of this structure.                                                        *
 *                                                                           *
 *****************************************************************************/

struct statem_st {
    enum MSG_FLOW_STATE state;
    enum WRITE_STATE write_state;
    enum WORK_STATE write_state_work;
    enum READ_STATE read_state;
    enum WORK_STATE read_state_work;
    OSSL_HANDSHAKE_STATE hand_state;
    int in_init;
    int read_state_first_init;
    int use_timer;
#ifndef OPENSSL_NO_SCTP
    int in_sctp_read_sock;
#endif
};
typedef struct statem_st STATEM;


/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * state machine. Any libssl code may call these functions/macros            *
 *                                                                           *
 *****************************************************************************/

__owur int statem_accept(SSL *s);
__owur int statem_connect(SSL *s);
void statem_clear(SSL *s);
void statem_set_renegotiate(SSL *s);
void statem_set_error(SSL *s);
int statem_in_error(const SSL *s);
void statem_set_in_init(SSL *s, int init);
__owur int statem_app_data_allowed(SSL *s);
#ifndef OPENSSL_NO_SCTP
void statem_set_sctp_read_sock(SSL *s, int read_sock);
__owur int statem_in_sctp_read_sock(SSL *s);
#endif


