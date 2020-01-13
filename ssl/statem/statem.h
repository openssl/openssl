/*
 * Copyright 2015-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*****************************************************************************
 *                                                                           *
 * These enums should be considered PRIVATE to the state machine. No         *
 * non-state machine code should need to use these                           *
 *                                                                           *
 *****************************************************************************/
/*
 * Valid return codes used for functions performing work prior to or after
 * sending or receiving a message
 */
typedef enum {
    /* Something went wrong */
    WORK_ERROR,
    /* We're done working and there shouldn't be anything else to do after */
    WORK_FINISHED_STOP,
    /* We're done working move onto the next thing */
    WORK_FINISHED_CONTINUE,
    /* We're working on phase A */
    WORK_MORE_A,
    /* We're working on phase B */
    WORK_MORE_B,
    /* We're working on phase C */
    WORK_MORE_C
} WORK_STATE;

/* Write transition return codes */
typedef enum {
    /* Something went wrong */
    WRITE_TRAN_ERROR,
    /* A transition was successfully completed and we should continue */
    WRITE_TRAN_CONTINUE,
    /* There is no more write work to be done */
    WRITE_TRAN_FINISHED
} WRITE_TRAN;

/* Message flow states */
typedef enum {
    /* No handshake in progress */
    MSG_FLOW_UNINITED,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR,
    /* We are reading messages */
    MSG_FLOW_READING,
    /* We are writing messages */
    MSG_FLOW_WRITING,
    /* Handshake has finished */
    MSG_FLOW_FINISHED
} MSG_FLOW_STATE;

/* Read states */
typedef enum {
    READ_STATE_HEADER,
    READ_STATE_BODY,
    READ_STATE_POST_PROCESS
} READ_STATE;

/* Write states */
typedef enum {
    WRITE_STATE_TRANSITION,
    WRITE_STATE_PRE_WORK,
    WRITE_STATE_SEND,
    WRITE_STATE_POST_WORK
} WRITE_STATE;

typedef enum {
    /* The enc_write_ctx can be used normally */
    ENC_WRITE_STATE_VALID,
    /* The enc_write_ctx cannot be used */
    ENC_WRITE_STATE_INVALID,
    /* Write alerts in plaintext, but otherwise use the enc_write_ctx */
    ENC_WRITE_STATE_WRITE_PLAIN_ALERTS
} ENC_WRITE_STATES;

typedef enum {
    /* The enc_read_ctx can be used normally */
    ENC_READ_STATE_VALID,
    /* We may receive encrypted or plaintext alerts */
    ENC_READ_STATE_ALLOW_PLAIN_ALERTS
} ENC_READ_STATES;

/*****************************************************************************
 *                                                                           *
 * This structure should be considered "opaque" to anything outside of the   *
 * state machine. No non-state machine code should be accessing the members  *
 * of this structure.                                                        *
 *                                                                           *
 *****************************************************************************/

struct otls_statem_st {
    MSG_FLOW_STATE state;
    WRITE_STATE write_state;
    WORK_STATE write_state_work;
    READ_STATE read_state;
    WORK_STATE read_state_work;
    Otls_HANDSHAKE_STATE hand_state;
    /* The handshake state requested by an API call (e.g. HelloRequest) */
    Otls_HANDSHAKE_STATE request_state;
    int in_init;
    int read_state_first_init;
    /* true when we are actually in tls_accept() or tls_connect() */
    int in_handshake;
    /*
     * True when are processing a "real" handshake that needs cleaning up (not
     * just a HelloRequest or similar).
     */
    int cleanuphand;
    /* Should we skip the CertificateVerify message? */
    unsigned int no_cert_verify;
    int use_timer;
    ENC_WRITE_STATES enc_write_state;
    ENC_READ_STATES enc_read_state;
};
typedef struct otls_statem_st Otls_STATEM;

/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libtls internal API to the   *
 * state machine. Any libtls code may call these functions/macros            *
 *                                                                           *
 *****************************************************************************/

__owur int otls_statem_accept(tls *s);
__owur int otls_statem_connect(tls *s);
void otls_statem_clear(tls *s);
void otls_statem_set_renegotiate(tls *s);
void otls_statem_fatal(tls *s, int al, int func, int reason, const char *file,
                       int line);
# define tls_AD_NO_ALERT    -1
# ifndef OPENtls_NO_ERR
#  define tlsfatal(s, al, f, r)  otls_statem_fatal((s), (al), (0), (r), \
                                                   OPENtls_FILE, OPENtls_LINE)
# else
#  define tlsfatal(s, al, f, r)  otls_statem_fatal((s), (al), (0), (r), NULL, 0)
# endif

int otls_statem_in_error(const tls *s);
void otls_statem_set_in_init(tls *s, int init);
int otls_statem_get_in_handshake(tls *s);
void otls_statem_set_in_handshake(tls *s, int inhand);
__owur int otls_statem_skip_early_data(tls *s);
void otls_statem_check_finish_init(tls *s, int send);
void otls_statem_set_hello_verify_done(tls *s);
__owur int otls_statem_app_data_allowed(tls *s);
__owur int otls_statem_export_allowed(tls *s);
__owur int otls_statem_export_early_allowed(tls *s);

/* Flush the write BIO */
int statem_flush(tls *s);
