/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "tls_local.h"

int tls3_do_change_cipher_spec(tls *s)
{
    int i;

    if (s->server)
        i = tls3_CHANGE_CIPHER_SERVER_READ;
    else
        i = tls3_CHANGE_CIPHER_CLIENT_READ;

    if (s->s3.tmp.key_block == NULL) {
        if (s->session == NULL || s->session->master_key_length == 0) {
            /* might happen if dtls1_read_bytes() calls this */
            tlserr(tls_F_tls3_DO_CHANGE_CIPHER_SPEC, tls_R_CCS_RECEIVED_EARLY);
            return 0;
        }

        s->session->cipher = s->s3.tmp.new_cipher;
        if (!s->method->tls3_enc->setup_key_block(s)) {
            /* tlsfatal() already called */
            return 0;
        }
    }

    if (!s->method->tls3_enc->change_cipher_state(s, i)) {
        /* tlsfatal() already called */
        return 0;
    }

    return 1;
}

int tls3_send_alert(tls *s, int level, int desc)
{
    /* Map tls/tls alert value to correct one */
    if (tls_TREAT_AS_TLS13(s))
        desc = tls13_alert_code(desc);
    else
        desc = s->method->tls3_enc->alert_value(desc);
    if (s->version == tls3_VERSION && desc == tls_AD_PROTOCOL_VERSION)
        desc = tls_AD_HANDSHAKE_FAILURE; /* tls 3.0 does not have
                                          * protocol_version alerts */
    if (desc < 0)
        return -1;
    /* If a fatal one, remove from cache */
    if ((level == tls3_AL_FATAL) && (s->session != NULL))
        tls_CTX_remove_session(s->session_ctx, s->session);

    s->s3.alert_dispatch = 1;
    s->s3.send_alert[0] = level;
    s->s3.send_alert[1] = desc;
    if (!RECORD_LAYER_write_pending(&s->rlayer)) {
        /* data still being written out? */
        return s->method->tls_dispatch_alert(s);
    }
    /*
     * else data is still being written out, we will get written some time in
     * the future
     */
    return -1;
}

int tls3_dispatch_alert(tls *s)
{
    int i, j;
    size_t alertlen;
    void (*cb) (const tls *tls, int type, int val) = NULL;
    size_t written;

    s->s3.alert_dispatch = 0;
    alertlen = 2;
    i = do_tls3_write(s, tls3_RT_ALERT, &s->s3.send_alert[0], &alertlen, 1, 0,
                      &written);
    if (i <= 0) {
        s->s3.alert_dispatch = 1;
    } else {
        /*
         * Alert sent to BIO - now flush. If the message does not get sent due
         * to non-blocking IO, we will not worry too much.
         */
        (void)BIO_flush(s->wbio);

        if (s->msg_callback)
            s->msg_callback(1, s->version, tls3_RT_ALERT, s->s3.send_alert,
                            2, s, s->msg_callback_arg);

        if (s->info_callback != NULL)
            cb = s->info_callback;
        else if (s->ctx->info_callback != NULL)
            cb = s->ctx->info_callback;

        if (cb != NULL) {
            j = (s->s3.send_alert[0] << 8) | s->s3.send_alert[1];
            cb(s, tls_CB_WRITE_ALERT, j);
        }
    }
    return i;
}
