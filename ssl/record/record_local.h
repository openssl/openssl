/*
 * Copyright 1995-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

/*****************************************************************************
 *                                                                           *
 * The following macros/functions are PRIVATE to the record layer. They      *
 * should NOT be used outside of the record layer.                           *
 *                                                                           *
 *****************************************************************************/

#define MAX_WARN_ALERT_COUNT    5

/* Functions/macros provided by the RECORD_LAYER component */

#define RECORD_LAYER_get_rrec(rl)               ((rl)->rrec)
#define RECORD_LAYER_set_packet(rl, p)          ((rl)->packet = (p))
#define RECORD_LAYER_reset_packet_length(rl)    ((rl)->packet_length = 0)
#define RECORD_LAYER_get_rstate(rl)             ((rl)->rstate)
#define RECORD_LAYER_set_rstate(rl, st)         ((rl)->rstate = (st))
#define RECORD_LAYER_get_read_sequence(rl)      ((rl)->read_sequence)
#define RECORD_LAYER_get_write_sequence(rl)     ((rl)->write_sequence)
#define RECORD_LAYER_get_numrpipes(rl)          ((rl)->numrpipes)
#define RECORD_LAYER_set_numrpipes(rl, n)       ((rl)->numrpipes = (n))
#define RECORD_LAYER_inc_empty_record_count(rl) ((rl)->empty_record_count++)
#define RECORD_LAYER_reset_empty_record_count(rl) \
                                                ((rl)->empty_record_count = 0)
#define RECORD_LAYER_get_empty_record_count(rl) ((rl)->empty_record_count)
#define RECORD_LAYER_is_first_record(rl)        ((rl)->is_first_record)
#define RECORD_LAYER_set_first_record(rl)       ((rl)->is_first_record = 1)
#define RECORD_LAYER_clear_first_record(rl)     ((rl)->is_first_record = 0)
#define DTLS_RECORD_LAYER_get_r_epoch(rl)       ((rl)->d->r_epoch)

__owur int tls3_read_n(tls *s, size_t n, size_t max, int extend, int clearold,
                       size_t *readbytes);

DTLS1_BITMAP *dtls1_get_bitmap(tls *s, tls3_RECORD *rr,
                               unsigned int *is_next_epoch);
int dtls1_process_buffered_records(tls *s);
int dtls1_retrieve_buffered_record(tls *s, record_pqueue *queue);
int dtls1_buffer_record(tls *s, record_pqueue *q, unsigned char *priority);
void tls3_record_sequence_update(unsigned char *seq);

/* Functions provided by the DTLS1_BITMAP component */

int dtls1_record_replay_check(tls *s, DTLS1_BITMAP *bitmap);
void dtls1_record_bitmap_update(tls *s, DTLS1_BITMAP *bitmap);

/* Macros/functions provided by the tls3_BUFFER component */

#define tls3_BUFFER_get_buf(b)              ((b)->buf)
#define tls3_BUFFER_set_buf(b, n)           ((b)->buf = (n))
#define tls3_BUFFER_get_len(b)              ((b)->len)
#define tls3_BUFFER_set_len(b, l)           ((b)->len = (l))
#define tls3_BUFFER_get_left(b)             ((b)->left)
#define tls3_BUFFER_set_left(b, l)          ((b)->left = (l))
#define tls3_BUFFER_sub_left(b, l)          ((b)->left -= (l))
#define tls3_BUFFER_get_offset(b)           ((b)->offset)
#define tls3_BUFFER_set_offset(b, o)        ((b)->offset = (o))
#define tls3_BUFFER_add_offset(b, o)        ((b)->offset += (o))
#define tls3_BUFFER_is_initialised(b)       ((b)->buf != NULL)
#define tls3_BUFFER_set_default_len(b, l)   ((b)->default_len = (l))

void tls3_BUFFER_clear(tls3_BUFFER *b);
void tls3_BUFFER_set_data(tls3_BUFFER *b, const unsigned char *d, size_t n);
void tls3_BUFFER_release(tls3_BUFFER *b);
__owur int tls3_setup_read_buffer(tls *s);
__owur int tls3_setup_write_buffer(tls *s, size_t numwpipes, size_t len);
int tls3_release_read_buffer(tls *s);
int tls3_release_write_buffer(tls *s);

/* Macros/functions provided by the tls3_RECORD component */

#define tls3_RECORD_get_type(r)                 ((r)->type)
#define tls3_RECORD_set_type(r, t)              ((r)->type = (t))
#define tls3_RECORD_set_rec_version(r, v)       ((r)->rec_version = (v))
#define tls3_RECORD_get_length(r)               ((r)->length)
#define tls3_RECORD_set_length(r, l)            ((r)->length = (l))
#define tls3_RECORD_add_length(r, l)            ((r)->length += (l))
#define tls3_RECORD_sub_length(r, l)            ((r)->length -= (l))
#define tls3_RECORD_get_data(r)                 ((r)->data)
#define tls3_RECORD_set_data(r, d)              ((r)->data = (d))
#define tls3_RECORD_get_input(r)                ((r)->input)
#define tls3_RECORD_set_input(r, i)             ((r)->input = (i))
#define tls3_RECORD_reset_input(r)              ((r)->input = (r)->data)
#define tls3_RECORD_reset_data(r)               ((r)->data = (r)->input)
#define tls3_RECORD_get_seq_num(r)              ((r)->seq_num)
#define tls3_RECORD_get_off(r)                  ((r)->off)
#define tls3_RECORD_set_off(r, o)               ((r)->off = (o))
#define tls3_RECORD_add_off(r, o)               ((r)->off += (o))
#define tls3_RECORD_get_epoch(r)                ((r)->epoch)
#define tls3_RECORD_is_tlsv2_record(r) \
            ((r)->rec_version == tls2_VERSION)
#define tls3_RECORD_is_read(r)                  ((r)->read)
#define tls3_RECORD_set_read(r)                 ((r)->read = 1)

void tls3_RECORD_clear(tls3_RECORD *r, size_t);
void tls3_RECORD_release(tls3_RECORD *r, size_t num_recs);
void tls3_RECORD_set_seq_num(tls3_RECORD *r, const unsigned char *seq_num);
int tls3_get_record(tls *s);
__owur int tls3_do_compress(tls *tls, tls3_RECORD *wr);
__owur int tls3_do_uncompress(tls *tls, tls3_RECORD *rr);
int tls3_cbc_copy_mac(unsigned char *out,
                       const tls3_RECORD *rec, size_t md_size);
__owur int tls3_cbc_remove_padding(tls3_RECORD *rec,
                                   size_t block_size, size_t mac_size);
__owur int tls1_cbc_remove_padding(const tls *s,
                                   tls3_RECORD *rec,
                                   size_t block_size, size_t mac_size);
int dtls1_process_record(tls *s, DTLS1_BITMAP *bitmap);
__owur int dtls1_get_record(tls *s);
int early_data_count_ok(tls *s, size_t length, size_t overhead, int send);
