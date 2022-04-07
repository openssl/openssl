/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>

/*
 * We use the term "record" here to refer to a packet of data. Records are
 * typically protected via a cipher and MAC, or an AEAD cipher (although not
 * always). This usage of the term record is consistent with the TLS concept.
 * In QUIC the term "record" is not used but it is analogous to the QUIC term
 * "packet". The interface in this file applies to all protocols that protect
 * records/packets of data, i.e. (D)TLS and QUIC. The term record is used to
 * refer to both contexts.
 */


/*
 * Types of QUIC record layer;
 *
 * QUIC reuses the TLS handshake for agreeing secrets. An SSL object representing
 * a QUIC connection will have an additional SSL object internally representing
 * the TLS state of the QUIC handshake. This internal TLS is referred to as
 * QUIC-TLS in this file.
 * "Records" output from QUIC-TLS contains standard TLS handshake messages and
 * are *not* encrypted directly but are instead wrapped up in plaintext
 * CRYPTO frames. These CRYPTO frames could be collected together with other
 * QUIC frames into a single QUIC packet. The QUIC record layer will then
 * encrypt the whole packet.
 *
 * So we have:
 * QUIC-TLS record layer: outputs plaintext CRYPTO frames containing TLS
 *                        handshake messages only.
 * QUIC record layer: outputs encrypted packets which may contain CRYPTO frames
 *                    or any other type of QUIC frame.
 */

/*
 * An OSSL_RECORD_METHOD is a protcol specific method which provides the
 * functions for reading and writing records for that protocol. Which
 * OSSL_RECORD_METHOD to use for a given protocol is defined by the SSL_METHOD.
 */
typedef struct ossl_record_method_st OSSL_RECORD_METHOD;

/*
 * An OSSL_RECORD_LAYER is just an externally defined opaque pointer created by
 * the method
 */
typedef struct ossl_record_layer_st OSSL_RECORD_LAYER;


#define OSSL_RECORD_ROLE_CLIENT 0
#define OSSL_RECORD_ROLE_SERVER 1

#define OSSL_RECORD_DIRECTION_READ  0
#define OSSL_RECORD_DIRECTION_WRITE 1

/*
 * Protection level. For <= TLSv1.2 only "NONE" and "APPLICATION" are used.
 */
#define OSSL_RECORD_PROTECTION_LEVEL_NONE        0
#define OSSL_RECORD_PROTECTION_LEVEL_EARLY       1
#define OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE   2
#define OSSL_RECORD_PROTECTION_LEVEL_APPLICATION 3


/*
 * Template for creating a record. A record consists of the |type| of data it
 * will contain (e.g. alert, handshake, application data, etc) along with an
 * array of buffers in |bufs| of size |numbufs|. There is a corresponding array
 * of buffer lengths in |buflens|. Concatenating all of the buffer data together
 * would give you the complete plaintext payload to be sent in a single record.
 */
struct ossl_record_template_st {
    int type;
    void **bufs;
    size_t *buflens;
    size_t numbufs;
};

typedef struct ossl_record_template_st OSSL_RECORD_TEMPLATE;

/*
 * Rather than a "method" approach, we could make this fetchable - Should we?
 * There could be some complexity in finding suitable record layer implementations
 * e.g. we need to find one that matches the negotiated protocol, cipher,
 * extensions, etc. The selection_cb approach given above doesn't work so well
 * if unknown third party providers with OSSL_RECORD_METHOD implementations are
 * loaded.
 */

/*
 * If this becomes public API then we will need functions to create and
 * free an OSSL_RECORD_METHOD, as well as functions to get/set the various
 * function pointers....unless we make it fetchable.
 */
struct ossl_record_method_st {
    /*
     * Create a new OSSL_RECORD_LAYER object for handling the protocol version
     * set by |vers|. |role| is 0 for client and 1 for server. |direction|
     * indicates either read or write. |level| is the protection level as
     * described above. |settings| are mandatory settings that will cause the
     * new() call to fail if they are not understood (for example to require
     * Encrypt-Then-Mac support). |options| are optional settings that will not
     * cause the new() call to fail if they are not understood (for example
     * whether to use "read ahead" or not).
     *
     * The BIO in |transport| is the BIO for the underlying transport layer.
     * Where the direction is "read", then this BIO will only ever be used for
     * reading data. Where the direction is "write", then this BIO will only
     * every be used for writing data.
     *
     * An SSL object will always have at least 2 OSSL_RECORD_LAYER objects in
     * force at any one time (one for reading and one for writing). In some
     * protocols more than 2 might be used (e.g. in DTLS for retransmitting
     * messages from an earlier epoch).
     */

    /*
     * TODO: Will have to be something other than SSL_CIPHER if we make this
     * fetchable
     */
    OSSL_RECORD_LAYER *new(int vers, int role, int direction, int level,
                           unsigned char *secret, size_t secretlen,
                           SSL_CIPHER *c, BIO *transport, BIO_ADDR *local,
                           BIO_ADDR *peer, OSSL_PARAM *settings,
                           OSSL_PARAM *options);
    void free(OSSL_RECORD_LAYER *rl);

    int reset(OSSL_RECORD_LAYER *rl); /* Is this needed? */

    /* Returns 1 if we have unprocessed data buffered or 0 otherwise */
    int unprocessed_read_pending(OSSL_RECORD_LAYER *rl);
    /*
     * Returns 1 if we have processed data buffered that can be read or 0 otherwise
     * - not necessarily app data
     */
    int processed_read_pending(OSSL_RECORD_LAYER *rl);

    /*
     * The amount of processed app data that is internally bufferred and
     * available to read
     */
    size_t app_data_pending(OSSL_RECORD_LAYER *rl);

    int write_pending(OSSL_RECORD_LAYER *rl);


    /*
     * Find out the maximum amount of plaintext data that the record layer is
     * prepared to write in a single record. When calling write_records it is
     * the caller's responsibility to ensure that no record template exceeds
     * this maximum when calling write_records.
     */
    size_t get_max_record_len(OSSL_RECORD_LAYER *rl);

    /*
     * Find out the maximum number of records that the record layer is prepared
     * to process in a single call to write_records. It is the caller's
     * responsibility to ensure that no call to write_records exceeds this
     * number of records.
     */
    size_t get_max_records(OSSL_RECORD_LAYER *rl);

    /*
     * Write |numtempl| records from the array of record templates pointed to
     * by |templates|. Each record should be no longer than the value returned
     * by get_max_record_len(), and there should be no more records than the
     * value returned by get_max_records().
     * |allowance| is the maximum amount of "on-the-wire" data that is allowed
     * to be sent at the moment (including all QUIC headers, but excluding any
     * UDP/IP headers). After a successful or retry return |*sent| will
     * be updated with the amount of data that has been sent so far. In the case
     * of a retry this could be 0.
     * Where possible the caller will attempt to ensure that all records are the
     * same length, except the last record. This may not always be possible so
     * the record method implementation should not rely on this being the case.
     * In the event of a retry the caller should call retry_write_records()
     * to try again. No more calls to write_records() should be attempted until
     * retry_write_records() returns success.
     * Buffers allocated for the record templates can be freed immediately after
     * write_records() returns - even in the case a retry.
     * The record templates represent the plaintext payload. The encrypted
     * output is written to the |transport| BIO.
     * Returns:
     *  1 on success
     *  0 on retry
     * -1 on failure
     */
    int write_records(OSSL_RECORD_LAYER *rl, OSSL_RECORD_TEMPLATE **templates,
                      size_t numtempl, size_t allowance, size_t *sent);

    /*
     * Retry a previous call to write_records. The caller should continue to
     * call this until the function returns with success or failure. After
     * each retry more of the data may have been incrementally sent. |allowance|
     * is the amount of "on-the-wire" data that is allowed to be sent at the
     * moment. After a successful or retry return |*sent| will
     * be updated with the amount of data that has been sent by this call to
     * retry_write_records().
     * Returns:
     *  1 on success
     *  0 on retry
     * -1 on failure
     */
    int retry_write_records(OSSL_RECORD_LAYER *rl, size_t allowance,
                            size_t *sent);

    /*
     * Read a record and return the record layer version and record type in
     * the |rversion| and |type| parameters. |*data| is set to point to a
     * record layer buffer containing the record payload data and |*datalen|
     * is filled in with the length of that data. The |epoch| and |seq_num|
     * values are only used if DTLS has been negotiated. In that case they are
     * filled in with the epoch and sequence number from the record.
     * An opaque record layer handle for the record is returned in |*rechandle|
     * which is used in a subsequent call to |release_record|. The buffer must
     * remain available until release_record is called.
     *
     * Internally the the OSSL_RECORD_METHOD the implementation may read/process
     * multiple records in one go and buffer them.
     */
    int read_record(OSSL_RECORD_LAYER *rl, void **rechandle, int *rversion,
                    int *type, unsigned char **data, size_t *datalen,
                    uint16_t *epoch, unsigned char *seq_num);
    /*
     * Release a buffer associated with a record previously read with
     * read_record. Records are guaranteed to be released in the order that they
     * are read.
     */
    void release_record(OSSL_RECORD_LAYER *rl, void *rechandle);

};
