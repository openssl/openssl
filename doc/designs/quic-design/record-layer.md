Design Problem: Abstract Record Layer
=====================================

This document covers the design of an abstract record layer for use in (D)TLS
and QUIC.

A record within this document refers to a packet of data. It will typically
contain some form of header data and some payload data, and will often be
cryptographically protected. A record may or may not have a one-to-one
correspondence with network packets, depending on the protocol and the
implementation details of an individual record layer.

The term record comes from the TLS and DTLS specifications. It is not used in
QUIC. A TLS record is roughly analagous to a QUIC packet. For the sake of
simplicity in this document we use the term record to refer to both concepts.

Libssl in OpenSSL 3.0 supports a number of different types of record layer,
and record layer variants:

- Standard TLS record layer
- Standard DTLS record layer
- Kernel TLS record layer

Within the TLS record layer there are options to handle "multiblock" and
"pipelining" which are different approaches for supporting the reading or
writing of multiple records at the same time.

These different record layer implementations and variants have each been added
at different times and over many years. The result is that each have taken
slightly different approaches for achieving the goals that were appropriate at
the time and the integration points where they have been added are spread
throughout the code.

The introduction of QUIC support will see the implementation of two more record
layers:
- QUIC record layer: A record here refers to a QUIC packet
- QUIC-TLS record layer: This refers to the "inner" TLS implementation used by
  QUIC. Records here will be QUIC CRYPTO frames.

Requirements
------------

The technical requirements
[document](https://github.com/openssl/openssl/blob/master/doc/designs/quic-design/quic-requirements.md)
lists these requirements that are relevant to the record layer:

* The current libssl record layer includes support for TLS, DTLS and KTLS. QUIC
  will introduce another variant and there may be more over time. The OMC
  requires a pluggable record layer interface to be implemented to enable this
  to be less intrusive, more maintainable, and to harmonize the existing record
  layer interactions between TLS, DTLS, KTLS and the planned QUIC protocols. The
  pluggable record layer interface will be internal only for MVP and be public
  in a future release.

* The minimum viable product (MVP) for the next release is a pluggable record
  layer interface and a single stream QUIC client in the form of s_client that
  does not require significant API changes. In the MVP, interoperability should
  be prioritized over strict standards compliance.

* Once we have a fully functional QUIC implementation (in a subsequent release),
  it should be possible for external libraries to be able to use the pluggable
  record layer interface and it should offer a stable ABI (via a provider).

* The internal architecture should allow for the fact that we may want to
  support "single copy" APIs in the future

The MVP requirements are:

* a pluggable record layer (not public for MVP)

Candidate Solution: Use a METHOD based approach
------------------------------------------------

A METHOD based approach is simply a structure containing function pointers. It
is a common pattern in the OpenSSL codebase. Different strategies for
implementing a METHOD can be employed, but these differences are hidden from
the caller of the METHOD.

In this solution we would seek to implement a different METHOD for each of the
types of record layer that we support, i.e. there would be one for the standard
TLS record layer, one for the standard DTLS record layer, one for kernel TLS,
one for QUIC and one for QUIC-TLS.

In the MVP the METHOD approach would be private. However, once it has
stabilised, it would be straight forward to supply public functions to enable
end user applications to construct their own METHODs.

This option is simpler to implement than the alternative of having a provider
based approach. However it could be used as a "stepping stone" for that, i.e.
the MVP could implement a METHOD based approach, and subsequent releases could
convert the METHODs into fully fetchable algorithms.

Pros:
* Simple approach that has been used historically in OpenSSL
* Could be used as the basis for the final public solution
* Could also be used as the basis for a fetchable solution in a subsequent
  release
* If this option is later converted to a fetchable solution then much of the
  effort involved in making the record layer fetchable can be deferred to a
  later release

Cons:
* Not consistent with the provider based approach we used for extensibility in
  3.0
* If this option is implemented and later converted to a fetchable solution then
  some rework might be required

Candidate Solution: Use a provider based approach
-------------------------------------------------

This approach is very similar to the alternative METHOD based approach. The
main difference is that the record layer implementations would be held in
providers and "fetched" in much the same way that cryptographic algorithms are
fetched in OpenSSL 3.0.

This approach is more consistent with the approach adopted for extensibility in
3.0. METHODS are being deprecated with providers being used extensively.

Complex objects (e.g. an `SSL` object) cannot be passed across the
libssl/provider boundary. This imposes some restrictions on the design of the
functions that can be implemented. Additionally implementing the infrastructure
for a new fetchable operation is more involved than a METHOD based approach.

Pros:
* Consistent with the extensibility solution used in 3.0
* If this option is implemented immediately in the MVP then it would avoid later
  rework if adopted in a subsequent release

Cons:
* More complicated to implement than the simple METHOD based approach
* Cannot pass complex objects across the provider boundary


Solution Outline: Use a METHOD based approach
---------------------------------------------

This section focuses on the "Use a METHOD based approach" candidate solution
above and further elaborates a design for how that approach might work.

A proposed internal record method API is given in [Appendix A](#appendix-a).

An `OSSL_RECORD_METHOD` represents the implementation of a particular type of
record layer. It contains a set of function pointers to represent the various
actions that can be performed by a record layer.

An `OSSL_RECORD_LAYER` object represents a specific instantiation of a
particular `OSSL_RECORD_METHOD`. It contains the state used by that
`OSSL_RECORD_METHOD` for a specific connection (i.e. `SSL` object). Any `SSL`
object will have at least 2 `OSSL_RECORD_LAYER` objects associated with it - one
for reading and one for writing. In some cases there may be more than 2 - for
example in DTLS it may be necessary to retransmit records from a previous epoch.
There will be different `OSSL_RECORD_LAYER` objects for different protection
levels or epochs. It may be that different `OSSL_RECORD_METHOD`s are used for
different protection levels. For example a connection might start using the
standard TLS record layer during the handshake, and later transition to using
the kernel TLS record layer once the handshake is complete.

A new `OSSL_RECORD_LAYER` is created by calling the `new` function of the
associated `OSSL_RECORD_METHOD`, and freed by calling the `free` function. The
internal structure details of an `OSSL_RECORD_LAYER` are entirely hidden to
libssl and will be specific to the given `OSSL_RECORD_METHOD`.

The payload for a record that will be written out to the network will be
assembled by libssl. That payload may be spread across multiple buffers. For
example a QUIC record (packet) may consist of multiple frames. There might be a
buffer containing the header data for the first frame, followed by a second
buffer containing the contents of the frame. A third buffer might contain the
header data for a second frame, and a fourth buffer might contain the payload
data for the second frame. There can be an arbitrary number of buffers which,
when concatenated together, form the total payload for the whole record. This
approach means that libssl can avoid having to copy all of the data from
multiple sources into a single buffer before calling the record layer.

All of the above data for a single record will be represented by an
`OSSL_RECORD_TEMPLATE` structure.

In order to assemble a record, libssl will need to know the maximum length of a
record that can be supported by the `OSSL_RECORD_LAYER`. In order to support
this an `OSSL_RECORD_METHOD` will supply a `get_max_record_len()` function to
query this value. It will be libssl's responsibility to ensure that no record
exceeds the maximum supported record length.

An `OSSL_RECORD_METHOD` supplies a `write_records` function which libssl can
call to write one or more records. Libssl will supply an array of
`OSSL_RECORD_TEMPLATE` objects along with the number of such templates. This
number is guaranteed to never be greater than the maximum number of records
that the record layer can handle at one time as returned by the
`get_max_records()` function.

The implementation of the `write_records` function must construct the
appropriate number of records, apply protection to them as required and then
write them out to the underlying transport layer BIO. Congestion or flow control
limits may apply. The maximum amount of data that may be sent at the current
time is supplied by libssl in the `allowance` parameter. It is the
`OSSL_RECORD_METHOD`'s responsibily to ensure that no more bytes than
`allowance` are transmitted via the transport layer BIO. In the event that not
all the data can be transmitted at the current time (either because of the
`allowance` limit, or because the underlying transport has indicated a retry),
then the `write_records` function will return a "retry" response. It is
permissible for the data to be partially sent, but this is still considered a
"retry" until all of the data is sent. The `sent` parameter will be filled in
with the number of bytes sent during this `write_records` call in both a
success and a retry response.

On a success or retry response libssl may free its buffers immediately. The
`OSSL_RECORD_LAYER` object will have to buffer any untransmitted data until it
is eventually sent. The move of data from the input buffers to the internal
`OSSL_RECORD_METHOD` buffer should occur during packet protection and is the
"single copy" allowed by the requirements.

If a "retry" occurs, then libssl will subsequently call `retry_write_records`
and continue to do so until a success return value is received. Libssl will
never call `write_records` a second time until a previous call to
`write_records` or `retry_write_records` has indicated success.

Libssl will read records by calling the `read_record` function. The
`OSSL_RECORD_LAYER` may read multiple records in one go and buffer them, but the
`read_record` function only ever returns one record at a time. The
`OSSL_RECORD_LAYER` object owns the buffers for the record that has been read
and supplies a pointer into that buffer back to libssl for the payload data, as
well as other information about the record such as its length and the type of
data contained in it. Each record has an associated opaque handle `rechandle`.
The record data must remain buffered by the `OSSL_RECORD_LAYER` until it has
been released via a call to `release_record()`.


<a id='appendix-a'></a>Appendix A: An internal record method API
----------------------------------------------------------------
A proposed internal recordmethod.h header file for the record method API:

```` C
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
````
