QUIC Proposed Final MVP API Design
==================================

This incorporates the result of the DDD design exploration process and
synthesizes the output of that process with the original QUIC API proposal. The
the below API has been designed to support the DDD demos with their diffs
without further changes, and thereby meet the agreed requirements for QUIC.

Response to OTC Questions
-------------------------

1. *Timer based events*

   This was the subject of extensive discussion in the documents accompanying
   the DDD demos; refer to these documents for details.

2. *TCP vs UDP socket creation*

   If the application is creating the socket they will need to change this.
   BIO_new_ssl_connect will be modified to automatically switch to SOCK_DGRAM
   when it is being used with a QUIC `SSL_CTX`.

3. *Blocking*

   This API supports both blocking and non-blocking use. This is demonstrated by
   the DDD diffs, so see the diffs and the discussion documents alongside them
   for examination of these issues.

4. *No visible event capability for existing apps*

   Covered by the API below.

5. *Configure protocol via a string*

   Not covered by MVP and therefore not specified below. We may provide a call
   similar to BIO_new_ssl_connect in future which can do it all (TLS, DTLS,
   QUIC), which will probably be the rough shape of it.

API
---

```c

/*
 * Method used for non-thread-assisted QUIC client operation.
 */
__owur const SSL_METHOD *QUIC_client_method(void);

/*
 * Method used for thread-assisted QUIC client operation.
 */
__owur const SSL_METHOD *QUIC_client_thread_method(void);

/*
 * Connection Establishment: General Case
 * ======================================
 *
 * After creating a SSL_CTX with one of the above methods, an SSL object is
 * created:
 *
 *   ssl = SSL_new(ctx);
 *
 * This is considered a QUIC connection object from the outset,
 * i.e. SSL_is_connection() returns 1 immediately. The connection
 * has not yet been made.
 *
 * SSL_set_connect_state(ssl); must be called. It is an error to call
 * SSL_set_accept_state(ssl); with one of the above methods.
 *
 * It is necessary that SSL_set_tlsext_host_name() is called as SNI is
 * mandatory. SSL_set1_host() should be called to allow certificate
 * verification. Later we might provide a single call to set both of these to be
 * set ala SSL_connect_ex these but this can wait.
 *
 * At this point:
 *
 *   If SSL_set_fd is called the SSL object, which represents a QUIC
 *   connection, we take it as a cue that it must use this FD.
 *
 *   If the FD has a destination (this can be tested via getpeername())
 *   this can be used as-is. We might always use sendto though and
 *   change the address we use later if connection migration occurs.
 *
 *   If the FD has no destination we need to determine a destination.
 *   We can either fail in this case or do a DNS lookup ourselves.
 *   We already have the infrastructure for this with BIO_lookup.
 *   In the BIO_new_ssl_connect case the lookup will already have been
 *   done by BIO_s_connect.
 *
 *   If SSL_set_bio is called the SSL object, which represents a QUIC
 *   connection, takes it as a cue that it must use this BIO, and that the BIO
 *   has datagram semantics. If the BIO supports sendto/recvfrom/etc. we might
 *   be able to support connection migration, otherwise it is e.g. a
 *   BIO_dgram_mem (e.g. DDD demo 05) which has not indicated that sendto
 *   addresses will be honoured and migration is disabled.
 *
 * SSL_connect(ssl) may be called or it may be implied by trying to
 * use SSL_read/SSL_write.
 *
 *
 * Connection Establishment: BIO_new_ssl_connect
 * =============================================
 *
 * BIO_new_ssl_connect will be changed to create a SOCK_DGRAM stream
 * when the SSL_CTX passed to it uses a QUIC method.
 *
 * At some point in the future (beyond the MVP) we can change
 * BIO_new_ssl_connect to use alternate methods to provide target addresses to
 * the QUIC connection object it creates, to the extent necessary to support
 * connection migration, etc. This abstracts these changes from codebases which
 * use BIO_new_ssl_connect.
 */

/*
 * Get the polling FD for the BIO. This might be different from the value
 * returned by BIO_get_fd and should be used by the application for polling. For
 * BIO_f_ssl it uses SSL_get_poll_fd; for anything else it will just forward to
 * BIO_get_fd.
 */
__owur int BIO_get_poll_fd(BIO *bio, int *fd); /* BIO_C_GET_POLL_FD */
__owur int SSL_get_poll_fd(SSL *ssl, int *fd);

/*
 * Returns the number of milliseconds from now to the earliest (possible) timer
 * event requiring ticking.
 *
 * Returns 0 if a timer event needs to be processed immediately.
 * Returns -1 if no callback is needed (infinity).
 */
__owur int BIO_get_next_tick(BIO *bio); /* BIO_C_GET_NEXT_TICK */
__owur int SSL_get_next_tick(SSL *ssl);

/*
 * Give libssl an opportunity to do things, for example due to timer events,
 * even when no specific read or write call is being performed.
 *
 * Note that:
 *   - For TLS this ss a no-op, as there are no timer events for TLS;
 *   - For DTLS this is equivalent to calling DTLSv1_handle_timeout();
 *   - For QUIC, only SSL objects representing a connection have timer events;
 *   - For QUIC SSL objects representing additional streams, this is a no-op.
 *
 * Returns 1 on success and 0 on failure.
 */
__owur int BIO_tick(BIO *bio); /* BIO_C_TICK */
__owur int SSL_tick(SSL *ssl);

/*
 * Get the SSL object representing the connection associated with this object.
 *
 * If the SSL object represents a non-QUIC method or a QUIC connection, this
 * returns the same object passed.
 *
 * If the SSL object represents a QUIC stream returns the QUIC connection
 * object.
 */
__owur SSL *SSL_get0_connection(SSL *ssl);

/*
 * Returns 1 if the object represents a connection. This always returns 1 for
 * non-QUIC methods, but returns 0 for SSL objects for QUIC streams which are
 * not also the QUIC connection object.
 *
 * This is exactly equivalent to (SSL_get0_connection(ssl) == ssl).
 */
__owur int SSL_is_connection(SSL *ssl);

/*
 * If the object represents a stream, returns a SSL_STREAM_TYPE value
 * designating whether the stream can be used for transmission, reception,
 * or both.
 *
 * This always returns SSL_STREAM_TYPE_BIDI for non-QUIC methods.
 *
 * It returns SSL_STREAM_TYPE_NONE for a QUIC connection object if it
 * does not have a default stream.
 */
#define SSL_STREAM_TYPE_NONE    0
#define SSL_STREAM_TYPE_READ    1
#define SSL_STREAM_TYPE_WRITE   2
#define SSL_STREAM_TYPE_BIDI    (SSL_STREAM_TYPE_READ | SSL_STREAM_TYPE_WRITE)
__owur int SSL_get_stream_type(SSL *ssl);

/*
 * QUIC: Returns the unique stream ID for the stream, an integer in range [0,
 * 2**62-1]. If called on a QUIC connection, returns the unique stream ID for
 * the default stream if there is one, and otherwise returns 0.
 *
 * TLS, DTLS: Returns 0.
 * TODO: Previously Matt proposed this just returns a monotonically incrementing
 *       counter for TLS/DTLS, but is there any reason to implement this?
 */
__owur uint64_t SSL_get_stream_id(SSL *ssl);

/*
 * Returns the SSL object's preference for a maximum UDP payload size.
 *
 * A client can use this to determine the size of the buffers they should use
 * for receiving datagrams to be pushed to the SSL object. This is only
 * necessary if the client is shunting its own buffers to libssl, and only if
 * support for larger than worst case MTUs is desired. The returned value should
 * be set as the MTU on the BIO_dgram to indicate to the SSL object that support
 * for larger MTUs is available.
 */
__owur ssize_t SSL_get_preferred_max_dgram_len(SSL *ssl);


/* ========================================================
 * BIO_dgram enhancements
 */

/* 
 * Create a BIO_dgram_mem pair. This functions like a BIO pair but
 * has datagram semantics.
 */
int BIO_new_dgram_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);

/*
 * A buffering BIO with datagram semantics.
 */
BIO_METHOD *BIO_f_dgram_buffer();

/*
 * A flag settable on BIO_dgram_mem. A BIO_read call will not truncate, but
 * instead fail if the frame is too large for the provided buffer. The
 * application must call BIO_ctrl_pending() to determine the necessary buffer
 * size and try again. Note that this changes the semantics of the BIO away from
 * the Berkeley sockets SOCK_DGRAM semantics and is therefore disabled by
 * default.
 */
__owur int BIO_dgram_set_no_trunc(BIO *bio, int enable);

/*
 * These allow an application which has pointed libssl to a BIO_dgram_mem to
 * indicate that it will support and honour specification of destination
 * addresses by writes from libssl to the TX side of the BIO, and will provide
 * source addresses in its calls to writes to the RX side of the BIO. (If these
 * are not set on a BIO_dgram_mem, connection migration will be unavailable.)
 */
#define BIO_DGRAM_CAP_DST_ADDR              (1U<<0)
#define BIO_DGRAM_CAP_SRC_ADDR              (1U<<1)
__owur int BIO_set_dgram_caps(BIO *bio, unsigned int caps); /* BIO_CTRL_DGRAM_SET_CAPS */
__owur int BIO_get_dgram_caps(BIO *bio, unsigned int *caps); /* BIO_CTRL_DGRAM_GET_CAPS */

/*
 * These set and get source and destination address metadata.
 *
 * BIO_get_dgram_rx_{src,dst}_addr retrieve metadata attached to the last
 * datagram which was returned by a call to a BIO read function, and should
 * therefore be called after a successful read to determine the destination
 * address (i.e., our local address) and source address (i.e., our peer address)
 * of the datagram we received. BIO_get_dgram_rx_dst_addr gets the datagram's
 * destination address and BIO_get_dgram_rx_src_addr gets the datagram's source
 * address.
 *
 * BIO_set_dgram_tx_{src,dst}_addr set metadata to be attached to the next
 * datagram to be sent by a call to a BIO write function. They should therefore
 * be called before a write to determine the destination address (i.e., the peer
 * address) and optionally the source address (i.e., the local address) of the
 * datagram to be sent. BIO_set_dgram_tx_dst_addr sets the datagram's destination
 * address.
 *
 * BIO_set_dgram_tx_src_addr sets the datagram's source address but probably
 * does not need to be available for MVP.
 *
 * It should be noted that the BIO_get_... functions here and the BIO_set_...
 * functions here are not inverses and access different state. The BIO_get_...
 * functions retrieve RX state and the BIO_set_... functions set TX state.
 * These are independent of one another.
 *
 * If write-multiple-datagram and read-multiple-datagram BIO APIs are used. the
 * source/destination information is passed in structures used by those APIs.
 * The state configured by these functions is then undefined.
 *
 * For a BIO_dgram_mem, these functions will fail if the necessary capability
 * flags have not been set using BIO_set_dgram_caps. These functions are always
 * available for a BIO_dgram.
 *
 * These functions are inspired by #5257 but differ, because they use separate
 * state for the RX and TX side. This enables RX and TX to be performed from
 * different threads if desired. They have been renamed to reflect this and be
 * less confusing. Alternately, the read/write-multiple APIs can be used which
 * avoid mutating state inside the BIO_dgram, allowing arbitrary multithreaded
 * use.
 */
__owur int BIO_get_dgram_rx_src_addr(BIO *bio, BIO_ADDR *addr); /* BIO_CTRL_GET_DGRAM_RX_SRC_ADDR */
__owur int BIO_get_dgram_rx_dst_addr(BIO *bio, BIO_ADDR *addr); /* BIO_CTRL_GET_DGRAM_RX_DST_ADDR */

__owur int BIO_set_dgram_tx_src_addr(BIO *bio, const BIO_ADDR *addr); /* (non-MVP) BIO_CTRL_SET_DGRAM_TX_SRC_ADDR */
__owur int BIO_set_dgram_tx_dst_addr(BIO *bio, const BIO_ADDR *addr); /* BIO_CTRL_SET_DGRAM_TX_DST_ADDR */

/*
 * Read/write multiple API.
 *
 * This is evolved from my initial proposal in #18210 as well as from Matt's
 * original QUIC proposal.
 *
 * This features:
 *   - An intentionally high level message structure which only supports
 *     the functionality we want to support and which we can support
 *     across a wide range of platforms.
 *
 *   - No iovec support, as this cannot be performantly supported on some
 *     platforms.
 *
 *   - Ability to get both source and destination addresses both for RX and TX.
 *
 *   - Limited extensibity via per-message and global flags arguments.
 *
 * The caller sets data to point to the data buffer, and peer and local to
 * point to BIO_ADDRs to be filled with the peer and local addresses.
 * If peer or local are NULL, this data is simply not returned.
 *
 * data_len is set to the data buffer length on call and has the
 * actual amount of data sent/received written to it afterwards,
 * assuming the message was touched at all, as determined by the return
 * value of the function:
 *
 * These functions return the number n of messages sent/received, which will
 * always be less than or equal to num_msg, or -1:
 *
 *   Postcondition: n <= num_msg
 *
 *   Postcondition: msg[i] for all 0 <= i < n have had their data_len
 *      modified to the actual amount of data sent or received.
 *
 * The flags field of each message defines per-message flags and is used for
 * both input and output. If a message is processed, this field is written
 * with any result flags ("message truncated", etc.)
 *
 * There are no per-message flags currently defined.
 *
 * The flags argument to these functions defines global flags.
 *
 * The defined global flags are:
 *   BIO_DONTWAIT
 *      Return immediately if no data is available.
 *   BIO_WAITFORONE
 *      Acts as though BIO_DONTWAIT was passed after one datagram has been
 *      received.
 *
 * These functions are made extensible via a 'stride' argument which is set to
 * sizeof(BIO_msg) by the caller. This allows us to add more fields later
 * without breaking ABI.
 *
 * The effect on the state controlled by BIO_get/set_dgram_rx/tx_src/dst_addr by
 * these functions is undefined. Do not use ordinary BIO read/write functions
 * concurrently with these functions.
 *
 * Multithreaded use of these functions is explicitly allowed, including
 * concurrent multiple writers and concurrent multiple readers.
 *
 * An implementation may place limits on the number of messages processed in a
 * single BIO_sendmmsg/BIO_recvmmsg call, in which case this simply means the
 * return value will never exceed that number. Callers then proceed normally by
 * sending the unprocessed messages in subsequent calls.
 */
typedef struct bio_msg_st {
    void           *data;
    size_t          data_len;
    BIO_ADDR       *peer, *local;
    unsigned int    flags;
} BIO_msg;

#define BIO_WAITFORONE      (1U<<0)
#define BIO_DONTWAIT        (1U<<1)

__owur ssize_t BIO_sendmmsg(BIO *bio, BIO_msg *msg,
                            size_t stride, size_t num_msg, unsigned int flags);
__owur ssize_t BIO_recvmmsg(BIO *bio, BIO_msg *msg,
                            size_t stride, size_t num_msg, unsigned int flags);

/* 
 * (There will of course be BIO_METH_get/set functions corresponding to all of
 * these, which are not shown here)
 */

```

Post-MVP Functionality
----------------------

```c
/* ========================================================
 * Alternate API to avoid copying. Not for MVP.
 */
int BIO_get_dgram(BIO *bio, void **buf, size_t *buf_len);
int BIO_return_dgram(BIO *bio, void *buf, size_t buf_len);
int BIO_put_dgram(BIO *bio, const void *buf, size_t buf_len,
                  void (*free_cb)(void *buf, size_t buf_len, void *arg),
                  void *arg);

/* ========================================================
 * API for multiple streams. Not for MVP.
 */

/*
 * Create a new SSL object representing a single additional stream.
 *
 * There is no need to call SSL_connect on the resulting object, and
 * any such call is a no-op.
 *
 * For QUIC:
 *   Creates a new stream. Can be used on client or server. If the SSL_FLAG_UNI
 *   flag is set, the created stream is unidirectional, otherwise it is
 *   bidirectional.
 *
 * For TLS and DTLS clients:
 *   Attempts a resumption handshake. The flags argument is ignored.
 *
 * For TLS and DTLS servers:
 *   Always fails.
 */
#define SSL_FLAG_UNI    1
SSL *SSL_new_stream(SSL *ssl, unsigned int flags);

/*
 * Create a new SSL object representing an additional stream which has created
 * by the peer.
 *
 * There is no need to call SSL_accept on the resulting object, and
 * any such call is a no-op.
 *
 * For QUIC:
 *   Checks if a new stream has been created by the peer. If it has, creates a
 *   new SSL object to represent it and returns it. Otherwise, returns NULL.
 *
 * For all other methods:
 *   Returns NULL.
 *
 * The flags argument is unused and should be set to zero.
 *
 * TODO: Do we want a WAIT flag for synchronous blocking here?
 */
SSL *SSL_accept_stream(SSL *ssl, unsigned int flags);

/*
 * Determine the number of streams waiting to be returned on a subsequent call
 * to SSL_accept_stream. If this returns a non-zero value, SSL_accept_stream is
 * guaranteed to work. Returns 0 for non-QUIC objects, or for QUIC stream
 * objects.
 *
 * Not strictly necessary but probably convenient.
 */
int SSL_get_accept_stream_queue_len(SSL *ssl);

/*
 * Set a SSL_STREAM_TYPE value which determines the type of the default stream.
 * The default value for QUIC methods is SSL_STREAM_TYPE_BIDI.
 *
 * This must be set before connecting. It is an error to try to set it to
 * anything other than SSL_STREAM_TYPE_BIDI for non-QUIC methods (or
 * we could just have this always fail on non-QUIC methods).
 *
 * If this is set to SSL_STREAM_TYPE_NONE, no default stream is created
 * at connection time and the initial connection object does not represent
 * a stream. Calls to SSL_read()/SSL_write() on this object fail. Streams
 * must be created using SSL_new_stream() or SSL_accept_stream().
 *
 * If the SSL_FLAG_NO_DEFAULT_STREAM flag is set, the initial SSL object is
 * associated with a connection but not a a stream. An initial stream must be
 * created using SSL_new_stream(). SSL_read()/SSL_write() on the connection
 * object will fail. This must be set before connecting.
 */
__owur int SSL_set_default_stream_type(SSL *ssl, int type);

/*
 * Detaches a default stream from a QUIC connection object. If the
 * QUIC connection object does not contain a default stream, returns NULL.
 * After calling this, calling SSL_get_stream_type on the connection object
 * returns SSL_STREAM_TYPE_NONE. Always returns NULL for non-QUIC connections.
 *
 * NOTE: This is not really necessary but I imagine some people might find it
 *       convenient.
 */
SSL *SSL_detach_stream(SSL *ssl);

/*
 * Attaches a default stream to a QUIC connection object. If the conn object is
 * not a QUIC connection object, or already has a default stream, this function
 * fails. The stream must belong to the same connection, or this function fails.
 *
 * NOTE: This is not really necessary but I imagine some people might find it
 *       convenient.
 */
__owur int SSL_attach_stream(SSL *conn, SSL *stream);

```
