# Design Problem: QUIC API

There are a number of possibilities for how the long term QUIC API could be
structured.

The MVP will be written to allow current applications to use QUIC as a single
stream at “a flip of a switch”.  Just enough of the chosen longer term
design option is expected to be implemented _internally_ to support what the
MVP needs (i.e. not necessarily published as a public API).


## Candidate Solution: Just use the existing SSL API

In this solution we just use the existing SSL API (e.g. with a
“QUIC_client_method” and a “QUIC_server_method”) and extend it where
necessary to support QUIC specific functionality. Existing functions (such as
SSL_read or SSL_write) can be repurposed to work as you might expect (with a
default stream) for QUIC.

The existing SSL API does not separate the concepts of “connection” and
“stream”. However in QUIC there can be multiple streams associated with a
single connection. Therefore we would have to solve the problem of how to
represent this.  There are several possibilities:

* The `SSL` type represents a connection. We would need a new type for a stream
* The `SSL` type represents a stream.  We would need a new type for a
connection.
* The `SSL` type represents a connection, and it has functions to target the
desired stream, e.g.: \
`SSL_read_stream(ssl, 4, buf, sizeof(buf));`
* The `SSL` type represents both a connection and stream (in separate
instances).  Stream objects can be created from a connection object as
required, e.g.: \
`SSL *SSL_create_stream(SSL *ssl, int stream_number, int type);`

Pros

* Re-use all of the existing APIs
* Easier to convert existing applications to QUIC
* The API is already understood by application authors - they don’t need to
learn something new

Cons

* SSL objects are not currently thread safe. It’s not clear how the above
model would work in the case where multiple streams associated with a single
connection are being read from/written to in different threads
* SSL objects have lots of APIs that are very specific to TLS and would not fit
well with QUIC
* We would have to “pollute” the SSL API with lots of QUIC specific
functions
* The “SSL” type name doesn’t fit well with QUIC


## Candidate Solution: A generic comms API with SSL compat layer

In this approach we would develop a completely new generic secure
communications API that would support multiple protocol types, e.g. TLS, DLTS,
QUIC, etc. We might expect to see separate types for generic “connections”
and “streams”. Internally to a generic connection we would see protocol
specific objects. We could choose to expose these internal protocol specific
objects as part of the API, or we could expose them through generic mechanisms
(e.g. ctrls, OSSL_PARAM etc).

Some features can be simulated in protocols that don’t have them. For example
TLS doesn’t have a multi-stream capability - but it could be simulated by
running resumption handshakes to create a new “stream”.

Additionally an “SSL” compatibility layer would be developed. There could
be QUIC method objects (e.g. “QUIC_client_method'' or
“QUIC_server_method”). The compatibility layer:

1. Will call the generic API underneath, e.g. Common functions such as
“SSL_read” and “SSL_write” would be redirected internally  to the
equivalent generic connection/stream function as appropriate.
2. For MVP it will only support 1 stream
3. Should be possible (eventually) to move from the SSL API to the generic API
e.g.

    ```
    OSSL_CONN *SSL_get_connection(SSL *ssl);

    ```


The new generic API could be internal only for MVP. We might expect it to have
a context object type, a connection object type, a stream object type, etc.
Since it is not TLS, DTLS or QUIC specific, we would expect a different prefix.

Inevitably there will have to be mechanisms for making available protocol
specific functionality as part of the generic API. An open question is how this
would be done, e.g.

* Exposing a protocol specific object
* OSSL_PARAMs
* Some other params style approach but with ability for complex objects (e.g.
X509)

A possible data model for this approach can be seen here ([whiteboard
link](https://jamboard.google.com/d/1AM1g-9eUbGAJ3YR9cEVpH6mrpPHCxd-9DtJMG1hNPlk/edit?usp=meet_whiteboard)):


![alt_text](images/image1.png "image_tooltip")


Pros

* All protocols look the same to an application. Straight forward to switch
from one protocol to another

Cons

* Protocol differences will pollute the API
* Inevitably there will be some features that will work differently (or won’t
be present at all) between different protocols. Therefore applications swapping
from one protocol to another may still have to have some protocol specific code


## Candidate Solution: A completely new QUIC API with SSL compat layer

This solution is similar to the previous solution except that we do not attempt
to create a generic comms API and instead just implement a QUIC specific API.
Applications wanting to do TLS would still use the existing “SSL” API, and
applications wanting to do QUIC would use the new API.

Additionally we would also implement an SSL “compatibility” layer that
would convert SSL function calls to equivalent QUIC function as appropriate.
The compatibility layer:

1. Will call the QUIC API underneath, e.g. Common functions such as
“SSL_read” and “SSL_write” would be redirected internally to the
equivalent QUIC connection/stream function as appropriate.
2. For MVP it will only support 1 stream
3. Should be possible (eventually) to move from the SSL API to the QUIC API e.g.

    ```
    OSSL_QUIC_CONN *SSL_get_connection(SSL *ssl);

    ```

The new QUIC API could be internal only for MVP. We might expect it to have a
context object type, a connection object type, a stream object type, etc.

Pros

* Simpler solution - we don’t have to fit into some bigger “generic”
protocol concept

Cons

* Full QUIC will look very different to SSL
* Writing a QUIC application is completely different to writing a TLS
application - no easy path from one to the other


# Solution Outline: Use the existing SSL API

This section focuses on the "Just use the existing SSL API" candidate solution
above and further elaborates a design for how that approach might work.

The proposed additions to the ssl.h and bio.h header files for this approach
are given in [Appendix A](#appendix-a).

A key problem to solve with this design approach is how will QUIC events be
delivered to an application? In a (D)TLS application there is a one-to-one
correspondence between a socket and an `SSL` object. So an application can test
for a socket becoming readable/writeable and then call `SSL_read()`/`SSL_write()`
or some other `SSL` function in response. For servers it can also "accept" new
connections on a socket to learn about new connection events.

With QUIC there will be a single socket that is shared between multiple `SSL`
objects (or possibly a set of sockets that are shared). A socket becoming
readable/writeable can no longer be associated with a single `SSL` object. New
connections are just new packets arriving on the socket(s) just like any other.
There will need to be a mechanism to deliver events to an application that are
associated with an individual `SSL` object in order for the standard `SSL_read()`/
`SSL_write(`) functions, or some other IO function to be called.

To solve this problem this design introduces a new `SSL_EVENT_CTX` object. An
individual `SSL` object represents an individual stream. A set of `SSL` objects
together represent all of the streams available for a given connection. The
first `SSL` object created for a connection represents the connection itelf as
well as the first stream if there is one. All the `SSL` objects from all
connections associated with a shared set of sockets are all grouped together by
a single `SSL_EVENT_CTX`.

While the principal motivation for introducing `SSL_EVENT_CTX` is to support QUIC,
it may also be useful for supporting (D)TLS applications. Using an `SSL_EVENT_CTX`
will be required for QUIC applications, but using one should (if desired by the
application developer) also be possible for (D)TLS applications. It should also
be possible to write (D)TLS applications in the traditional way.

OpenSSL (D)TLS applications abstract away the details of the underlying
transport protocol using `BIO`s. Application developers can either use one of the
set of standard `BIO`s, or alternatively develop their own custom `BIO`s in order
to have more control over the interaction with the underlying transport
protocol. This approach needs to be possible with QUIC too. However for QUIC it
will no longer be the case that each `SSL` object needs different `BIO` objects.
Instead there will be common `BIO`s that are shared between multiple `SSL` objects.
These shared `BIO`s can be set on the `SSL_EVENT_CTX`.

Applications can call `SSL_EVENT_CTX_get_next_event()` to get the next event from
the event queue. Examples of events might be "new connection", "new stream",
"stream readable", "stream close", etc. Time based events can also be delivered.
Optionally events can be filtered for only a given `SSL` object. If the event
queue is empty then a new packet will be read from the underlying `BIO`s (if
possible) and any resulting events are added to the event queue.

Also associated with the `SSL_EVENT_CTX` is a new connection queue and a new
stream queue. In the case that a "new connection" event is received then the
application would need to create a new SSL object and then call `SSL_accept()` on
it. The `SSL` object will have inherited the `SSL_EVENT_CTX` to use from the
`SSL_CTX` and will inspect the new connection queue and automatically configure
the `SSL` object for the new incoming connection.

An application can (optionally) insert new connections into the connection
queue directly by calling `SSL_EVENT_CTX_add_new_connection()`. This would also
result in a "new connection" event being issued. This would not be necessary for
QUIC applications because new connections would be automatically added to the
queue. However it might be useful for (D)TLS applications where only the
application knows when a new connection has arrived, i.e. OpenSSL cannot detect
this automatically.

New connections are initiated via the `SSL_connect()` function call. For QUIC it
is preferred to use the new `SSL_connect_ex()` function instead which can
additionally specify the destination hostname and its address. The address is
required if the underlying socket is "unconnected".

New streams can be initiated by calling `SSL_new_stream()` and passing an
existing `SSL` object for some other stream from the same connection. Subsequently,
`SSL_connect()` will need to be called on the new `SSL` object. This could be made
to work for (D)TLS client applications which could automatically configure the
SSL object to try a resumption handshake. On the server side this would always
fail for (D)TLS applications.

New streams can also be initiated by the peer in which case a "new stream"
event would be issued by the `SSL_EVENT_CTX`. In that case details of the
incoming stream would be added to the new stream queue inside the `SSL_EVENT_CTX`.
The application would "accept" the incoming stream by calling
`SSL_accept_stream()`. This would only occur for QUIC applications - never for
(D)TLS applications.

A QUIC based application will need to handle various time based events. These
can be delivered as "tick" events from the `SSL_EVENT_CTX`. Alternatively, an
application can call `SSL_get_next_tick()` to get the next timeout event for a
given `SSL` object. For a DTLS application this is exactly equivalent to calling
`DTLSv1_get_timeout()`. Calling `SSL_tick()` on an `SSL` object will enable it
to process any outstanding time based events. For a DTLS application this is
exactly equivalent to calling `DTLSv1_handle_timeout()`. In a QUIC application
only the `SSL` object for the connection would ever have time based events. For
a TLS application there would never be time based events (so calling
`SSL_tick()` will have no effect).

## Changes to the BIO API

In order to support QUIC the current `BIO` API will need to be extended. The
existing "dgram" `BIO` can be used for UDP. However this only has very limited
support for sockets operating in an "unconnected" state. Currently, sending a
UDP packet from a dgram `BIO` using an unconnected socket requires the caller to
first use `BIO_ctrl()` to set the destination address and then call `BIO_write()`
to actually send the packet. A similar process is required for obtaining the peer
address from a received packet. This multi-call approach is unlikely to scale
well in a multi threaded application.

A further problem is the existing API provides no mechanism for sending or
receiving multiple messages at the same time. Operating systems provide various
mechanisms for optimising sending/receiving data if this can be achieved. Note
that OpenSSL does not need to implement support for this in its own `BIO`s in its
initial releases - but adding support for it in the API enables others to do so,
and enables it to be added easily to OpenSSL's own `BIO`s at any point.

The existing API also provides no support for setting/obtaining the local
address for a message to be sent/received. This may be useful in the case where
a socket is bound to multiple address using `INADDR_ANY` or `IN6ADDR_ANY`.

To solve all of the above issues two new functions are proposed: `BIO_sendmmsg()`
and `BIO_recvmmsg()`. There will also be associated `BIO_METHOD` functions to set
implementations for these. Support can be added to fall back to the existing
sending/receiving approach in the event that a `BIO` does not support the new
`BIO_METHOD` functions.

A demonstration client using the new SSL API functions has been provided in
[Appendix B](#appendix-b).

# <a id='appendix-a'></a>Appendix A: SSL API ssl.h and bio.h additions

Proposed additions to the ssl.h header file are as follows:


````
/* Methods representing the QUIC protocol */
__owur const SSL_METHOD *QUIC_method(void);
__owur const SSL_METHOD *QUIC_server_method(void);
__owur const SSL_METHOD *QUIC_client_method(void);

/*
 * An SSL object represents a single stream. The "first" SSL object for a
 * connection additionally represents that connection. In QUIC multiple SSL
 * objects (streams) can be associated with the same connection id. In (D)TLS
 * this would just generate a unique number for each SSL object.
 */
uint64_t SSL_get_conn_id(SSL *ssl);

/* Object to represent various events that might occur */
typedef struct ssl_event_st SSL_EVENT;

/*
 * Object to manage a collection of event sources. SSL_EVENT_CTX objects are
 * ref counted.
 */
typedef struct ssl_event_ctx_st SSL_EVENT_CTX;

/* Set the SSL_EVENT_CTX inherited by SSL objects created from this SSL_CTX */
int SSL_CTX_set1_SSL_EVENT_CTX(SSL_CTX *ctx, SSL_EVENT_CTX *ectx);

/*
 * Override the SSL_EVENT_CTX to use for an inidivudal SSL object. Calling
 * SSL_set_bio(), SSL_set0_rbio() or SSL_set0_wbio() on an SSL object will
 * replace any existing SSL_EVENT_CTX with a new one containing those BIOs.
 * The SSL_CTX used to create the SSL object and SSL_EVENT_CTX object must use
 * the same SSL_METHOD.
 */
int SSL_set1_SSL_EVENT_CTX(SSL *ssl, SSL_EVENT_CTX *ectx);

/*
 * With this option set a single SSL_EVENT_CTX object can be safely shared and
 * used between multiple threads.
 */
# define SSL_EVENT_CTX_NEW_OPTION_THREAD_SAFE       0x01

/* Types of events that can occur within an SSL_EVENT_CTX */
# define SSL_EVENT_TYPE_ERROR            0x01
# define SSL_EVENT_TYPE_NEW_CONNECTION   0x02
# define SSL_EVENT_TYPE_NEW_STREAM       0x04
# define SSL_EVENT_TYPE_CONNECTION_CLOSE 0x08
# define SSL_EVENT_TYPE_STREAM_CLOSE     0x10
# define SSL_EVENT_TYPE_STREAM_READABLE  0x20
# define SSL_EVENT_TYPE_STREAM_WRITEABLE 0x40
/* Indicates that a time based event has occurred */
# define SSL_EVENT_TYPE_TICK             0x80

# define SSL_EVENT_TYPE_ALL_EVENTS      (SSL_EVENT_TYPE_NEW_CONNECTION \
                                        | SSL_EVENT_TYPE_NEW_STREAM \
                                        | SSL_EVENT_TYPE_CONNECTION_CLOSE \
                                        | SSL_EVENT_TYPE_STREAM_CLOSE \
                                        | SSL_EVENT_TYPE_STREAM_READABLE \
                                        | SSL_EVENT_TYPE_STREAM_WRITEABLE \
                                        | SSL_EVENT_TYPE_TICK)

/*
 * Create a new SSL_EVENT_CTX object for the protocol SSL_METHOD as defined on
 * the SSL_CTX. evmask is a bitwise OR of all the events that should be reported
 * for this SSL_EVENT_CTX. Use of an SSL_EVENT_CTX will be optional for (D)TLS
 * but required for QUIC (since there is no way of receiving some of the events
 * otherwise).
 */
SSL_EVENT_CTX *SSL_EVENT_CTX_new(SSL_CTX *ctx, uint64_t evmask, uint64_t options);

int SSL_EVENT_CTX_up_ref(SSL_EVENT_CTX *ectx);
void SSL_EVENT_CTX_free(SSL_EVENT_CTX *ectx);

/*
 * Add new default rbio's and wbio's to be used by all consumers of this
 * SSL_EVENT_CTX. Does not need to be called for TLS. Required for DTLS if using
 * an SSL_EVENT_CTX. Always required for QUIC.
 */
int SSL_EVENT_CTX_add0_rbio(SSL_EVENT_CTX *ectx, BIO *rbio);
int SSL_EVENT_CTX_add0_wbio(SSL_EVENT_CTX *ectx, BIO *wbio);

/*
 * Process any time based actions that need to occur for the SSL object. For
 * DTLS this is equivalent to calling DTLSv1_handle_timeout(). For TLS this does
 * nothing (there are no time-based events for TLS). For QUIC only the inital
 * connection ojbect ever has time based events.
 */
int SSL_tick(SSL *s);

/*
 * Populates nexttick with the time until the next time based action that
 * requires a call to SSL_tick(). For DTLS, this is equivalent to calling
 * DTLSv1_get_timeout(). For TLS this will always return 0 (no next timeout).
 * For QUIC this will only return 1 (timeout available) for the connection
 * object.
 */
int SSL_get_next_tick(SSL *s, struct timeval *nexttick);

/*
 * Returns 1 if the SSL object represents the connection or 0 otherwise. For
 * (D)TLS all SSL objects represent a connection and so this always returns 1.
 * For QUIC only the first SSL object created for a connection represents the
 * connection (it may also represent the first stream). Subsequent SSL objects
 * created for that connection only represent streams.
 */
int SSL_is_connection(SSL *s);

/*
 * If the event queue is not empty then this returns immediately and fills in
 * ev with details of the next event. If the event queue is empty then it will
 * attempt to read a packet from the BIO associated with the given SSL object,
 * or if there is no associated BIO, or if the SSL object is NULL, then it will
 * attempt to read a packet from the rbios associated with the SSL_EVENT_CTX and
 * will then populate the event queue accordingly and fill ev with the first
 * event. For DTLS this could fulfil the role of DTLSv1_listen() and create a
 * "new connection" event only when the cookie has been verified.
 * If after the above the event queue is still empty and SSL_EVENT_TYPE_TICK is
 * not masked out then it will populate the event queue with any expired timer
 * events for s if it is non NULL, or any SSL objects otherwise.
 * If shouldblock is 1 and no events are available this function call will block
 * until an event is available, or the timeout value has expired. If shouldblock
 * is 1 and timeout is NULL then the function will block indefinitely until an
 * event is available. If shouldblock is 0 then then function will always return
 * immediately.
 */
int SSL_EVENT_CTX_get_next_event(SSL_EVENT_CTX *ectx, SSL *s,
                                 int shouldblock, struct tm *timeout,
                                 SSL_EVENT *ev);

/*
 * Add a pending new connection to the new connection queue in the SSL_EVENT_CTX.
 * This will result in an SSL_EVENT_TYPE_NEW_CONNECTION event being issued. A
 * subsequent call to SSL_accept will accept the connection and configure the
 * SSL object for it. Applications should only need to do this for TLS because we
 * don't otherwise know about the arrival of a new connection. Even for TLS this
 * is optional (new connections can just be handled as they are now without the
 * use of SSL_EVENT_CTX if desired). For QUIC and DTLS these new connections
 * can be detected automatically when SSL_EVENT_CTX_get_next_event() processes a
 * packet.
 */
int SSL_EVENT_CTX_add_new_connection(SSL_EVENT_CTX *ectx, BIO *rbio, BIO *wbio);

/*
 * Construct and free a new SSL_EVENT object
 */
SSL_EVENT *SSL_EVENT_new(void);
void SSL_EVENT_free(SSL_EVENT *ev);


/* Gives an integer value representing the type of event that occurred */
uint64_t SSL_EVENT_get_event_type(SSL_EVENT *event);

/*
 * Gets the stream associated with a given event. In the case of "new connection"
 * this will be NULL. In case the of "new stream" or "connection close" it will
 * be the "connection" object (i.e. first SSL object for the connection)
 */
SSL *SSL_EVENT_get_SSL(SSL_EVENT *event);

/*
 * Returns the error code associated with the event - for events that have an
 * associated error code.
 */
uint64_t SSL_EVENT_get_error_code(SSL_EVENT *event);

/*
 * Returns the reason phrase associated with an event if there is one or NULL
 * otherwise. Only relevant for SSL_EVENT_TYPE_CONNECTION_CLOSE.
 */
char *SSL_EVENT_get_reason(SSL_EVENT *event);

/*
 * Works as normal if the SSL object has already had its BIOs configured.
 * Otherwise it will check the new connection queue in the SSL_EVENT_CTX. If it
 * finds a pending new connection then it will "accept" it, adding the BIOs and
 * running the handshake. In the case of QUIC this will set up the SSL object as
 * the connection object (with an associated stream if applicable). Will return
 * SSL_ERROR_WANT_READ in the event that no new conneciton is pending.
 */
__owur int SSL_accept(SSL *ssl);

/*
 * Works as normal for (D)TLS. For QUIC it may be used for connecting new
 * streams created via `SSL_new_stream()`. For initial connections it may be
 * used but it is preferrable to use SSL_connect_ex() instead.
 */
__owur int SSL_connect(SSL *ssl);

/*
 * Works as for SSL_connect() except additionally specifying a hostname and
 * destination address. The (D)TLS and QUIC the hostname sets the hostname that
 * will be sent in the SNI extension, as well as the hostname used for server
 * certificate verification. The addr argument specifies for the destination
 * address to connect to. This will be ignored for (D)TLS. For QUIC it is
 * mandatory.
 * For QUIC an SSL object will typically use the BIOs as set on the
 * SSL_EVENT_CTX rather than having its own BIOs.
 */
__owur int SSL_connect_ex(SSL *ssl, const char *hostname, const BIO_ADDR *addr);

/*
 * In the case of a (D)TLS client attempts a resumption handshake. Will always
 * fail for a (D)TLS server (returns NULL). For QUIC it creates a new stream
 * (works on either client or server).
 * bidi - indicates whether the stream is bidirectional or write only. Selecting
 *        write only is an error for (D)TLS
 */
SSL *SSL_new_stream(SSL *ssl, int bidi);

/*
 * Not supported for (D)TLS - will always return NULL. For QUIC it will check
 * if a "new stream" event has occurred for the connection. If it has then a
 * new SSL object is created to represent it and returned.
 */
SSL *SSL_accept_stream(SSL *ssl);

````

Proposed additions to the bio.h header file are as follows:

````
/*
 * Send *nummsg messages (must be >0) from the local addresses to the peer
 * addresses via the BIO b. local is an array of *nummsg local addresses to
 * specify the local address each of the messages should be sent from. If local
 * is NULL or an individual message local address is NULL then the default local
 * address for the socket is used. Setting an explicit local address can be
 * useful if the socket is bound with INADDR_ANY or IN6ADDR_ANY (i.e. multiple
 * IP addresses are bound to the same socket). peer is an arry of *mummsg peer
 * addresses to specify the peer address each of the messages should be sent to.
 * If peer is NULL or an indivual message peer address is NULL then the BIO must
 * be in a "connected" state. data is an array of *nummsg pointers. Each pointer
 * is for the data for each individual message. Similarly dlen is array of
 * *numsg lengths corresponding to each of the individual messages. After a
 * successful call to this function *nummsg is updated with the number of
 * messages that were successfully sent (which may be less than the total
 * requested). It is thread-safe to call this function, or BIO_recvmmsg at the
 * same time in multiple threads for the same BIO. It is not thread-safe to call
 * this function at the same time as any other BIO function for the same BIO.
 */
int BIO_sendmmsg(BIO *b, const void **data, const size_t *dlen, size_t *nummsg,
                 BIO_ADDR **peer, BIO_ADDR **local);

/*
 * Receive up to *nummsg messages from the BIO b. *nummsg will be updated after
 * a sucessful call with the number of messages actually received. data is an
 * array of *nummsg pointers to buffers for the data to be received from each
 * individual message. Similarly dlen is an array *nummsg lengths of those
 * buffers. After a successful call the dlen array is updated with the actual
 * lengths of the received messages. If peer is non-NULL then it is an array
 * of *nummsg BIO_ADDR objects that will be updated after a successful call with
 * the address of the peer for the received messages. local works in the same
 * way for the local addresses that each of the messages was sent to (useful in
 * the case of INADDR_ANY or IN6ADDR_ANY to determine which of the multiple
 * addresses the socket is bound to the peer actually used). It is thread-safe
 * to call this function, or BIO_sendmmsg at the same time in multiple threads
 * for the same BIO. It is not thread-safe to call this function at the same
 * time as any other BIO function for the same BIO.
 */
int BIO_recvmmsg(BIO *b, void **data, size_t *dlen, size_t *nummsg,
                 BIO_ADDR **peer, BIO_ADDR **local);

/* Get and set BIO method implementations for BIO_sendmmsg() and BIO_recvmmmsg */
int (*BIO_meth_get_sendmmsg(const BIO_METHOD *biom)) (BIO *, void **, size_t *,
                                                      size_t *, BIO_ADDR **,
                                                      BIO_ADDR **);
int BIO_meth_set_sendmmsg(BIO_METHOD *biom,
                          int (*sendmmsg) (BIO *, void **, size_t *, size_t *,
                                           BIO_ADDR **, BIO_ADDR **));
int (*BIO_meth_get_recvmmsg(const BIO_METHOD *biom)) (BIO *, void **, size_t *,
                                                      size_t *, BIO_ADDR **,
                                                      BIO_ADDR **);
int BIO_meth_set_recvmmsg(BIO_METHOD *biom,
                          int (*recvmmsg) (BIO *, void **, size_t *, size_t *,
                                           BIO_ADDR **, BIO_ADDR **));
````

# <a id='appendix-b'></a>Appendix B: Sample client

This Appendix contains a sample client using the proposed new APIs. It compiles,
but cannot be tested since there is no implementation of the APIs yet.

````
#include <stdio.h>
#include <pthread.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

int still_running = 1;
int handshaking = 1;
int fd;

struct thread_data {
    SSL *stream;
    SSL_EVENT_CTX *ectx;
    char *hostname;
    BIO_ADDR *addr;
};

static void start_stream_thread(SSL *stream, SSL_EVENT_CTX *ectx,
                                char *hostname, BIO_ADDR *addr);

static void *do_stream_work(void *vdata)
{
    SSL_EVENT *ev = SSL_EVENT_new();
    SSL_EVENT_CTX *ectx;
    SSL *stream1, *stream2;
    int process_events = 1;
    size_t readbytes, written;
    unsigned char buf[1024];
    int width = fd + 1;
    fd_set readfds;
    struct timeval timeout;
    int do_timeout;
    int is_conn = SSL_is_connection(stream1);
    const char *msg = "Hello World!";
    struct thread_data *data = vdata;

    stream1 = data->stream;
    ectx = data->ectx;
    OPENSSL_free(data);

    while (still_running && process_events) {
        /*
         * If we're the connection object we'll get an event immediately (if there
         * is one) without blocking. Otherwise we'll block until there is an
         * event to process.
         */
        if (!SSL_EVENT_CTX_get_next_event(ectx, stream1, !is_conn, NULL, ev)) {
            /* No event occurred */
            if (is_conn) {
                /* Only the connection object needs to worry about the underlying
                 * fd. Wait for fd to become readable, or a timer event */

                FD_ZERO(&readfds);
                FD_SET(fd, &readfds);
                do_timeout = SSL_get_next_tick(stream1, &timeout);
                if (select(width, (void *)&readfds, NULL, NULL, do_timeout ? &timeout : NULL) < 0) {
                    printf("select error\n");
                    goto err;
                }
                if (handshaking) {
                    int connret;

                    /* No events occur until handshaking is complete */
                    connret = SSL_connect_ex(stream1, data->hostname, data->addr);
                    if (connret <= 0) {
                        switch (SSL_get_error(stream1, connret)) {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                            /* Loop again to recall SSL_connect */
                            continue;
                        default:
                            printf("Error during handshake\n");
                            goto err;
                        }
                    }
                    handshaking = 0;

                    if (!SSL_write_ex(stream1, msg, strlen(msg), &written)) {
                        /*
                         * Should really handle SSL_ERROR_WANT_WRITE, but we'll
                         * just error out
                         */
                        printf("Failed to write hello world message\n");
                        goto err;
                    }
                }
                continue;
            }
            /*
                * Should not happen. We should block until we get an event. If
                * we get here something went badly wrong.
                */
            printf("SSL_EVENT_CTX_get_next_event() error\n");
            goto err;
        }
        switch (SSL_EVENT_get_event_type(ev)) {
        case SSL_EVENT_TYPE_NEW_CONNECTION:
            printf("New connection event - but we are a client!\n");
            goto err;

        case SSL_EVENT_TYPE_NEW_STREAM:
            stream2 = SSL_accept_stream(stream1);
            if (stream2 == NULL) {
                printf("New stream event - but no new stream was available!\n");
                goto err;
            }
            start_stream_thread(stream2, ectx, NULL, NULL);
            break;

        case SSL_EVENT_TYPE_CONNECTION_CLOSE:
            still_running = 0;
            break;

        case SSL_EVENT_TYPE_STREAM_CLOSE:
            /*
             * The connection object may continue to receive events even after
             * any stream associated with it is closed
             */
            if (!is_conn)
                process_events = 0;
            break;

        case SSL_EVENT_TYPE_STREAM_READABLE:
            /* We should really do some proper error handling */
            if (SSL_read_ex(stream1, buf, sizeof(buf) - 1, &readbytes) > 0) {
                buf[readbytes] = '\0';
                printf("Read data: %s\n", buf);
            }
            break;

        case SSL_EVENT_TYPE_TICK:
            SSL_tick(stream1);
            break;

        case SSL_EVENT_TYPE_ERROR:
            printf("Error occurred\n");
            goto err;

        default:
            /* Ignore any other event */
            break;
        }
    }

 err:
    SSL_EVENT_free(ev);
    SSL_free(stream1);
    SSL_EVENT_CTX_free(ectx);
    printf("Closing stream\n");
    return NULL;
}

void start_stream_thread(SSL *stream, SSL_EVENT_CTX *ectx, char *hostname,
                         BIO_ADDR *addr)
{
    pthread_t thread;
    struct thread_data *data;

    data = OPENSSL_malloc(sizeof *data);
    if (data == NULL) {
        printf("Malloc failure\n");
        return;
    }
    SSL_up_ref(stream);
    SSL_EVENT_CTX_up_ref(ectx);
    data->stream = stream;
    data->ectx = ectx;
    data->hostname = hostname;
    data->addr = addr;

    if (pthread_create(&thread, NULL, do_stream_work, data)) {
        printf("Failed to create stream\n");
        SSL_free(stream);
        SSL_EVENT_CTX_free(ectx);
        OPENSSL_free(data);
    }
}

static int create_sockets(SSL_EVENT_CTX *ectx, BIO_ADDR **addr)
{
    /* Create the sockets here and set them in the SSL_EVENT_CTX object */

    return 1;
}

int main(void)
{
    SSL_CTX *ctx = SSL_CTX_new(QUIC_client_method());
    SSL *ssl;
    SSL_EVENT_CTX *ectx;
    int ret = 1;
    BIO_ADDR *addr = NULL;

    if (ctx == NULL) {
        printf("Failed to create ctx\n");
        goto err;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create SSL object\n");
        goto err;
    }

    ectx = SSL_EVENT_CTX_new(ctx, SSL_EVENT_TYPE_ALL_EVENTS,
                             SSL_EVENT_CTX_NEW_OPTION_THREAD_SAFE);
    if (ectx == NULL) {
        printf("Failed to create SSL_EVENT_CTX\n");
        goto err;
    }

    if (!create_sockets(ectx, &addr)) {
        printf("Failed to set up sockets\n");
        goto err;
    }
    start_stream_thread(ssl, ectx, "example.com", addr);

    ret = 0;
 err:
    SSL_free(ssl);
    SSL_EVENT_CTX_free(ectx);
    SSL_CTX_free(ctx);
    return ret;
}
````
