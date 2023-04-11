QUIC Connection ID Cache
========================

The connection ID cache is responsible for managing connection IDs, both local
and remote.

Remote Connection IDs
---------------------

For remote connection IDs, we need to be able to:

* add new IDs per connection;
* pick a non-retired ID associated from those available for a connection and
* select a connection ID by sequence number and retire that and all older IDs.

The cache will be implemented as a double ended queue as part of the
QUIC_CONNECTION object.  The queue will be sorted by sequence number
and must maintain a count of the number of connection IDs present.
There is no requirement to maintain a global mapping since remote IDs
are only used when sending packets, not receiving them.

In MVP, a many-to-1 matching of Connection IDs per Connection object
is required.  Refer third paragraph in [5.1].

When picking a non-retired connection ID for MVP, the youngest available will
be chosen.

Local Connection IDs
--------------------

For local connection IDs, we need to be able to:

* generate a new connection ID and associate it with a connection;
* query if a connection ID is present;
* for a server, map a connection ID to a QUIC_CONNECTION;
* drop all connection IDs associated with a QUIC_CONNECTION;
* select a connection ID by sequence number and retire that and all older IDs
  and
* select a connection ID by sequence number and drop that and all older IDs.

All connection IDs issued by our stack must be the same length because
short form packets include the connection ID but no length byte.  Random
connection IDs of this length will be allocated.  Note that no additional
information will be contained in the connection ID.

There will be one global set of local connection IDs, `QUIC_ROUTE_TABLE`,
which is shared by all connections over all SSL_CTX objects.  This is
used to dispatch incoming datagrams to their correct destination and
will be implemented as a dictionary.

### Notes

* For MVP, it would be sufficient to only use a zero length connection ID.
* For MVP, a connection ID to QUIC_CONNECTION mapping need not be implemented.
* Post MVP, funnelling all received packets through a single socket is
  likely to be bottleneck.
  An alternative would be receiving from <host address, source port> pairs.
* For MVP, the local connection ID cache need only have one element.
  I.e. there is no requirement to implement any form of lookup.

Routes
------

A pair of connection IDs identify a route between the two ends of the
communication.  This contains the connection IDs of both ends of the
connection and the common sequence number.  We need to be able to:

* select a connection ID by sequence number and retire that and all older IDs
  and
* select a connection ID by sequence number and drop that and all older IDs.

It is likely that operations on local and remote connection IDs can be
subsumed by the route functionality.

ID Retirement
-------------

Connection IDs are retired by either a [NEW_CONNECTION_ID] or
a [RETIRE_CONNECTION_ID] frame and this is acknowledged by a
RETIRE_CONNECTION_ID or a NEW_CONNECTION_ID frame respectively.

When a retirement frame is received, we can immediately _remove_ the
IDs covered from our cache and then send back an acknowledgement of
the retirement.

If we want to retire a frame, we send a retirement frame and mark the
IDs covered in our cache as _retired_.  This means that we cannot send
using any of these IDs but can still receive using them.  Once our peer
acknowledges the retirement, we can _remove_ the IDs.

It is possible to receive out of order packets **after** receiving a
retirement notification.  It's unclear what to do with these, however
dropping them seems reasonable.  The alternative would be to maintain
the route in a _deletable_ state until all packets in flight at the time
of retirement have been acked.

API
---

### Connection ID additions

```c
/* QUIC connection ID representation. */
#define QUIC_MAX_CONN_ID_LEN   20

typedef struct quic_conn_id_st {
    unsigned char id_len;
    unsigned char id[QUIC_MAX_CONN_ID_LEN];
} QUIC_CONN_ID;

static ossl_unused ossl_inline int ossl_quic_conn_id_eq(const QUIC_CONN_ID *a,
                                                        const QUIC_CONN_ID *b);

/* New functions */
int ossl_quic_conn_id_set(QUIC_CONN_ID *cid, unsigned char *id,
                          unsigned int id_len);

int ossl_quic_conn_id_generate(OSSL_LIB_CTX *ctx, QUIC_CONN_ID *cid);
```

### Routes

Additional status and source information is also included.

```c
typedef struct quic_route_st QUIC_ROUTE;
typedef struct quic_route_table QUIC_ROUTE_TABLE;

struct quic_route_st {
    QUIC_ROUTE_TABLE *tbl;
    QUIC_CONN_ID     local;
    QUIC_CONN_ID     remote;
    uint64_t         seq_no;        /* Sequence number for both ends */
    unsigned int     retired : 1;   /* Connection ID has been retired */
};

QUIC_ROUTE_TABLE *ossl_quic_route_table_new(OSSL_LIB_CTX *ctx);

void ossl_quic_route_table_free(QUIC_ROUTE_TABLE *routes);

/*
 * Create a new route for the given connection / route table.
 * The local connection ID and sequence number are automatically set.
 * The return is freed when the route is deleted from the route table.
 *
 * Passing NULL for remote_id will create a route with a zero length
 * remote ID.  Such an ID can be replaced later using the
 * ossl_quic_route_set_remote_connection_id() call.
 */
QUIC_ROUTE *ossl_quic_route_new(QUIC_ROUTE_TABLE *tbl
                                const unsigned char *remote_id,
                                size_t remote_id_len);
```

### Route query functions

```c
/*
 * Return a reference to the local connection ID from a route
 */
const QUIC_CONN_ID *
        ossl_quic_route_get_local_connection_id(const QUIC_ROUTE *route);

/*
 * Return a reference to the remote connection ID from a route
 */
const QUIC_CONN_ID *
        ossl_qui_route_get_remote_connection_id(const QUIC_ROUTE *route);


/*
 * For a route, return the route table it is included in
 * Unsure if this is required.
 */
QUIC_ROUTE_TABLE *ossl_quic_route_get_route_table(const QUIC_ROUTE *route);

/*
 * Extract the sequence number from a route
 */
uint64_t ossl_quic_route_get_sequence_number(const QUIC_ROUTE *route);

/*
 * Query if a route has been retired or not
 */
int ossl_quic_route_is_retired(const QUIC_ROUTE *route);
```

### Route update

```c
/*
 * Set a remote connection ID.
 * This is only a valid operation if the remote ID is currently set to
 * the null zero length ID.
 */
int ossl_quic_route_set_remote_connection_id(const QUIC_ROUTE *route,
                                             const unsigned char *remote_id,
                                             size_t remote_id_len);
```

### Route table queries

```c
/*
 * Query a route table entry by either local or remote ID
 */
QUIC_ROUTE *ossl_route_table_get0_route_from_local(
        const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len);
QUIC_ROUTE *ossl_route_table_get0_route_from_remote(
        const QUIC_ROUTE_TABLE *cache,
        const unsigned char *conn_id, size_t conn_id_len);
```

### Route retirement

```c
/*
 * Retire by sequence number up to and including the one specified.
 */
int ossl_quic_route_table_retire(QUIC_ROUTE_TABLE *routes, uint64_t seq_no);

/*
 * Delete by sequence number up to and including the one specified.
 */
int ossl_quic_route_table_remove(QUIC_ROUTE_TABLE *routes, uint64_t seq_no);
```

[5.1]: (https://datatracker.ietf.org/doc/html/rfc9000#section-5.1)
[active_connection_id_limit]: (https://datatracker.ietf.org/doc/html/rfc9000#section-18.2)
[NEW_CONNECTION_ID]: (https://datatracker.ietf.org/doc/html/rfc9000#section-19.15)
[RETIRE_CONNECTION_ID]: (https://datatracker.ietf.org/doc/html/rfc9000#section-19.16)
[retired]: (https://datatracker.ietf.org/doc/html/rfc9000#section-5.1.2)
