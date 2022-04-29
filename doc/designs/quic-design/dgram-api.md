Datagram BIO API revisions for sendmmsg/recvmmsg
================================================

We need to evolve the API surface of BIO which is relevant to BIO_dgram (and the
eventual BIO_dgram_mem) to support APIs which allow multiple datagrams to be
sent or received simultaneously, such as sendmmsg(2)/recvmmsg(2).

Options for the API surface include:

sendmmsg/recvmmsg-like API
--------------------------

```c
int BIO_readm(BIO *b, BIO_mmsghdr *msgvec,
              unsigned len, int flags, struct timespec *timeout);
int BIO_writem(BIO *b, BIO_mmsghdr *msgvec,
              unsigned len, int flags, struct timespec *timeout);
```

We can either define `BIO_mmsghdr` as a typedef of `struct mmsghdr` or redefine
an equivalent structure. The former has the advantage that we can just pass the
structures through to the syscall without copying them.

Note that in `BIO_mem_dgram` we will have to process and therefore understand
the contents of `struct mmsghdr` ourselves. Therefore, initially we define a
subset of `struct mmsghdr` as being supported, specifically no control messages;
`msg_name` and `msg_iov` only.

The flags argument is defined by us. Initially we can support something like
`MSG_DONTWAIT` (say, `BIO_DONTWAIT`).

Alternate API
-------------

Could we use a simplified API? For example, could we have an API that returns
one datagram where BIO_dgram uses `readmmsg` internally and queues the returned
datagrams, thereby still avoiding extra syscalls but offering a simple API.

The problem here is we want to support “single-copy” (where the data is only
copied as it is decrypted). Thus BIO_dgram needs to know the final resting place
of encrypted data at the time it makes the `readmmsg` call.

One option would be to allow the user to set a callback on BIO_dgram it can use
to request a new buffer, then have an API which returns the buffer:

```c
int BIO_dgram_set_read_callback(BIO *b,
                                void *(*cb)(size_t len, void *arg),
                                void *arg);
int BIO_dgram_set_read_free_callback(BIO *b,
                                     void (*cb)(void *buf,
                                                size_t buf_len,
                                                void *arg),
                                     void *arg);
int BIO_read_dequeue(BIO *b, void **buf, size_t *buf_len);
```

The BIO_dgram calls the specified callback when it needs to generate internal
iovecs for its `readmmsg` call, and the received datagrams can then be popped by
the application and freed as it likes. (The read free callback above is only
used in rare circumstances, such as when calls to `BIO_read` and
`BIO_read_dequeue` are alternated, or when the BIO_dgram is destroyed prior to
all read buffers being dequeued; see below.) For convenience we could have an
extra call to allow a buffer to be pushed back into the BIO_dgram's internal
queue of unused read buffers, which avoids the need for the application to do
its own management of such recycled buffers:

```c
int BIO_dgram_push_read_buffer(BIO *b, void *buf, size_t buf_len);
```

On the write side, the application provides buffers and can get a callback when
they are freed. BIO_write_queue just queues for transmission, and the `sendmmsg`
call is made when calling `BIO_flush`. (TBD: whether it is reasonable to
overload the semantics of BIO_flush in this way.)

```c
int BIO_dgram_set_write_done_callback(BIO *b,
                                      void (*cb)(const void *buf,
                                                 size_t buf_len,
                                                 int status,
                                                 void *arg),
                                      void *arg);
int BIO_write_queue(BIO *b, const void *buf, size_t buf_len);
int BIO_flush(BIO *b);
```

The status argument to the write done callback will be 1 on success, some
negative value on failure, and some special negative value if the BIO_dgram is
being freed before the write could be completed.

For send/receive addresses, we import the `BIO_(set|get)_dgram_(origin|dest)`
APIs proposed in the sendmsg/recvmsg PR (#5257). `BIO_get_dgram_(origin|dest)`
should be called immediately after `BIO_read_dequeue` and
`BIO_set_dgram_(origin|dest)` should be called immediately before
`BIO_write_queue`.

This approach allows `BIO_dgram` to support myriad options via composition of
successive function calls in a “builder” style rather than via a single function
call with an excessive number of arguments or pointers to unwieldy ever-growing
argument structures, requiring constant revision of the central read/write
functions of the BIO API.

Note that since `BIO_set_dgram_(origin|dest)` sets data on outgoing packets and
`BIO_get_dgram_(origin|dest)` gets data on incoming packets, it doesn't follow
that these are accessing the same data (they are not setters and getters of a
variables called "dgram origin" and "dgram destination", even though they look
like setters and getters of the same variables from the name.) We probably want
to separate these as there is no need for a getter for outgoing packet
destination, for example, and by separating these we allow the possibility of
multithreaded use (one thread reads, one thread writes) in the future. Possibly
we should choose less confusing names for these functions. Maybe
`BIO_set_outgoing_dgram_(origin|dest)` and
`BIO_get_incoming_dgram_(origin|dest)`.

Pros of this approach:

  - Application can generate one datagram at a time and still get the advantages
    of sendmmsg/recvmmsg (fewer syscalls, etc.)

    We probably want this for our own QUIC implementation built on top of this
    anyway. Otherwise we will need another piece to do basically the same thing
    and agglomerate multiple datagrams into a single BIO call. Unless we only
    want use `sendmmsg` constructively in trivial cases (e.g. where we send two
    datagrams from the same function immediately after one another... doesn't
    seem like a common use case.)

  - Flexible support for single-copy (zero-copy).

Cons of this approach:

  - Very different way of doing reads/writes might be strange to existing
    applications. *But* the primary consumer of this new API will be our own
    QUIC implementation so probably not a big deal. We can always support
    `BIO_read`/`BIO_write` as a less efficient fallback for existing third party
    users of BIO_dgram.

### Compatibility interop

Suppose the following sequence happens:

1. BIO_read (legacy call path)
2. BIO_read_dequeue (`recvmmsg` based call path with callback-allocated buffer)
3. BIO_read (legacy call path)

For (1) we have two options

a. Use `recvmmsg` and add the received datagrams to an RX queue just as for the
   `BIO_read_dequeue` path. We use an OpenSSL-provided default allocator
   (`OPENSSL_malloc`) and flag these datagrams as needing to be freed by OpenSSL,
   not the application.

   When the application calls `BIO_read`, a copy is performed and the internal
   buffer is freed.

b. Use `recvfrom` directly. This means we have a `recvmmsg` path and a
   `recvfrom` path depending on what API is being used.

   The disadvantage of (a) is it yields an extra copy relative to what we have now,
   whereas with (b) the buffer passed to `BIO_read` gets passed through to the
   syscall and we do not have to copy anything.

   Since we will probably need to support platforms without
   `sendmmsg`/`recvmmsg` support anyway, (b) seems like the better option.

For (2) the new API is used. Since the previous call to BIO_read is essentially
“stateless” (it's just a simple call to `recvfrom`, and doesn't require mutation
of any internal BIO state other than maybe the last datagram source/destination
address fields), BIO_dgram can go ahead and start using the `recvmmsg` code
path. Since the RX queue will obviously be empty at this point, it is
initialised and filled using `recvmmsg`, then one datagram is popped from it.

For (3) we have a legacy `BIO_read` but we have several datagrams still in the
RX queue. In this case we do have to copy - we have no choice. However this only
happens in circumstances where a user of BIO_dgram alternates between old and
new APIs, which should be very unusual.

Subsequently for (3) we have to free the buffer using the free callback. This is
an unusual case where BIO_dgram is responsible for freeing read buffers and not
the application (the only other case being premature destruction, see below).
But since this seems a very strange API usage pattern, we may just want to fail
in this case.

Probably not worth supporting this. So we can have the following rule:

- After the first call to `BIO_read_dequeue` is made on a BIO_dgram, all
  subsequent calls to ordinary `BIO_read` will fail.

Of course, all of the above applies analogously to the TX side.

### BIO_dgram_mem

We will also implement from scratch a BIO_dgram_mem. This will be provided as a
BIO pair which provides identical semantics to the BIO_dgram above, both for the
legacy and zero-copy code paths.

### Thread safety

It is a functional assumption of the above design that we would never want to
have more than one thread doing TX on the same BIO and never have more than one
thread doing RX on the same BIO.

If we did ever want to do this, multiple BIOs on the same FD is one possibility
(for the BIO_dgram case at least). But I don't believe there is any general
intention to support multithreaded use of a single BIO at this time (unless I am
mistaken), so this seems like it isn't an issue.

If we wanted to support multithreaded use of the same FD using the same BIO, we
would need to revisit the set-call-then-execute-call API approach above
(`BIO_(set|get)_dgram_(origin|dest)`) as this would pose a problem. But I mainly
mention this only for completeness. Our recent learnt lessons on cache
contention suggest that this probably wouldn't be a good idea anyway.

### Other questions

BIO_dgram will call the allocation function to get buffers for `recvmmsg` to
fill. We might want to have a way to specify how many buffers it should offer to
`recvmmsg`, and thus how many buffers it allocates in advance.

### Premature destruction

If BIO_dgram is freed before all datagrams are read, the read buffer free
callback is used to free any unreturned read buffers.
