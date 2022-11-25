QUIC API Overview
=================

This document sets out the objectives of the QUIC API design process, describes
the new and changed APIs, and the design constraints motivating those API
designs and the relevant design decisions.

Objectives
----------

The objectives of the QUIC API design are:

- to provide an API suitable for use with QUIC, now and in the future;

- to reuse the existing libssl APIs to the extent feasible;

- to enable existing applications to adapt to using QUIC with only
  minimal API changes.

SSL Objects
-----------

### Structure of Documentation

Each API listed below has an information table with the following fields:

- **Semantics**: This can be one of:

    - **Unchanged**: The semantics of this existing libssl API call are
      unchanged.
    - **Changed**: The semantics are changed for QUIC.
    - **New**: The API is new for QUIC.

- `SSL_get_error`: Can this API, when used with QUIC, change the
  state returned by `SSL_get_error`? This can be any combination of:

    - **Never**: Does not interact with `SSL_get_error`.
    - **Error**: Non-`WANT_READ`/`WANT_WRITE` errors can be raised.
    - **Want**: `WANT_READ`/`WANT_WRITE` can be raised.

- **Can Tick?**: Whether this function is allowed to tick the QUIC state
  machine and potentially perform network I/O.

- **CSHL:** Connection/Stream/Handshake Layer classification.
  This can be one of:

    - **HL:** This is a handshake layer related call. It should be supported
      on a QUIC connection SSL object, forwarding to the handshake layer
      SSL object.

      Whether we allow QUIC stream SSL objects to have these calls forwarded is
      TBD.

    - **HL-Forbidden:** This is a handshake layer related call, but it is
      inapplicable to QUIC, so it is not supported.

    - **C:** Not handshake-layer related. QUIC connection SSL object usage only.
      Fails on a QUIC stream SSL object.

    - **CS:** Not handshake-layer related. Can be used on any QUIC SSL object.

### Existing APIs

#### `SSL_set_connect_state`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | HL            |

#### `SSL_set_accept_state`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | HL            |

**Note:** Attempting to proceed in this state will not function for now because
we do not implement server support at this time. However, the semantics of this
function as such are unchanged.

#### `SSL_is_server`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | HL            |

#### `SSL_connect`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | HL            |

Simple composition of `SSL_set_connect_state` and `SSL_do_handshake`.

#### `SSL_accept`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | HL            |

Simple composition of `SSL_set_accept_state` and `SSL_do_handshake`.

#### `SSL_do_handshake`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | HL            |

**Note:** Idempotent if handshake already completed.

**Blocking Considerations:** Blocks until handshake completed if in blocking
mode.

**TBD:** Should this wait until handshake is completed or until it is confirmed?

#### `SSL_read`, `SSL_read_ex`, `SSL_peek`, `SSL_peek_ex`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | CS            |

**Blocking Considerations:** Blocks until at least one byte is available or an
error occurs if in blocking mode (including the peek functions).

#### `SSL_write`, `SSL_write_ex`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | CS            |

We have to implement all of the following modes:

- `SSL_ENABLE_PARTIAL_WRITE` on or off
- `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` on or off
- Blocking mode on or off

**Blocking Considerations:** Blocks until all data is written or an error occurs
if in blocking mode.

TBD: Does SSL_ENABLE_PARTIAL_WRITE interact with blocking mode?

#### `SSL_pending`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | CS            |

#### `SSL_has_pending`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | CS            |

**TBD.** Options:

  - Semantics unchanged or approximated (essentially, `SSL_pending() || any RXE
    queued || any URXE queued`).
  - Change semantics to only determine the return value based on if there is
    data in the stream receive buffer.

#### `SSL_shutdown`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Error/Want    | Yes       | CS            |

Semantics unchanged on QUIC Connection SSL objects.

Probable implementation:

  - If the peer did not yet close the connection, send CONNECTION_CLOSE once
    (best effort, tick), return 0.
  - Otherwise, if teardown is complete, return 1.

Semantics for future QUIC Stream SSL objects TBD, but:

  - We should have a way for `SSL_shutdown` to only affect the stream object
    and not the entire connection, so that applications can pass SSL objects for
    an individual stream to parts of themselves which expect something
    resembling traditional TCP stream and then call `SSL_shutdown`.

    A reasonable design here would be to have `SSL_shutdown` on a QUIC stream
    SSL object only shut down that stream. However this would mean
    `SSL_shutdown` behaves differently on the default stream (i.e., the QUIC
    connection SSL object) to other streams. Thus a new API should probably be
    added explicitly for QUIC stream shutdown. `SSL_shutdown` on a QUIC stream
    object will redirect to this function, or it can be used explicitly on the
    QUIC connection object if it has a default stream bound.

#### `SSL_clear`

There are potential implementation hazards:

>SSL_clear() resets the SSL object to allow for another connection. The reset
>operation however keeps several settings of the last sessions (some of these
>settings were made automatically during the last handshake). It only makes sense
>for a new connection with the exact same peer that shares these settings, and
>may fail if that peer changes its settings between connections.

**TBD:** How should `SSL_clear` be implemented? Either:

  - Modernised implementation which resets everything, handshake layer
    re-instantiated (safer);
  - Preserve `SSL_clear` semantics at the handshake layer, reset all QUIC state
    (`QUIC_CHANNEL` torn down, CSM reset).

#### `SSL_set0_rbio`, `SSL_set0_wbio`, `SSL_set_bio`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Changed   | Never         | No        | C             |

Sets network-side BIO.

The changes to the semantics of these calls are as follows:

  - The BIO MUST be a BIO with datagram semantics.

  - If the BIO is non-pollable (see below), application-level blocking mode will
    be forced off.

#### `SSL_set_[rw]fd`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Changed   | Never         | No        | C             |

Sets network-side socket FD.

Existing behaviour: Instantiates a `BIO_s_socket`, sets an FD on it, and sets it
as the BIO.

New proposed behaviour:

- Instantiate a `BIO_s_dgram` instead for a QUIC connection SSL object.
- Fails (no-op) for a QUIC stream SSL object.

#### `SSL_get_[rw]fd`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | C             |

Should not require any changes.

#### `SSL_CTRL_MODE`, `SSL_CTRL_CLEAR_MODE`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| Unchanged | Never         | No        | CS            |

#### SSL Modes

- `SSL_MODE_ENABLE_PARTIAL_WRITE`: Implemented. If this mode is set during a
  non-partial-write `SSL_write` operation spanning multiple `SSL_write` calls,
  this operation is aborted and partial write mode begins immediately.

- `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`: Implemented.

- `SSL_MODE_AUTO_RETRY`: TBD.

- `SSL_MODE_RELEASE_BUFFERS`: Ignored. This is an optimization and if it has
  any sensible semantic correspondence to QUIC, this can be considered later.

- `SSL_MODE_SEND_FALLBACK_SCSV`: TBD: Either ignore or fail if the client
  attempts to set this prior to handshake. The latter is probably safer.

  TBD: What if the client attempts to set this post handshake? Ignore it?

- `SSL_MODE_ASYNC`: TBD.

### New APIs

TBD: Should any of these be implemented as ctrls rather than actual functions?

#### `SSL_tick`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | Yes       | CS            |

Advances the QUIC state machine to the extent feasible, potentially performing
network I/O. Also compatible with DTLSv1 and supercedes `DTLSv1_handle_timeout`
for all use cases.

TBD: Should we just map this to DTLS_CTRL_HANDLE_TIMEOUT internally (and maybe
alias the CTRL #define)?

#### `SSL_get_tick_timeout`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | No        | CS            |

Gets the time until the QUIC state machine next wants to receive a timeout
event, if any.

This is similar to the existing `DTLSv1_get_timeout` function, but it is not
specific to DTLSv1. It is also usable for DTLSv1 and can become a
protocol-agnostic API for this purpose, superceding `DTLSv1_get_timeout` for all
use cases.

The design is similar to that of `DTLSv1_get_timeout` and uses a `struct
timeval`. However, this function represents an infinite timeout (i.e., no
timeout) using `tv_sec == -1`, whereas `DTLSv1_get_timeout` represents an
infinite timeout using a 0 return value, which does not allow a failure
condition to be distinguished.

TBD: Should we just map this to DTLS_CTRL_GET_TIMEOUT internally (and maybe
alias the CTRL #define)?

#### `SSL_set_blocking_mode`, `SSL_get_blocking_mode`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | No        | CS            |

Turns blocking mode on or off. This is necessary because up until now libssl has
operated in blocking or non-blocking mode automatically as an emergent
consequence of whether the underlying network socket is blocking. Since we are
proposing to use only non-blocking I/O internally, use of blocking semantics at
the application level must be explicitly configured.

Use on stream objects: It may be feasible to implement this such that different
QUIC stream SSL objects can have different settings for this option.

Not supported for non-QUIC SSL objects.

#### `SSL_get_rpoll_descriptor`, `SSL_get_wpoll_descriptor`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | No        | CS            |

These functions output poll descriptors which can be used to determine
when the QUIC state machine should next be ticked. `SSL_get_rpoll_descriptor` is
relevant if `SSL_want_net_read` returns 1, and `SSL_get_wpoll_descriptor` is
relevant if `SSL_want_net_write` returns 1.

The implementation of these functions is a simple forward to
`BIO_get_rpoll_descriptor` and `BIO_get_wpoll_descriptor` on the underlying
network BIOs.

#### `SSL_want_net_read`, `SSL_want_net_write`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | No        | CS            |

These calls return 1 if the QUIC state machine is interested in receiving
further data from the network, or writing to the network, respectively. The
return values of these calls should be used to determine which wakeup events
should cause an application to call `SSL_tick`. These functions do not mutate
any state, and their return values may change after a call to any SSL function
other than `SSL_want_net_read`, `SSL_want_net_write`,
`SSL_get_rpoll_descriptor`, `SSL_get_wpoll_descriptor` and
`SSL_get_tick_timeout`.

#### `SSL_want`, `SSL_want_read`, `SSL_want_write`

The existing API `SSL_want`, and the macros defined in terms of it, are
traditionally used to determine if the SSL state machine has exited in
non-blocking mode due to a desire to read from or write to the underlying
network BIO. However, this API is unsuitable for use with QUIC because the
return value of `SSL_want` can only express one I/O direction at a time (read or
write), not both. This call will not be implemented for QUIC (e.g. always
returns `SSL_NOTHING`) and `SSL_want_net_read` and `SSL_want_net_write` will be
used instead.

TBD: Should these be implemented for non-QUIC SSL objects?

#### `SSL_set_initial_peer_addr`, `SSL_get_initial_peer_addr`

| Semantics | `SSL_get_error` | Can Tick? | CSHL          |
| --------- | ------------- | --------- | ------------- |
| New       | Never         | No        | CS            |

`SSL_set_initial_peer_addr` sets the initial L4 UDP peer address for an outgoing
QUIC connection.

The initial peer address may be autodetected if no peer address has already been
set explicitly and the QUIC connection SSL object is provided with a
`BIO_s_dgram` with a peer set.

`SSL_set_initial_peer_addr` cannot be called after a connection is established.

### Future APIs

A custom poller interface may be provided in the future. For more information,
see the QUIC I/O Architecture design document.

BIO Objects
-----------

### Existing APIs

#### `BIO_s_connect`, `BIO_new_ssl_connect`, `BIO_set_conn_hostname`

We are aiming to support use of the existing `BIO_new_ssl_connect` API with only
minimal changes. This will require internal changes to `BIO_s_connect`, which
should automatically detect when it is being used with a QUIC `SSL_CTX` and act
accordingly.

#### `BIO_new_bio_pair`

Unsuitable for use with QUIC on the network side; instead, applications can
make use of the new `BIO_s_dgram_pair` which provides equivalent functionality
with datagram semantics.

#### Interactions with `BIO_f_buffer`

Existing applications sometimes combine a network socket BIO with a
`BIO_f_buffer`. This is problematic because the datagram semantics of writes are
not preserved, therefore the BIO provided to libssl is, as provided, unusable
for the purposes of implementing QUIC. Moreover, output buffering is not a
relevant or desirable performance optimisation for the transmission of UDP
datagrams and will actually undermine QUIC performance by causing incorrect
calculation of ACK delays and consequently inaccurate RTT calculation.

Options:

  - Require applications to be changed to not use QUIC with a `BIO_f_buffer`.
  - Detect when a `BIO_f_buffer` is part of a BIO stack and bypass it
    (yucky and surprising).

#### MTU Signalling

**See also:**
[BIO_s_dgram_pair(3)](https://www.openssl.org/docs/manmaster/man3/BIO_s_dgram_pair.html)

`BIO_dgram_get_mtu` (`BIO_CTRL_DGRAM_GET_MTU`) and `BIO_dgram_set_mtu`
(`BIO_CTRL_DGRAM_SET_MTU`) already exist for `BIO_s_dgram` and are implemented
on a `BIO_s_dgram_pair` to allow the MTU to be determined and configured. One
side of a pair can configure the MTU to allow the other side to detect it.

`BIO_s_dgram` also has pre-existing support for getting the correct MTU value
from the OS using `BIO_CTRL_DGRAM_QUERY_MTU`.

### New APIs

#### `BIO_sendmmsg` and `BIO_recvmmsg`

**See also:**
[BIO_sendmmsg(3)](https://www.openssl.org/docs/manmaster/man3/BIO_sendmmsg.html)

The BIO interface features a new high-performance API for the execution of
multiple read or write operations in a single system call, on supported OSes. On
other OSes, a compatible fallback implementation is used.

Unlike all other BIO APIs, this API is intended for concurrent threaded use and
as such operates in a stateless fashion with regards to a BIO. This means, for
example, that retry indications are made using explicit API inputs and outputs
rather than setting an internal flag on the BIO.

This new BIO API includes:

- Local address support (getting the destination address of an incoming
  packet; setting the source address of an outgoing packet), where support
  for this is available;
- Peer address support (setting the destination address of an outgoing
  packet; getting the source address of an incoming packet), where support
  for this is available.

The following functionality was intentionally left out of this design because
not all OSes can provide support:

- Iovecs (which have also been determined not to be necessary for a
  performant QUIC implementation);
- Features such as `MSG_DONTWAIT`, etc.

This BIO API is intended to be extensible. For more information on this API, see
BIO_sendmmsg(3) and BIO_recvmmsg(3).

Custom BIO implementers may set their own implementation of these APIs via
corresponding `BIO_meth` getter/setter functions.

#### Truncation Mode

**See also:**
[BIO_s_dgram_pair(3)](https://www.openssl.org/docs/manmaster/man3/BIO_s_dgram_pair.html)

The controls `BIO_dgram_get_no_trunc` (`BIO_CTRL_DGRAM_GET_NO_TRUNC`) and
`BIO_dgram_get_no_trunc` (`BIO_CTRL_DGRAM_GET_NO_TRUNC`) are introduced. This is
a boolean value which may be implemented by BIOs with datagram semantics. When
enabled, attempting to receive a datagram such that the datagram would
ordinarily be truncated (as per the design of the Berkeley sockets API) instead
results in a failure. This is intended for implementation by `BIO_s_dgram_pair`.
For compatibility, the default behaviour is off.

#### Capability Negotiation

**See also:**
[BIO_s_dgram_pair(3)](https://www.openssl.org/docs/manmaster/man3/BIO_s_dgram_pair.html)

Where a `BIO_s_dgram_pair` is used, there is the potential for such a memory BIO
to be used by existing application code which is being adapted for use with
QUIC. A problem arises whereby one end of a `BIO_s_dgram_pair` (for example, the
side being used by OpenSSL's QUIC implementation) may assume that the other end
supports certain capabilities (for example, specifying a peer address), when in
actual fact the opposite end of the `BIO_s_dgram_pair` does not.

A capability signalling mechanism is introduced which allows one end of a
`BIO_s_dgram_pair` to indicate to the user of the opposite BIO the following
capabilities and related information:

- Whether source addresses the peer specifies will be processed.
- Whether destination addresses the peer specifies will be processed.
- Whether source addresses will be provided to the opposite BIO when it
  receives datagrams.
- Whether destination addresses will be provided to the opposite BIO
  when it receives datagrams.

The usage is as follows:

- One side of a BIO pair calls `BIO_dgram_set_caps` with zero or
  more of the following flags to advertise its capabilities:
  - `BIO_DGRAM_CAP_HANDLES_SRC_ADDR`
  - `BIO_DGRAM_CAP_HANDLES_DST_ADDR`
  - `BIO_DGRAM_CAP_PROVIDES_SRC_ADDR`
  - `BIO_DGRAM_CAP_PROVIDES_DST_ADDR`
- The other side of the BIO pair calls `BIO_dgram_get_effective_caps`
  to learn the effective capabilities of the BIO. These are the capabilities set
  by the opposite BIO.
- The above process can also be repeated in the opposite direction.

#### Local Address Support

**See also:**
[BIO_s_dgram_pair(3)](https://www.openssl.org/docs/manmaster/man3/BIO_s_dgram_pair.html)

Support for local addressing (the reception of destination addresses for
incoming packets, and the specification of source addresses for outgoing
packets) varies by OS. Thus, it may not be available in all circumstances. A
feature negotiation mechanism is introduced to facilitate this.

`BIO_dgram_get_local_addr_cap` (`BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP`) determines
if a BIO is potentially capable of supporting local addressing on the current
platform. If it determines that support is available, local addressing support
must then be explicitly enabled via `BIO_dgram_set_local_addr_enable`
(`BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE`). If local addressing support has not
been enabled, attempts to use local addressing (for example via `BIO_sendmmsg`
or `BIO_recvmmsg` with a `BIO_MSG` with a non-NULL `local` field) fails.

An explicit enablement call is required because setting up local addressing
support requires system calls on most operating systems prior to sending or
receiving packets and we do not wish to do this automatically inside the
`BIO_sendmmsg`/`BIO_recvmmsg` fastpaths, particularly since the process of
enabling support could fail due to lack of OS support, etc.

`BIO_dgram_get_local_addr_enable` (`BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE`) is
also available.

It is important to note that `BIO_dgram_get_local_addr_cap` is entirely distinct
from the application capability negotiation mechanism discussed above. Whereas
the capability negotiation mechanism discussed above allows *applications* to
signal what they are capable of handling in their usage of a given BIO,
`BIO_dgram_local_addr_cap` allows a *BIO implementation* to indicate to the
users of that BIO whether it is able to support local addressing (where
enabled).

#### `BIO_s_dgram_pair`

**See also:**
[BIO_s_dgram_pair(3)](https://www.openssl.org/docs/manmaster/man3/BIO_s_dgram_pair.html)

A new BIO implementation, `BIO_s_dgram_pair`, is provided. This is similar to
the existing BIO pair but provides datagram semantics. It provides full support
for the new APIs `BIO_sendmmsg`, `BIO_recvmmsg`, the capability negotiation
mechanism described above, local address support and the MTU signalling
mechanism described above.

It can be instantiated using the new API `BIO_new_dgram_pair`.

#### `BIO_POLL_DESCRIPTOR`

The concept of *poll descriptors* are introduced. A poll descriptor is a tagged
union structure which represents an abstraction over some unspecified kind of OS
descriptor which can be used for synchronization and waiting.

The most commonly used kind of poll descriptor is one which describes a network
socket (i.e., on POSIX-like platforms, a file descriptor), however other kinds
of poll descriptor may be defined.

A BIO may be queried for whether it has a poll descriptor for read or write
operations respectively:

- Where `BIO_get_rpoll_descriptor` (`BIO_CTRL_GET_RPOLL_DESCRIPTOR`) is called,
  the BIO should output a poll descriptor which describes a resource which can
  be used to determine when the BIO will next become readable via a call to
  `BIO_read` or, if supported by the BIO, `BIO_recvmmsg`.
- Where
  `BIO_get_wpoll_descriptor` (`BIO_CTRL_GET_WPOLL_DESCRIPTOR`) is called, the
  BIO should output a poll descriptor which describes a resource which can be
  used to determine when the BIO will next become writeable via a call to
  `BIO_write` or, if supported by the BIO, `BIO_sendmmsg`.

A BIO may not necessarily be able to provide a poll descriptor. For example,
memory-based BIOs such as `BIO_s_dgram_pair` do not correspond to any OS
synchronisation resource, and thus the `BIO_get_rpoll_descriptor` and
`BIO_get_wpoll_descriptor` calls are not supported for such BIOs.

A BIO which supports these functions is known as pollable, and a BIO which does
not is known as non-pollable. `BIO_s_dgram` supports these functions.

The implementation of these functions for a `BIO_f_ssl` forwards to
`SSL_get_rpoll_descriptor` and `SSL_get_wpoll_descriptor` respectively. The

#### `BIO_s_dgram_mem`

This is a basic memory buffer BIO with datagram semantics. Unlike
`BIO_s_dgram_pair`, it is unidirectional and does not support peer addressing or
local addressing.

#### `BIO_err_is_non_fatal`

A new predicate function `BIO_err_is_non_fatal` is defined which determines if
an error code represents a non-fatal or transient error. For details, see
[BIO_sendmmsg(3)](https://www.openssl.org/docs/manmaster/man3/BIO_sendmmsg.html).
