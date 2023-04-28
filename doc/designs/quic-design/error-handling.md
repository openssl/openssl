Error handling in QUIC code
===========================

Current situation with TLS
--------------------------

The errors are put on the error stack (rather a queue but error stack is
used throughout the code base) during the libssl API calls. In most
(if not all) cases they should appear there only if the API call returns an
error return value. The `SSL_get_error()` call depends on the stack being
clean before the API call to be properly able to determine if the API
call caused a library or system (I/O) error.

As the error stacks are thread-local calls from separate threads (even with
the same SSL object) push errors to these separate error stacks. This is
not a problem as applications are supposed to check for errors immediately
after the API call on the same thread. There is no such thing as
Thread-assisted mode of operation.

Constraints
-----------

We need to keep using the existing ERR API as doing otherwise would
complicate the existing applications and break our API compatibility promise.
Even the ERR_STATE structure is public, although deprecated, an thus its
structure and semantics cannot be changed.

The error stack access is not under a lock (because it is thread-local).
This complicates _moving errors between threads_.

Error stack entries contain allocated data, copying entries between threads
would mean duplicating it or losing it.

Assumptions
-----------

This document assumes the error state of the QUIC connection (or stream for
stream level errors) is handled separately.

We can assume the internal assistance thread is well-behaving in regards
to the error stack.

We assume there are two types of errors that can be raised in the QUIC
library calls and in the subordinate libcrypto (and provider) calls. First
type is an intermittent error that does not really affect the state of the
QUIC connection - for example EAGAIN returned on a syscall, or unavailability
of some algorithm where there are other algorithms to try. Second type
is a permanent error that affect the error state of the QUIC connection.

Design
------

Return value of SSL_get_error() on QUIC connections or streams does not
depend on the error stack contents.

Intermittent errors are handled within the library and cleared from the
error stack before returning to the user.

Permanent errors happenning within the assist thread need to be transferred
to the regular user thread. To simplify the implementation they are required
to appear on the error stack reachable by the application ERR_ calls only
after the SSL_get_error() is called from the application.

Implementation
--------------

There is an error stack in QUIC_CHANNEL which serves as temporary storage
for errors happening in the internal assistance thread. When a permanent error
is detected in the assistance thread the error stack entries are copied
to this error stack in QUIC_CHANNEL.

When SSL_get_error() is called and there is a permanent error condition
detected the errors from the QUIC_CHANNEL error stack are moved to the
error stack of the thread that is calling SSL_get_error() on the SSL
object representing the QUIC_CONNECTION.

SSL_tick() return value
-----------------------

If a permanent error is detected during an SSL_tick() call, SSL_tick()
should return an error to make an application be aware of the error
condition. Otherwise an application keeping an idle connection with
a server would not be able to detect a connection error.

Multi-stream-multi-thread mode
------------------------------

TBD
