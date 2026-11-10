RADIX Test Framework
====================

Purpose
-------

This directory contains the RADIX test framework, which is a six-dimension
script-driven facility intended to facilitate execution of

- multi-stream
- multi-client
- multi-server
- multi-thread
- multi-process (in future)
- multi-node (in future)

test vignettes for network protocol testing applications. While it is currently
used for QUIC, it has been designed to be agnostic so that it can be adapted to
other protocols in future if desired.

In particular, it does not assume a single client and a single server. Examples
of vignettes designed to be supported by the RADIX test framework in future
include:

- single client ↔ single server
- multiple clients ↔ single server
- single client ↔ multiple servers
- multiple clients ↔ multiple servers

“Multi-process” and “multi-node” means there has been some consideration
given to support of multi-process and multi-node testing in the future, though
this is not currently supported.

Distinctive features
--------------------

The RADIX test framework has the following features:

- Because it uses the QUIC server API, opcodes are not split into “C” and “S”
  variants. All endpoints are treated symmetrically. The legacy `QUIC_TSERVER`
  facility is not used and will eventually be retired once other test suites
  no longer rely on it.

- The framework is not limited to two objects (client and server),
  but can instead instantiate an arbitrary number of SSL objects and pass these
  to operations. Other kinds of object could be supported in future if needed.

- Scripts are generated dynamically at launch time by functions rather than
  hardcoded into the executable. In particular, this allows very long
  procedurally generated test scripts which would be impractical to write
  by hand. This can be used for stress testing, for example.

- Because scripts are generated dynamically, script operations need not be
  expressible as initializer lists, so their in-memory representation is
  simple, compact, and flexible. A stack-based approach allows arbitrary
  argument types to be passed as operands to an operation, rather than having
  a fixed number of operands of fixed type for all script operations.

- Scripts are named, rather than numbered, giving more useful debug output,
  and hopefully reducing the frequency of merge conflicts.

- Debug output includes a listing of each generated script (with its name,
  source location and description), a trace of each executed operation, and
  the final state of the operand stack.

- Logging of child threads is buffered and printed after a test is complete,
  which avoids non-deterministic interleaving of test output.

- The interpreter has a small number of core opcodes; the vast majority of
  test operations are performed via `OP_FUNC`.

- In the future, multi-process or multi-node testing will be supported.
  The expectation is that multi-node testing will be facilitated by having the
  master process invoke a hook shell script which is responsible for propping up
  and tearing down the additional nodes. Writing a suitable hook script will be
  left as an exercise to the test infrastructure maintainer. This abstracts the
  test framework from the details of a specific infrastructure environment and
  its management tools (VMs, containers, etc.).

- The core test interpreter is designed to be agnostic to QUIC and could be
  used for testing other protocols in the future. There is a clean, layered
  design which draws a clear distinction between the core interpreter,
  protocol-specific bindings and support code, test operation definitions, and
  script definitions.

- Since ALPN is required for QUIC, it is set automatically when establishing
  a QUIC connection; scripts do not need an opcode to set it.

- Scripts do not need to end with an explicit `OP_END`.

Blocking operations
-------------------

QUIC clients and listeners are explicitly nonblocking by default. Accepted
connections and their streams inherit this setting. The interpreter drives
active endpoints and advances the simulated clock between operations and on
retries, so an operation must return to allow its peer to make progress.

Tests which require blocking operations must enable them explicitly with
`SSL_set_blocking_mode` and provide independent progress for the peer and the
simulated clock while the call waits. `OP_CONNECT_WAIT` always sets the client
to nonblocking mode, so enable blocking I/O after that operation. The domain
flags still enable blocking support, which is also needed by tests of
`SSL_poll` with a nonzero timeout.

Architecture
------------

The RADIX test suite framework is built in four layers:

- **TERP** ([terp.c](./terp.c)), a protocol-agnostic stack-based script
  interpreter for interruptible execution of test vignettes;

- the **QUIC bindings** ([quic_bindings.c](./quic_bindings.c)), which defines
  QUIC-specific test framework;

- the **QUIC operations** ([quic_ops.c](./quic_ops.c)), which define specific
  test operations for TERP which can be invoked by QUIC unit tests on top of the
  basic infrastructure defined by the QUIC bindings;

- the QUIC unit tests ([quic_tests.c](./quic_tests.c)), which use the above
  QUIC bindings.
