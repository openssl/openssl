Packet Demuxer
==============

This is a QUIC specific module that parses headers of incoming packets and
decides what to do next.

Demuxer requirements for MVP
----------------------------

These are requirements that were identified for MVP:

- multiple QUIC packets in an UDP packet handling as packet coalescing
  must be supported
- client must discard packets that do not match existing connection ID
- client must discard packets with version different from the one initially
  selected

Optional demuxer requirements
-----------------------------

These are optional features of client side demuxer, not required for MVP
but otherwise desirable:

- optionally trigger sending stateless reset packets if a received packet
  on client is well-formed but does not belong to a known connection

Demuxer requirements for server
-------------------------------

Further requirements after MVP for server support:

- on servers packets can create a new connection potentially
- server side packet handling for unsupported version packets:
  - trigger sending version negotiation packets if server receives a packet
    with unsupported version and is large enough to initiate a new connection;
    limit the number of such packets with the same destination
  - discard smaller packets with unsupported version
- packet handling on server for well-formed packets with supported version
  but with unknown connection IDs:
  - if the packet is well-formed Initial packet, trigger creating a new
    connection
  - if the the packet is well-formed 0RTT packet, mark the packet to be
    buffered for short time (as Initial packet might arrive late)
    - this is optional - enabled only if 0RTT support is enabled by the
      application
  - discard any other packet with unknown connection IDs
    - optionally trigger sending stateless reset packets as above for client
