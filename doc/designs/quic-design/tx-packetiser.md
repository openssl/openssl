TX Packetiser
=============

This module creates frames from the application data obtained from
the application.  It also receives CRYPTO frames from the TLS Handshake
Record Layer and ACK frames from the ACK Handling And Loss Detector
subsystem.

The packetiser also deals with the flow and congestion controllers.

Creation & Destruction
----------------------

```c
struct ossl_quic_tx_packetiser_st {
    QUIC_CONNECTION *conn;
};

_owur typedef struct ossl_quic_tx_packetiser_st OSSL_QUIC_TX_PACKETISER;

OSSL_QUIC_TX_PACKETISER ossl_quic_tx_packetiser_new(QUIC_CONNECTION *conn);
void ossl_quic_tx_packetiser_free(OSSL_QUIC_TX_PACKETISER *tx);
```

Structures
----------

### Connection

Represented by an QUIC_CONNECTION object.

### Stream

Represented by an QUIC_STREAM object.

As per [RFC 9000 2.3 Stream Prioritization], streams should contain a priority
provided by the calling application.  For MVP, this is not required to be
implemented because only one stream is supported.  However, packets being
retransmitted should be preferentially sent as noted in
[RFC 9000 13.3 Retransmission of Information].

```c
void SSL_set_priority(SSL *stream, uint32_t priority);
uint32_t SSL_get_priority(SSL *stream);
```

For protocols where priority is not meaningful, the set function is a noop and
the get function returns a constant value.

### Frame

QUIC frames are represented by a leading variable length integer
indicating the type of the frame.  This is followed by the frame data.
Only the first byte of the type is important because there are no defined
packet types that need more than one byte to represent.  Thus:

```c
struct ossl_quic_frame_st {
    unsigned char type;
};

typedef struct ossl_quic_frame_st OSSL_QUIC_FRAME;

struct ossl_quic_txp_frame_st {
    OSSL_QUIC_FRAME *frame; /* Frame in wire format */
    size_t frame_len;       /* Size of frame */
    uint32_t priority;      /* Priority of frame */
};

typedef struct ossl_quic_txp_frame_st OSSL_QUIC_TXP_FRAME;
```

The packetiser/ACK manager can alter the priority of a frame a small amount.
For example, a retransmitted frame may have it's priority increased slightly.

#### Frames

Frames are taken from [RFC 9000 12.4 Frames and Frame Types].

| Type | Name | I | H | 0 | 1 | N | C | P | F |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0x00 | padding | &check; | &check; | &check; | &check; | &check; | | &check;
| 0x01 | ping | &check; | &check; | &check; | &check; | | | | |
| 0x02 | ack 0x02 | &check; | &check; | | &check; | &check; | &check; | | |
| 0x03 | ack 0x03 | &check; | &check; | | &check; | &check; | &check; | | |
| 0x04 | reset_stream | | | &check; | &check; | | | | |
| 0x05 | stop_sending | | | &check; | &check; | | | | |
| 0x06 | crypto | &check; | &check; | | &check; | | | | |
| 0x07 | new_token | | | | &check; | | | | |
| 0x08 | stream 0x08 | | | &check; | &check; | | | | &check; |
| 0x09 | stream 0x09 | | | &check; | &check; | | | | &check; |
| 0x0A | stream 0x0A | | | &check; | &check; | | | | &check; |
| 0x0B | stream 0x0B | | | &check; | &check; | | | | &check; |
| 0x0C | stream 0x0C | | | &check; | &check; | | | | &check; |
| 0x0D | stream 0x0D | | | &check; | &check; | | | | &check; |
| 0x0E | stream 0x0E | | | &check; | &check; | | | | &check; |
| 0x0F | stream 0x0F | | | &check; | &check; | | | | &check; |
| 0x10 | max_data | | | &check; | &check; | | | | |
| 0x11 | max_stream_data | | | &check; | &check; | | | | |
| 0x12 | max_streams 0x12 | | | &check; | &check; | | | | |
| 0x13 | max_streams 0x13 | | | &check; | &check; | | | | |
| 0x14 | data_blocked | | | &check; | &check; | | | | |
| 0x15 | stream_data_blocked | | | &check; | &check; | | | | |
| 0x16 | streams_blocked 0x16 | | | &check; | &check; | | | | |
| 0x17 | streams_blocked 0x17 | | | &check; | &check; | | | | |
| 0x18 | new_connection_id | | | &check; | &check; | | | &check; | |
| 0x19 | retire_connection_id | | | &check; | &check; | | | | |
| 0x1A | path_challenge | | | &check; | &check; | | | &check; | |
| 0x1B | path_response | | | | &check; | | | &check; | |
| 0x1C | connection_close 0x1C | &check; | &check; | &check; | &check; | &check;
| 0x1D | connection_close 0x1D | | | &check; | &check; | &check; | | | |
| 0x1E | handshake_done | | | | &check; | | | | |

The various fields are as defined in RFC 9000.

##### Pkts

_Pkts_ are defined as:

| Pkts | Description|
| :---: | --- |
| I | Valid in Initial packets|
| H | Valid in Handshake packets|
| 0 | Valid in 0-RTT packets|
| 1 | Valid in 1-RTT packets|

##### Spec

_Spec_ is defined as:

| Spec | Description |
| :---: | --- |
| N | Not ack-eliciting. |
| C | does not count toward bytes in flight for congestion control purposes. |
| P | Can be used to probe new network paths during connection migration. |
| F | The contents of frames with this marking are flow controlled. |

For `C`, `N` and `P`, the entire packet must consist of only frames with the
marking for the packet to qualify for it.  For example, a packet with an ACK
frame and a _stream_ frame would qualify for neither the `C` or `N` markings.

### Packets

Frames are coalesced into packets which are then sent by the record layer.
The `packet_header` is a pointer to the leading bytes of the packet.
The `frames` are pointers to the individual frames that make up the
packet's body.
It is expected that the record layer will encrypt from the `packet_header` and
`frames` directly without a copy.

```c
enum packet_validity_e {
    QUIC_PACKET_INITIAL,
    QUIC_PACKET_HANDSHAKE,
    QUIC_PACKET_0_RTT,
    QUIC_PACKET_1_RTT
};

typedef enum packet_validity_e PACKET_VALIDITY;

struct ossl_quic_packet_st {
    QUIC_CONNECTION *conn;
    unsigned char *packet_header;
    size_t packet_header_length;
    STACK_OF(OSSL_QUIC_TXP_FRAME) *frames;

    QUIC_PN packet_number; /* RFC 9000 12.3 */
    size_t packet_length;

    /*
     * One of the QUIC_PN_SPACE_* values. This qualifies the pkt_num field
     * into a packet number space.
     */
    unsigned int pkt_space : 2;

    /* Pkts options */
    PACKET_VALIDITY validity;

    /* Spec */
    unsigned int no_ack : 1;
    unsigned int no_congestion_control : 1;
    unsigned int probing : 1;
    unsigned int flow_controlled : 1;
};

typedef struct ossl_quic_packet_st OSSL_QUIC_PACKET;
```

#### Notes

- Do we need the distinction between 0-rtt and 1-rtt when both are in
  the Application Data number space?
- 0-RTT packets can morph into 1-RTT packets and this needs to be handled by
  the packetiser.

Interactions
------------

The packetiser needs to interact with other modules.  This defines the APIs
by which it does so.

Frames are passed to the packetiser on a per stream basis.
The frames must be fully formed.  By passing a frame to this function,
ownership is passed to the packetiser which queues the frames for later
sending by the record layer.

```c
int ossl_quic_packetiser_buffer_frame(OSSL_QUIC_TX_PACKETISER *tx,
                                      QUIC_CONNECTION *stream,
                                      const OSSL_QUIC_FRAME *frame,
                                      size_t frame_length);
```

### Stream Send Buffers

Data from the stream send buffers is treated specially.  The packetiser knows
how much space is left in each packet and it will request that amount of data
from the stream send buffers.  The stream send buffers will return a
constructed frame header and a pointer to the steam data and length.  A second
call exists to allow the packetiser to know how much data is queued for a stream
so that planning for the creation of multiple packets is possible.

```c
int ossl_quic_get_app_data(QUIC_STREAM *stream, size_t request,
                           const OSSL_QUIC_FRAME **frame,
                           const unsigned char **data,
                           size_t *data_len);

size_t ossl_quic_get_app_data_size(QUIC_STREAM *stream);
```

#### Notes

* Unclear how to best free the data after sent data was acked.
  The data will be fragments from the buffers so the stream send buffers will
  need to remember which fragment have been sent and which are pending and
  only free once everything is sent:

```c
int ossl_quic_free_app_data(QUIC_STREAM *stream, void *data, size_t data_len);
```

* Need a call to tell the stream send buffers to forget about previously
  requested app data because it needs to be retransmitted and the
  boundaries could change.  Any record of the indicated data having being
  transmitted should be removed and the data is made eligible to be sent
  again.

```c
int ossl_quic_retransmitting_app_data(QUIC_STREAM *stream,
                                      void *data, size_t data_len);
```

### TLS Handshake Record Layer

Uses the Record Layer API to implement the inner TLS-1.3 protocol handshake.
It produces the QUIC crypto frames which are queued using the same mechanism
as the [Stream Send Buffers](#stream-send-buffers) above.

### Flow Controller and Statistics Collector

To make decisions about what frames to coalesce, the packetiser relies
on the flow controller to enforce stream and connection bandwidth limits
[RFC 9000 4.1 Data Flow Control].

```c
/*
 * Return the maximum amount of data that is permitted for the given stream.
 * This includes both the stream limit and it's associated connection limit.
 */
size_t ossl_quic_stream_flow_maximum_size(QUIC_STREAM *stream);

/*
 * Inform the flow controller that an amount of data has been queued for
 * sending to a stream.
 */
int ossl_quic_flow_controller_sent_data(QUIC_FLOW_CONTROLLER *flow,
                                        QUIC_STREAM *stream, size_t bytes);
```

### Congestion Controller

Also part of the frame coalescing decision is the congestion controller
[RFC 9002].  For MVP, this will be a _just send it_.

```c
/*
 * Pluggable congestion controller APIs go here
 * Extract that is required from #18018
 */
```

### QUIC Write Record Layer

Coalesced frames are passed to the QUIC record layer for encryption and sending.
To send accumulated frames as packets to the QUIC Write Record Layer:

```c
int ossl_qtx_write_pkt(OSSL_QTX *qtx, const OSSL_QTX_PKT *pkt);
```

The packetiser will attempt to maximise the number of bytes in a packet.
It will also attempt to create multiple packets to send simultaneously.

The packetiser should also implement a wait time to allow more data to
accumulate before exhausting it's supply of data.  The length of the wait
will depend on how much data is queue already and how much space remains in
the packet being filled.  Once the wait is finished, the packets will be sent
by calling:

```c
void ossl_qtx_flush_net(OSSL_QTX *qtx);
```

The write record layer is responsible for coalescing multiple QUIC packets
into datagrams.

### ACK Handling and Loss Detector

1. When a packet is sent, the packetiser needs to inform the ACK Manager.
2. When a packet is ACKed, inform packetiser so it can drop sent frames.
3. When a packet is lost, inform packetiser to create retransmission packet(s).
4. When a packet is discarded without ACK/loss, inform packetiser to clean up.

```c
int ossl_ackm_on_tx_packet(OSSL_ACKM *ackm, OSSL_ACKM_TX_PKT *pkt)
int ossl_quic_packet_acked(OSSL_QUIC_TX_PACKETISER *tx,
                           OSSL_QUIC_PACKET *packet);
int ossl_quic_packet_lost(OSSL_QUIC_TX_PACKETISER *tx,
                          OSSL_QUIC_PACKET *packet);
int ossl_quic_packet_discarded(OSSL_QUIC_TX_PACKETISER *tx,
                               OSSL_QUIC_PACKET *packet);
```

#### Notes

| Name here | Name in ACK Manager |
| --- | --- |
| `ossl_quic_packet_sent` | `QUIC_ACKM_on_tx_ack_packet` |
| `ossl_quic_packet_acked` | `on_acked` |
| `ossl_quic_packet_lost` | `on_lost` |
| `ossl_quic_packet_discarded` | `on_discarded` |

Packets
-------

Packets formats are defined in [RFC 9000 17.1 Packet Formats].

### Packet types

QUIC supports a number of different packets.  The combination of packets of
different types as per [RFC 9000 12.2 Coalescing Packets], is done by the
record layer.

#### Version Negotiation Packet

Refer to [RFC 9000 17.2.1 Version Negotiation Packet].

#### Initial Packet

Refer to [RFC 9000 17.2.2 Initial Packet].

#### Handshake Packet

Refer to [RFC 9000 17.2.4 Handshake Packet].

#### App Data 0-RTT Packet

Refer to [RFC 9000 17.2.3 0-RTT].

#### App Data 1-RTT Packet

Refer to [RFC 9000 17.3.1 1-RTT].

#### Retry Packet

Refer to [RFC 9000 17.2.5 Retry Packet.

Packetisation and Processing
----------------------------

### Application data frames

The packetiser builds application data frames after requesting a specific
amount of application data.  If insufficient data is available, or buffer
boundaries prevent fulfilling the entire request, the stream send buffer module
is free to return a smaller amount of data.

### Retransmission

When a packet is determined to be lost by the ACK Manager, the
`ossl_quic_packet_lost()` function will be called.  This function will
extract the frame references from the packet and re-queue them for
transmission as if `ossl_quic_packetiser_buffer_frame()` had been called
for each
frame followed by `ossl_quic_packetiser_send_packets()`.  Frames that need to be
retransmitted will be be considered higher priority than other pending
frames, although both types are available to construct packets from.
Moreover, any such constructed packets will not be subject to a delay
before transmission.

### Restricting packet sizes

Three factors impact the size of packets that can be sent:

* MTU restricting packet sizes
* Flow control
* Congestion control

The MTU limits the size of an individual packet, the other two limit the
total amount of data that can be sent.  The packetiser needs to query the
current limits using the `ossl_quic_stream_flow_maximum_size()`,
`get_send_allowance()` and `get_data_mtu()` calls.

The packetiser will prioritise sending [`C`](#spec) spec packets together
in order to maximise the amount of data available for the application.

### Stateless Reset

Refer to [RFC 9000 10.3 Stateless Reset].  It's entirely reasonable for
the state machine to send this directly and immediately if required.

[RFC 9000 2.3 Stream Prioritization]: https://datatracker.ietf.org/doc/html/rfc9000#section-2.3
[RFC 9000 4.1 Data Flow Control]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
[RFC 9000 10.3 Stateless Reset]: https://datatracker.ietf.org/doc/html/rfc9000#section-10.3
[RFC 9000 12.2 Coalescing Packets]: https://datatracker.ietf.org/doc/html/rfc9000#section-12.2
[RFC 9000 12.4 Frames and Frame Types]: https://datatracker.ietf.org/doc/html/rfc9000#section-12.4
[RFC 9000 13.3 Retransmission of Information]: https://datatracker.ietf.org/doc/html/rfc9000#section-13.3
[RFC 9000 17.1 Packet Formats]: https://datatracker.ietf.org/doc/html/rfc9000#section-17
[RFC 9000 17.2.1 Version Negotiation Packet]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.1
[RFC 9000 17.2.2 Initial Packet]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
[RFC 9000 17.2.3 0-RTT]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.3
[RFC 9000 17.2.4 Handshake Packet]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.4
[RFC 9000 17.2.5 Retry Packet]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.5
[RFC 9000 17.3.1 1-RTT]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.3.1
[RFC 9002]: https://datatracker.ietf.org/doc/html/rfc9002
