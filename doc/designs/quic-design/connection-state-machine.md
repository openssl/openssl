QUIC Connection State Machine
=============================

FSM Model
---------

QUIC client-side connection state can be broken down into five coarse phases of
a QUIC connection:

- The Idle substate (which is simply the state before we have started trying to
  establish a connection);
- The Active state, which comprises two substates:
    - The Establishing state, which comprises many different substates;
    - The Open state;
- The Terminating state, which comprises several substates;
- The Terminated state, which is the terminal state.

There is monotonic progression through these phases.

These names have been deliberately chosen to use different terminology to common
QUIC terms such as 'handshake' to avoid confusion, as they are not the same
concepts. For example, the Establishing state uses Initial, Handshake and 1-RTT
packets.

This discussion is (currently) given from the client side perspective only.
State machine considerations only relevant to servers are not mentioned.
0-RTT is also not currently modelled in this analysis.

The synthesis of this FSM is not suggested by the QUIC RFCs but has been
discerned from the requirements imposed. This does not mean that the
implementation of this FSM as literally presented below is an optimal or
advisable implementation strategy, and a cursory examination of existing QUIC
implementations suggests that such an approach is not common. Moreover, excess
attention should not be given to the Open state, as 1-RTT application
communication can occur even still in the Establishing state (for example, when
the handshake has been completed but not yet confirmed).

However, the state machine described herein is helpful as an aid to
understanding and broadly captures the logic which our implementation will
embody. The design of the actual implementation is discussed further below.

The above states and their substates are defined as follows:

- The Establishing state involves the use of Initial and Handshake
  packets. It is terminated when the handshake is confirmed.

  Handshake confirmation is not the same as handshake completion.
  Handshake confirmation occurs on the client when it receives
  a `HANDSHAKE_DONE` frame (which occurs in a 1-RTT packet, thus
  1-RTT packets are also invoked in the Establishing state).
  On the server, handshake confirmation occurs as soon as
  the handshake is considered completed (see RFC 9001 s. 4.1).

  The Establishing state is subdivided into the following substates:

   - Proactive Version Negotiation (optional): The client sends
     a Version Negotiation packet with a reserved version number
     to forcibly elicit a list of the server's supported versions.
     This is not expected to be commonly used, as it adds a round trip.

     If it is used, the time spent in this state is based on waiting for
     the server to respond, and potentially retransmitting after a
     timeout.

   - Pre-Initial: The client has completed proactive version negotiation
     (if it performed it), but has not yet sent any encrypted packet. This
     substate is included for exposition; no time will generally be spent in it
     and there is immediate transmission of the first encrypted packet and
     transition to Initial Exchange A.

   - Initial Exchange A: The client has sent at least one Initial
     packet to the server attempting to initiate a connection.

     The client is waiting for a server response, which might
     be:
       - a Version Negotiation packet (leading to the Reactive Version
                                       Negotiation state);
       - a Retry packet     (leading to Initial Exchange B); or
       - an Initial packet  (leading to the Initial Exchange Confirmed state).

   - Reactive Version Negotiation: The server has rejected the client's
     proposed version. If proactive version negotiation was used, this
     can be considered an error. Otherwise, we return to the Pre-Initial
     state and proceed as though proactive version negotiation was
     performed using the information in the version negotiation packet.

   - Initial Exchange B: The client has been asked to perform a Retry.
     It sends at least one Initial packet to the server attempting to
     initiate a connection. Every Initial packet contains the quoted Retry
     Token. Any data sent in `CRYPTO` frames in Initial Exchange A must be
     retransmitted, but PNs MUST NOT be reset. Note that this is still
     considered part of the same connection, and QUIC Transport Parameters are
     later used to cryptographically bind the established connection state to
     the original DCIDs used as part of the Retry process. A server is not
     allowed to respond to a Retry-triggered Initial exchange with another
     Retry, and if it does we ignore it, which is the major distinction of this
     state from Initial Exchange A.

     The client is waiting for a server response, which might be:
       - a Version Negotiation packet (invalid, ignored);
       - a Retry packet               (invalid, ignored);
       - an Initial packet    (leading to the Initial Exchange Continued
                               state);

   - Initial Exchange Continued: The client has sent at least one
     Initial packet to the server and received at least one valid Initial packet
     from the server. There is no longer any possibility of a Retry (any such
     packet is ignored) and communications may continue via Initial packets for
     an arbitrarily long period until the handshake layer indicates the
     Handshake EL is ready.

     The client is waiting for server packets, until one of those packets
     causes the handshake layer (whether it is TLS 1.3 or some other
     hypothetical handshake layer) to emit keys for the Handshake EL.
     This will generally occur due to incoming Initial packets containing
     crypto stream segments (in the form of `CRYPTO` frames) which deliver
     handshake layer protocol messages to the handshake layer in use.

   - Handshake: The Handshake EL is now available to the client.
     Either client or server may send the first Handshake packet.

     The client is waiting to receive a Handshake packet from the server.

   - Handshake Continued: The client has received and successfully
     decrypted at least one Handshake packet. The client now discards
     the Initial EL. Communications via the handshake EL may continue for
     an arbitrary period of time.

     The client is waiting to receive more Handshake packets from the
     server to advance the handshake layer and cause it to transition
     to the Handshake Completed state.

   - Handshake Completed: The handshake layer has indicated that it
     considers the handshake completed. For TLS 1.3, this means both
     parties have sent and received (and verified) TLS 1.3 Finished
     messages. The handshake layer must emit keys for the 1-RTT EL
     at this time.

     Though the handshake is not yet confirmed, the client can begin
     sending 1-RTT packets.

     The QUIC Transport Parameters sent by the peer are now authenticated.
     (Though the peer's QUIC Transport Parameters may have been received
      earlier in the handshake process, they are only considered
      authenticated at this point.)

     The client transitions to Handshake Confirmed once either
       - it receives a `HANDSHAKE_DONE` frame in a 1-RTT packet, or
       - it receives acknowledgement of any 1-RTT packet it sent.

     Though this discussion only covers the client state machine, it is worth
     noting that on the server, the handshake is considered confirmed as soon as
     it is considered completed.

   - Handshake Confirmed: The client has received confirmation from
     the server that the handshake is confirmed.

     The principal effect of moving to this state is that the Handshake
     EL is discarded. Key Update is also now permitted for the first
     time.

     The Establishing state is now done and there is immediate transition
     to the Open state.

- The Open state is the steady state of the connection. It is a single state.

  Application stream data is exchanged freely. Only 1-RTT packets are used. The
  Initial, Handshake (and 0-RTT) ELs have been discarded, transport parameters
  have been exchanged, and the handshake has been confirmed.

  The client transitions to

   - the Terminating — Closing state if the local application initiates an
     immediate close (a `CONNECTION_CLOSE` frame is sent);
   - the Terminating — Draining state if the remote peer initiates
     an immediate close (i.e., a `CONNECTION_CLOSE` frame is received);
   - the Terminated state if the idle timeout expires; a `CONNECTION_CLOSE`
     frame is NOT sent;
   - the Terminated state if the peer triggers a stateless reset; a
     `CONNECTION_CLOSE` frame is NOT sent.

- The Terminating state is used when closing the connection.
  This may occur due to an application request or a transport-level
  protocol error.

  Key updates may not be initiated in the Terminating state.

  This state is divided into two substates:

   - The Closing state, used for a locally initiated immediate close. In
     this state, a packet containing a `CONNECTION_CLOSE` frame is
     transmitted again in response to any packets received. This ensures
     that a `CONNECTION_CLOSE` frame is received by the peer even if the
     initially transmitted `CONNECTION_CLOSE` frame was lost. Note that
     these `CONNECTION_CLOSE` frames are not governed by QUIC's normal loss
     detection mechanisms; this is a bespoke mechanism unique to this
     state, which exists solely to ensure delivery of the `CONNECTION_CLOSE`
     frame.

     The endpoint progresses to the Terminated state after a timeout
     interval, which should not be less than three times the PTO interval.

     It is also possible for the endpoint to transition to the Draining
     state instead, if it receives a `CONNECTION_CLOSE` frame prior
     to the timeout expiring. This indicates that the peer is also
     closing.

   - The Draining state, used for a peer initiated immediate close.

     The local endpoint may not send any packets of any kind in this
     state. It may optionally send one `CONNECTION_CLOSE` frame immediately
     prior to entering this state.

     The endpoint progresses to the Terminated state after a timeout
     interval, which should not be less than three times the PTO interval.

- The Terminated state is the terminal state of a connection.
  Regardless of how a connection ends (local or peer-initiated immediate close,
  idle timeout, stateless reset), a connection always ultimately ends up in this
  state. There is no longer any requirement to send or receive any packet. No
  timer events related to the connection will ever need fire again. This is a
  totally quiescent state. The state associated with the connection may now be
  safely freed.

We express this state machine in more concrete form in the form of a table,
which makes the available transitions clear:

† Except where superceded by a more specific transition

ε means “where no other transition is applicable”.

Where an action is specified in the Transition/Action column but no new state,
no state change occurs.

<table>
<tr><th>State</th><th>Action On Entry/Exit</th><th>Event</th><th>Transition/Action</th></tr>
<tr>
  <td rowspan="2"><tt>IDLE</tt></td>
  <td rowspan="2"></td>
  <td>—<tt>APP:CONNECT</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.PROACTIVE_VER_NEG</tt> (if used), else
  <tt>ACTIVE.ESTABLISHING.PRE_INITIAL</tt></td>
</tr>
<tr>
  <td>—<tt>APP:CLOSE</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>
<tr>
  <td rowspan="5"><tt>ACTIVE</tt></td>
  <td rowspan="5"></td>
  <td>—<tt>IDLE_TIMEOUT</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>
<tr>
  <td>—<tt>PTO_TIMEOUT</tt>→ †</td>
  <td><tt>SendProbeIfAnySentPktsUnacked()</tt></td>
</tr>
<tr>
  <td>—<tt>APP:CLOSE</tt>→ †</td>
  <td><tt>TERMINATING.CLOSING</tt></td>
</tr>
<tr>
  <td>—<tt>RX:ANY[CONNECTION_CLOSE]</tt>→</td>
  <td><tt>TERMINATING.DRAINING</tt></td>
</tr>
<tr>
  <td>—<tt>RX:STATELESS_RESET</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>

<tr>
  <td rowspan="3"><tt>ACTIVE.ESTABLISHING.PROACTIVE_VER_NEG</tt></td>
  <td rowspan="3"><tt>enter:SendReqVerNeg</tt></td>
  <td>—<tt>RX:VER_NEG</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.PRE_INITIAL</tt></td>
</tr>
<tr>
  <td>—<tt>PTO_TIMEOUT</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.PROACTIVE_VER_NEG</tt> (retransmit)</td>
</tr>
<tr>
  <td>—<tt>APP:CLOSE</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>
<tr>
  <td rowspan="1"><tt>ACTIVE.ESTABLISHING.PRE_INITIAL</tt></td>
  <td rowspan="1"></td>
  <td>—ε→</td>
  <td><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_A</tt></td>
</tr>
<tr>
  <td rowspan="4"><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_A</tt></td>
  <td rowspan="4"><tt>enter:SendPackets()</tt> (First Initial)</td>
  <td>—<tt>RX:RETRY</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_B</tt></td>
</tr>
<tr>
  <td>—<tt>RX:INITIAL</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_CONTINUED</tt></td>
</tr>
<tr>
  <td>—<tt>RX:VER_NEG</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.REACTIVE_VER_NEG</tt></td>
</tr>
<tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td rowspan="1"><tt>ACTIVE.ESTABLISHING.REACTIVE_VER_NEG</tt></td>
  <td rowspan="1"></td>
  <td>—ε→</td>
  <td><tt>ACTIVE.ESTABLISHING.PRE_INITIAL</tt></td>
</tr>
<tr>
  <td rowspan="3"><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_B</tt></td>
  <td rowspan="3"><tt>enter:SendPackets()</tt><br/>
    (First Initial, with token)<br/>
    (*All further Initial packets contain the token)<br/>(*PN is not reset)</td>
  <td>—<tt>RX:INITIAL</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_CONTINUED</tt></td>
</tr>
<tr>
  <td>—<tt>PTO_TIMEOUT</tt>→</td>
  <td>TODO: Tail loss probe for initial packets?</td>
</tr>
<tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td rowspan="2"><tt>ACTIVE.ESTABLISHING.INITIAL_EXCHANGE_CONTINUED</tt></td>
  <td rowspan="2"><tt>enter:SendPackets()</tt></td>
  <td>—<tt>RX:INITIAL</tt>→</td>
  <td>(packet processed, no change)</td>
</tr>
<tr>
  <td>—<tt>TLS:HAVE_EL(HANDSHAKE)</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.HANDSHAKE</tt></td>
</tr>
<tr>
  <td rowspan="3"><tt>ACTIVE.ESTABLISHING.HANDSHAKE</tt></td>
  <td rowspan="3"><tt>enter:ProvisionEL(Handshake)</tt><br/>
  <tt>enter:SendPackets()</tt> (First Handshake packet, if pending)</td>
  <td>—<tt>RX:HANDSHAKE</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.HANDSHAKE_CONTINUED</tt></td>
</tr>
<tr>
  <td>—<tt>RX:INITIAL</tt>→</td>
  <td>(packet processed if EL is not dropped)</td>
</tr>
<tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td rowspan="3"><tt>ACTIVE.ESTABLISHING.HANDSHAKE_CONTINUED</tt></td>
  <td rowspan="3"><tt>enter:DropEL(Initial)</tt><br/><tt>enter:SendPackets()</tt></td>
  <td>—<tt>RX:HANDSHAKE</tt>→</td>
  <td>(packet processed, no change)</td>
</tr>
<tr>
  <td>—<tt>TLS:HANDSHAKE_COMPLETE</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.HANDSHAKE_COMPLETE</tt></td>
</tr>
 <tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td rowspan="3"><tt>ACTIVE.ESTABLISHING.HANDSHAKE_COMPLETED</tt></td>
  <td rowspan="3"><tt>enter:ProvisionEL(1RTT)</tt><br/><tt>enter:HandshakeComplete()</tt><br/><tt>enter[server]:Send(HANDSHAKE_DONE)</tt><br/><tt>enter:SendPackets()</tt></td>
  <td>—<tt>RX:1RTT[HANDSHAKE_DONE]</tt>→</td>
  <td><tt>ACTIVE.ESTABLISHING.HANDSHAKE_CONFIRMED</tt></td>
</tr>
<tr>
  <td>—<tt>RX:1RTT</tt>→</td>
  <td>(packet processed, no change)</td>
</tr>
 <tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td rowspan="1"><tt>ACTIVE.ESTABLISHING.HANDSHAKE_CONFIRMED</tt></td>
  <td rowspan="1"><tt>enter:DiscardEL(Handshake)</tt><br/><tt>enter:Permit1RTTKeyUpdate()</tt></td>
  <td>—ε→</td>
  <td><tt>ACTIVE.OPEN</tt></td>
</tr>
<tr>
  <td rowspan="2"><tt>ACTIVE.OPEN</tt></td>
  <td rowspan="2"></td>
  <td>—<tt>RX:1RTT</tt>→</td>
  <td>(packet processed, no change)</td>
</tr>
<tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td><tt>TERMINATING</tt></td>
  <td></td>
  <td>—<tt>TERMINATING_TIMEOUT</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>
<tr>
  <td rowspan="4"><tt>TERMINATING.CLOSING</tt></td>
  <td rowspan="4"><tt>enter:QueueConnectionCloseFrame()</tt><br/><tt>enter:SendPackets()</tt></td>
  <td>—<tt>RX:ANY[CONNECTION_CLOSE]</tt>→</td>
  <td><tt>TERMINATING.DRAINING</tt></td>
</tr>
<tr>
  <td>—<tt>RX:ANY</tt>→</td>
  <td><tt>QueueConnectionCloseFrame()</tt><br/><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td>—<tt>CAN_SEND</tt>→</td>
  <td><tt>SendPackets()</tt></td>
</tr>
<tr>
  <td>—<tt>RX:STATELESS_RESET</tt>→</td>
  <td><tt>TERMINATED</tt></td>
</tr>
<tr>
  <td rowspan="1"><tt>TERMINATING.DRAINING</tt></td>
  <td rowspan="1"></td>
  <td></td>
  <td></td>
</tr>
<tr>
  <td rowspan="1"><tt>TERMINATED</tt></td>
  <td rowspan="1"></td>
  <td>[terminal state]</td>
  <td></td>
</tr>
</table>

Notes on various events:

- `CAN_SEND` is raised when transmission of packets has been unblocked after previously
  having been blocked. There are broadly two reasons why transmission of packets
  may not have been possible:

  - Due to OS buffers or network-side write BIOs being full;
  - Due to limits imposed by the chosen congestion controller.

  `CAN_SEND` is expected to be raised due to a timeout prescribed by the
  congestion controller or in response to poll(2) or similar notifications, as
  abstracted by the BIO system and how the application has chosen to notify
  libssl of network I/O readiness.

  It is generally implied that processing of a packet as mentioned above
  may cause new packets to be queued and sent, so this is not listed
  explicitly in the Transition column except for the `CAN_SEND` event.

- `PTO_TIMEOUT` is raised after the PTO interval and stimulates generation
  of a tail loss probe.

- `IDLE_TIMEOUT` is raised after the connection idle timeout expires.
  Note that the loss detector only makes a determination of loss due to an
  incoming ACK frame; if a peer becomes totally unresponsive, this is the only
  mechanism available to terminate the connection (other than the local
  application choosing to close it).

- `RX:STATELESS_RESET` indicates receipt of a stateless reset, but note
  that it is not guaranteed that we are able to recognise a stateless reset
  that we receive, thus this event may not always be raised.

- `RX:ANY[CONNECTION_CLOSE]` denotes a `CONNECTION_CLOSE` frame received
  in any non-discarded EL.

- Any circumstance where `RX:RETRY` or `RX:VER_NEG` are not explicitly
  listed means that these packets are not allowed and will be ignored.

- Protocol errors, etc. can be handled identically to `APP:CLOSE` events
  as indicated in the above table if locally initiated. Protocol errors
  signalled by the peer are handled as `RX:ANY[CONNECTION_CLOSE]` events.

Notes on various actions:

- `SendPackets()` sends packets if we have anything pending for transmission,
  and only to the extent we are able to with regards to congestion control and
  available BIO buffer space, etc.

Non-FSM Model
-------------

Common QUIC implementations appear to prefer modelling connection state as a set
of flags rather than as a FSM. It can be observed above that there is a fair
degree of commonality between many states. This has been modelled above using
hierarchical states with default handlers for common events. [The state machine
can be viewed as a diagram here (large
image).](./images/connection-state-machine.png)

We transpose the above table to sort by events rather than states, to discern
the following list of events:

- `APP:CONNECT`: Supported in `IDLE` state only.

- `RX:VER_NEG`: Handled in `ESTABLISHING.PROACTIVE_VER_NEG` and
  `ESTABLISHING.INITIAL_EXCHANGE_A` only, otherwise ignored.

- `RX:RETRY`: Handled in `ESTABLISHING.INITIAL_EXCHANGE_A` only.

- `PTO_TIMEOUT`: Applicable to `OPEN` and all (non-ε) `ESTABLISHING`
  substates. Handled via `SendProbeIfAnySentPktsUnacked()` except in the
  `ESTABLISHING.PROACTIVE_VER_NEG` state, which reenters that state to trigger
  retransmission of a Version Negotiation packet.

- `IDLE_TIMEOUT`: Applicable to `OPEN` and all (non-ε) `ESTABLISHING` substates.
  Action: immediate transition to `TERMINATED` (no `CONNECTION_CLOSE` frame
  is sent).

- `TERMINATING_TIMEOUT`: Timeout used by the `TERMINATING` state only.

- `CAN_SEND`: Applicable to `OPEN` and all (non-ε) `ESTABLISHING`
  substates, as well as `TERMINATING.CLOSING`.
  Action: `SendPackets()`.

- `RX:STATELESS_RESET`: Applicable to all `ESTABLISHING` and `OPEN` states and
  the `TERMINATING.CLOSING` substate.
  Always causes a direct transition to `TERMINATED`.

- `APP:CLOSE`: Supported in `IDLE`, `ESTABLISHING` and `OPEN` states.
  (Reasonably a no-op in `TERMINATING` or `TERMINATED.`)

- `RX:ANY[CONNECTION_CLOSE]`: Supported in all `ESTABLISHING` and `OPEN` states,
  as well as in `TERMINATING.CLOSING`. Transition to `TERMINATING.DRAINING`.

- `RX:INITIAL`, `RX:HANDSHAKE`, `RX:1RTT`: Our willingness to process these is
  modelled on whether we have an EL provisioned or discarded, etc.; thus
  this does not require modelling as additional state.

  Once we successfully decrypt a Handshake packet, we stop processing Initial
  packets and discard the Initial EL, as required by RFC.

- `TLS:HAVE_EL(HANDSHAKE)`: Emitted by the handshake layer when Handshake EL
  keys are available.

- `TLS:HANDSHAKE_COMPLETE`: Emitted by the handshake layer when the handshake
  is complete. Implies connection has been authenticated. Also implies 1-RTT EL
  keys are avilable. Whether the handshake is complete, and also whether i  is
  confirmed, is reasonably implemented as a flag.

From here we can discern state dependence of different events:

  - `APP:CONNECT`: Need to know if application has invoked this event yet,
    as if so it is invalid.

    State: Boolean: Connection initiated?

  - `RX:VER_NEG`: Only valid if we have not yet received any successfully
    processed encrypted packet from the server.

  - `RX:RETRY`: Only valid if we have sent an Initial packet to the server,
    have not yet received any successfully processed encrypted packet
    from the server, and have not previously been asked to do a Retry as
    part of this connection (and the Retry Integrity Token validates).

    Action: Note that we are now acting on a retry and start again.
    Do not reset packet numbers. The original CIDs used for the first
    connection attempt must be noted for later authentication in
    the QUIC Transport Parameters.

    State: Boolean: Retry requested?

    State: CID: Original SCID, DCID.

  - `PTO_TIMEOUT`: If we have sent at least one encrypted packet yet,
    we can handle this via a standard probe-sending mechanism. Otherwise, we are
    still in Proactive Version Negotiation and should retransmit the Version
    Negotiation packet we sent.

    State: Boolean: Doing proactive version negotiation?

  - `IDLE_TIMEOUT`: Only applicable in `ACTIVE` states.

    We are `ACTIVE` if a connection has been initiated (see `APP:CONNECT`) and
    we are not in `TERMINATING` or `TERMINATED`.

  - `TERMINATING_TIMEOUT`: Timer used in `TERMINATING` state only.

  - `CAN_SEND`: Stimulates transmission of packets.

  - `RX:STATELESS_RESET`: Always handled unless we are in `TERMINATED`.

  - `APP:CLOSE`: Usually causes a transition to `TERMINATING.CLOSING`.

  - `RX:INITIAL`, `RX:HANDSHAKE`, `RX:1RTT`: Willingness to process
    these is implicit in whether we currently have the applicable EL
    provisioned.

  - `TLS:HAVE_EL(HANDSHAKE)`: Handled by the handshake layer
    and forwarded to the record layer to provision keys.

  - `TLS:HANDSHAKE_COMPLETE`: Should be noted as a flag and notification
    provided to various components.

We choose to model the CSM's state as follows:

  - The `IDLE`, `ACTIVE`, `TERMINATING.CLOSED`, `TERMINATING.DRAINED` and
    `TERMINATED` states are modelled explicitly as a state variable. However,
    the substates of `ACTIVE` are not explicitly modelled.

  - The following flags are modelled:
    - Retry Requested? (+ Original SCID, DCID if so)
    - Have Sent Any Packet?
    - Are we currently doing proactive version negotiation?
    - Have Successfully Received Any Encrypted Packet?
    - Handshake Completed?
    - Handshake Confirmed?

  - The following timers are modelled:
    - PTO Timeout
    - Terminating Timeout
    - Idle Timeout

Implementation Plan
-------------------

- Phase 1: “Steady state only” model which jumps to the `ACTIVE.OPEN`
  state with a hardcoded key.

  Test plan: Currently uncertain, to be determined.

- Phase 2: “Dummy handshake” model which uses a one-byte protocol
  as the handshake layer as a standin for TLS 1.3. e.g. a 0x01 byte “represents”
  a ClientHello, a 0x02 byte “represents” a ServerHello. Keys are fixed.

  Test plan: If feasible, an existing QUIC implementation will be modified to
  use this protocol and E2E testing will be performed against it. (This
  can probably be done quickly but an alternate plan may be required if
  the effort needed turns out be excessive.)

- Phase 3: Final model with TLS 1.3 handshake layer fully plumbed in.

  Test plan: Testing against real world implementations.

Handling of Network I/O
-----------------------

Our API objectives make handling network I/O tricky.
Broadly speaking:

 - We want to support both blocking and non-blocking semantics
   for application use of the libssl APIs.

 - In the case of non-blocking applications, it must be possible
   for an application to do its own polling and make its own event
   loop.

Moreover, traditional use of the libssl API allows an application to pass an
arbitrary BIO to an SSL object; not only that, separate BIOs can be passed for
the read and write directions. The nature of this BIO can be arbitrary; it could
be a socket, or a memory buffer.

Implementation of QUIC requires handling of timer events as well as the
circumstances where a network socket becomes readable or writable. In many cases
we need to handle these events simultaneously (e.g. wait until a socket becomes
readable, or a timeout expires, whichever comes first).

### Use of non-blocking I/O

These requirements make it more or less a requirement that we use non-blocking
network I/O; we need to be able to (at a minimum) have timeouts on recv() calls,
and make best effort (non blocking) send() and recv() calls.

The only sensible way to do this portably is to configure the socket into
non-blocking mode. We could try to do a select() before calling send() or recv()
to get a guarantee that the call will not block, but this will probably run into
issues with buggy OSes which generate spurious socket readiness events. In any
case, relying on this to work reliably is not advisable.

Timeouts could be handled via setsockopt() socket timeout options, but this
depends on OS support and adds another syscall to every network I/O operation.
It also has obvious thread safety concerns if we want to move to concurrent use
of a single socket at some later date.

Some OSes support a `MSG_DONTWAIT` flag which allows a single I/O option to be
made non-blocking. However some OSes (e.g. Windows) do not support this, so we
cannot rely on this.

As such, we need to configure any socket FD we use into non-blocking mode. This
may confound users who pass a blocking socket to libssl. For most users however,
it would be unusual for a user to pass an FD to us, then also try to send and
receive traffic on the same socket. (There are some circumstances where this may
occur, however; the fixed bit in the QUIC packet header may allow protocol
multiplexing, for example with other protocols like RTP/RTCP or STUN. A
dedicated analysis to the requirements for supporting such applications should
probably be done to support this after MVP. In general, it is unlikely that such
applications will use blocking I/O anyway.)

As such, the impact on applications of this behaviour is limited and can be
documented.

Note that this is orthogonal to whether we provide blocking I/O semantics to the
application. While we use non-blocking I/O internally, this can be used to
provide either blocking or non-blocking semantics to the application, based on
what the application requests.

### Support of arbitrary BIOs

However, we need to support not just socket FDs but arbitrary BIOs as the basis
for the use of QUIC. Support for using QUIC with e.g. BIO_dgram_pair, a
bidirectional memory buffer with datagram semantics, is to be supported as part
of MVP. This must be rectified with the desire to support application-managed
event loops.

Broadly, the intention so far has been to enable the use of QUIC with an
application event loop by exposing an appropriate OS-level synchronisation
primitive to the application. On \*NIX platforms, this essentially means we
provide the application with:

  - An FD which should be polled for readability, writability, or both;
  - A deadline (if any is currently applicable).

Once either of these conditions is met, the QUIC state machine can be
(potentially) advanced meaningfully, and the application is expected to reenter
the QUIC state machine by calling `SSL_tick()` (or `SSL_read()` or
`SSL_write()`).

This model is readily supported when the read and write BIOs we are provided
with are socket BIOs:

  - The read-pollable FD is the FD of the read BIO.
  - The write-pollable FD is the FD of the write BIO.

However, things become more complex when we are dealing with memory-based BIOs
such as `BIO_dgram_pair` which do not naturally correspond to any OS primitive
which can be used for synchronisation, or when we are dealing with an
application-provided custom BIO.

### Pollable and Non-Pollable BIOs

In order to accommodate these various cases, we draw a distinction between
pollable and non-pollable BIOs.

  - A pollable BIO is a BIO which can provide some kind of OS-level
    synchronisation primitive, which can be used to determine when
    the BIO might be able to do useful work once more.

  - A non-pollable BIO has no naturally associated OS-level synchronisation
    primitive, but its state only changes in response to calls made to it (or to
    a related BIO, such as the other end of a pair).

#### Supporting Pollable BIOs

“OS-level synchronisation primitive” is deliberately vague. Most modern OSes use
unified handle spaces (UNIX, Windows) though it is likely there are more obscure
APIs on these platforms which have other handle spaces. However, this
unification is not necessarily significant.

For example, Windows sockets are kernel handles and thus like any other object
they can be used with the generic Win32 `WaitForSingleObject()` API, but not in
a useful manner; the generic readiness mechanism for WIndows handles is not
plumbed in for socket handles, and so sockets are simply never considered ready
for the purposes of this API, which will never return. Instead, the
WinSock-specific `select()` call must be used. On the other hand, other kinds of
synchronisation primitive like a Win32 Event must use `WaitForSingleObject()`.

Thus while in theory most modern operating systems have unified handle spaces in
practice there are substantial usage differences between different handle types.
As such, an API to expose a synchronisation primitive should probably be of a
tagged union design supporting possible variation.

An SSL object will provide methods to retrieve a pollable OS-level
synchronisation primitive which can be used to determine when the QUIC state
machine can (potentially) do more work. In order to maintain the integrity of
the BIO abstraction layer, an equivalent set of methods is added to the BIO API.

Such a possible design could be:

```c
#define BIO_POLL_DESCRIPTOR_TYPE_NONE        0
#define BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD     1

typedef struct bio_poll_descriptor_st {
    int type;
    union {
        int fd;
    } value;
} BIO_POLL_DESCRIPTOR;

int BIO_get_rpoll_descriptor(BIO *ssl, BIO_POLL_DESCRIPTOR *desc);
int BIO_get_wpoll_descriptor(BIO *ssl, BIO_POLL_DESCRIPTOR *desc);

int SSL_get_rpoll_descriptor(SSL *ssl, BIO_POLL_DESCRIPTOR *desc);
int SSL_get_wpoll_descriptor(SSL *ssl, BIO_POLL_DESCRIPTOR *desc);
```

Currently only a single descriptor type is defined, which is a FD on \*NIX and a
Winsock socket handle on Windows. These use the same type to minimise code
changes needed on different platforms in the common case of an OS network
socket. (Use of an `int` here is strictly incorrect for Windows; however, this
style of usage is prevalent in the OpenSSL codebase, so for consistency we
continue the pattern here.)

For `BIO_s_ssl`, the `BIO_get_[rw]poll_descriptor` functions are equivalent to
the `SSL_get_[rw]poll_descriptor` functions. The `SSL_get_[rw]poll_descriptor`
functions are equivalent to calling `BIO_get_[rw]poll_descriptor` on the
underlying BIOs provided to the SSL object. For a socket BIO, this will likely
just yield the socket's FD. For memory-based BIOs, see below.

The following APIs return boolean values which indicate whether readability and
writability are currently desired:

```c
int SSL_want_net_read(SSL *ssl);
int SSL_want_net_write(SSL *ssl);
```

The following API yields a current deadline (if any) after which the QUIC state
machine should be ticked:

```c
/* Returns milliseconds or -1 (infinity). */
int64_t SSL_get_tick_timeout(SSL *ssl);
```

Finally, the tick function allows the QUIC state machine to be ticked without
performing any specific operation:

```c
int SSL_tick(SSL *ssl);
```

Equivalent BIO methods will be defined for each of the above.

#### Supporting Non-Pollable BIOs

Where we are provided with a non-pollable BIO, we cannot provide the application
with any primitive used for synchronisation and it is assumed that the
application will handle its own network I/O, for example via a `BIO_dgram_pair`.

When libssl calls `BIO_get_[rw]poll_descriptor` on the underlying BIO, the call
fails, indicating that a non-pollable BIO is being used. Thus, if an application
calls `SSL_get_[rw]poll_descriptor`, that call also fails.

`SSL_get_tick_timeout` is still functional and must be handled by the
application.

There are various circumstances which need to be handled:

  - The QUIC implementation wants to write data to the network but
    is currently unable to (e.g. `BIO_dgram_pair` is full).

    This is not hard as our internal TX record layer allows arbitrary buffering.
    The only limit comes when QUIC flow control (which only applies to
    application stream data) applies a limit; then we must return
    `SSL_ERROR_WANT_WRITE`.

  - The QUIC implementation wants to read data from the network
    but is currently unable to (e.g. `BIO_dgram_pair` is empty).

    Here we need to return `SSL_ERROR_WANT_READ`; we thereby support libssl's
    classic nonblocking I/O interface.

### Configuration of Blocking vs. Non-Blocking Mode

Traditionally an SSL object has operated either in blocking mode or non-blocking
mode without requiring explicit configuration; if a socket returns EWOULDBLOCK
or similar, it is handled appropriately, and if a socket call blocks, there is
no issue. Since the QUIC implementation is building on non-blocking I/O, this
implicit configuration of non-blocking mode is not feasible.

Note that Windows does not have an API for determining whether a socket is in
blocking mode, so it is not possible to use the initial state of an underlying
socket to determine if the application wants to use non-blocking I/O or not.
Moreover this would undermine the BIO abstraction.

As such, an explicit call is introduced to configure an SSL (QUIC) object into
non-blocking mode:

```c
int SSL_set_blocking_mode(SSL *s, int blocking);
int SSL_get_blocking_mode(SSL *s);
```

Applications desiring non-blocking operation will need to call this API to
configure a new QUIC connection accordingly. Blocking mode is chosen as the
default for parity with traditional Berkeley sockets APIs and to make things
simpler for blocking applications, which are likely to be seeking a simpler
solution. However, blocking mode cannot be supported with a non-pollable BIO,
and thus blocking mode defaults to off when used with such a BIO.

A method is also needed for the QUIC implementation to inform an underlying BIO
that it *must not* block. The SSL object will call this function when it is
provided with an underlying BIO. For a socket BIO this can set the socket as
non-blocking; for a memory-based BIO it is a no-op; for `BIO_s_ssl` it is
equivalent to a call to `SSL_set_blocking_mode()`.

### Internal Polling

When blocking mode is configured, the QUIC implementation will call
`BIO_get_[rw]poll_descriptor` on the underlying BIOs and use a suitable OS
function (e.g. `select()`) to block. This will be implemented by an internal
function which can accept up to two poll descriptors (one for the read BIO, one
for the write BIO), which might be identical.

Blocking mode cannot be used with a non-pollable underlying BIO. If
`BIO_get[rw]poll_descriptor` is not implemented for either of the underlying
read and write BIOs, blocking mode cannot be enabled and blocking mode defaults
to off.
