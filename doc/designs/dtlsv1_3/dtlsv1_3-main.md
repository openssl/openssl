DTLS 1.3 Design
===============

This page presents an overview of the design rationale for the DTLSv1.3
(RFC 9147) implementation in OpenSSL.

Objectives
----------

* A user should be able to establish a DTLSv1.3 connection through the same
  apis as previous versions of DTLS.
* MUSTs, SHALLs and REQUIREDs of RFC 9147 are implemented.
* Implementation details of OPTIONALs, SHOULDs and MAYs are documented in
  this document.

Implementation details
----------------------

This section describes the implementation of optional requirements of DTLSv1.3
(RFC 9147).

### DTLSv1.0 support

RFC 9147 recommends to drop DTLSv1.0 support but OpenSSL will continue to
support it for now.

### DTLSv1.3 unified header

A new feature for DTLSv1.3 is the unified header (unified_hdr) (RFC 9147
section 4) of the DTLSCiphertext. OpenSSL supports receiving a DTLSCiphertext
of any format but always formats the header of outgoing DTLSCiphertext's the
same way:

* The C-bit is set to 0. Refer to [DTLSv1.3 connection id](#dtlsv1.3-connection-id)
* The S-bit is set to 1 (sequence numbers are 16-bit)
* The L-bit is set to 1 (length field is present)

Configurability of the unified header fields requires a new api and is marked
as a feature request in issue ###########.

### DTLSv1.3 connection id

OpenSSL does not support Connection ID's (RFC 9146). Notably Openssl DTLSv1.3 clients
will not offer the "connection_id" extension even though RFC 9147 states:

> DTLS clients which do not want to receive a Connection ID SHOULD still offer
> the "connection_id" extension [RFC9146] unless there is an application
> profile to the contrary. This permits a server which wants to receive a CID
> to negotiate one.

Implementation progress
-----------------------

This section contains a summary of the work required to implement DTLSv1.3 for Openssl.
It is basically a condensed version of the RFC.

### Backlog of work items

A summary of larger work items that needs to be addressed.

Notice that some of the requirements mentioned in [List of DTLS 1.3 requirements](#list-of-dtls-13-requirements)
is not covered by these workitems and must be implemented separately.

| Summary                                             | #PR            |
|-----------------------------------------------------|----------------|
| ACK messages                                        | -              |
| Use HelloRetryRequest instead of HelloVerifyRequest | #22985, #22400 |
| Message transcript                                  | -              |
| DTLSv1.3 epoch                                      | -              |
| ClientHello                                         | -              |
| legacy_version                                      | -              |
| EndOfEarlyData message                              | -              |
| Cryptographic Label Prefix                          | #22416         |
| Disable TLS 1.3 "compatibility mode"                | #22379         |
| DTLSv1.3 Fuzzer                                     | -              |

### Changes from DTLS 1.2 and/or TLS 1.3

In general the implementation of DTLSv1.3 reuses much of the same functionality of
TLSv1.3 and DTLSv1.2. This part of the implementation can be considered a
separate work item.

Here follows a collection of changes that need to be implemented.

#### Message Transcript

The message transcript is computed differently from DTLS 1.2 and TLS 1.3:

> In DTLS 1.3, the message transcript is computed over the original TLS 1.3-style
> Handshake messages without the message_seq, fragment_offset, and fragment_length
> values. Note that this is a change from DTLS 1.2 where those values were
> included in the transcript.

#### DTLSCipherText

DTLSCipherText differs from DTLS 1.2 and TLS 1.3:

> The DTLSCiphertext structure omits the superfluous version number and type fields
> ...
> The DTLSCiphertext structure has a variable-length header
> ...
> The entire header value shown in Figure 4 (but prior to record number encryption;
> see Section 4.2.3) is used as the additional data value for the AEAD function
> ...
> In DTLS 1.3 the 64-bit sequence_number is used as the sequence number for the
> AEAD computation; unlike DTLS 1.2, the epoch is not included.

Because of the encrypted sequence number and record number the implementation must
handle them as described in:

> 4.2.2. Reconstructing the Sequence Number and Epoch

And

> 4.2.3. Record Number Encryption

#### DTLSv1.3 epoch

The epoch is maintained differently from DTLS 1.2

> The DTLS epoch ...  is set as the least significant 2 octets of the connection
> epoch, which is an 8 octet counter incremented on every KeyUpdate

#### ClientHello

DTLS adds legacy_cookie which has a forced value. And there are changes to the
random value:

> random: Same as for TLS 1.3, except that the downgrade sentinels ... apply to
> DTLS 1.2 and DTLS 1.0, respectively.

#### legacy_version

The legacy_version field of messages and records is forced to DTLSv1.2 (254,253)

#### EndOfEarlyData message

> the EndOfEarlyData message is omitted both from the wire and the handshake
> transcript

#### Cryptographic Label Prefix

> For DTLS 1.3, that label SHALL be "dtls13"

#### ACK messages

See section 7 and 8 of RFC 9147.

#### Disable TLS 1.3 "compatibility mode"

The middlebox compatibility mode

> DTLS implementations do not use the TLS 1.3 "compatibility mode"

ChangeCipherSpec messages are no longer used.

> endpoints MUST NOT send ChangeCipherSpec messages

### List of DTLS 1.3 requirements

Here's a list of requirements from RFC 9147 together with their implementation status
and associated PR with the relevant implementation.

"TBD" indicates that the implementation is missing. Note there may exist a fix in a PR.

"Yes" indicates that the requirement is already implemented.

"No" indicates that the requirement will not be implemented. For example some requirements only
applies if the implementation supports Connection Id's.

"DTLS 1.2" indicates that the requirement is the same for DTLS 1.2 and is expected to already
have been implemented. "DTLS 1.2?" indicates that this is an optional requirement for DTLS 1.2.

"TLS 1.3" indicates that the requirement is the same for TLS 1.3 and is expected to already
have been implemented.

| Requirement description                                                                                                                                                                 | Implemented? |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Plaintext records MUST NOT be sent with sequence numbers that would exceed 2^48-1                                                                                                       | TBD          |
| [legacy_record_version] MUST be set to {254, 253} for all records other than the initial ClientHello                                                                                    | TBD          |
| [legacy_record_version] MUST be ignored for all purposes                                                                                                                                | TBD          |
| Omitting the length field MUST only be used for the last record in a datagram.                                                                                                          | No           |
| If a Connection ID is negotiated, then it MUST be contained in all datagrams                                                                                                            | No           |
| Sending implementations MUST NOT mix records from multiple DTLS associations in the same datagram                                                                                       | TBD          |
| If the second or later record has a connection ID which does not correspond to the same association used for previous records, the rest of the datagram MUST be discarded               | No           |
| If the first byte is alert(21), handshake(22), or ack(proposed, 26), the record MUST be interpreted as a DTLSPlaintext record                                                           | TBD          |
| If the first byte is any other value, then receivers MUST check to see if the leading bits of the first byte are 001                                                                    | TBD          |
| If so, the implementation MUST process the record as DTLSCiphertext; the true content type will be inside the protected portion                                                         | TBD          |
| Otherwise, the record MUST be rejected as if it had failed deprotection                                                                                                                 | TBD          |
| Implementations MUST send retransmissions of lost messages using the same epoch and keying material as the original transmission                                                        | TBD          |
| Implementations MUST either abandon an association or rekey prior to allowing the sequence number to wrap.                                                                              | DTLS 1.2?    |
| Implementations MUST NOT allow the epoch to wrap, but instead MUST establish a new association, terminating the old association.                                                        | DTLS 1.2     |
| Receivers MUST reject shorter records [Ciphertexts lengths less than 16 bytes] as if they had failed deprotection                                                                       | TBD          |
| Senders MUST pad short plaintexts out                                                                                                                                                   | TBD          |
| cipher suites, which are not based on AES or ChaCha20, MUST define their own record sequence number encryption in order to be used with DTLS                                            | N/A          |
| Each DTLS record MUST fit within a single datagram                                                                                                                                      | DTLS 1.2     |
| The first byte of the datagram payload MUST be the beginning of a record                                                                                                                | DTLS 1.2     |
| Records MUST NOT span datagrams                                                                                                                                                         | DTLS 1.2     |
| [For DTLS over TCP or SCTP] the upper layer protocol MUST NOT write any record that exceeds the maximum record size of 2^14 bytes                                                       | DTLS 1.2     |
| [If there is a transport protocol indication that the PMTU was exceeded] then the DTLS record layer MUST inform the upper layer protocol of the error                                   | DTLS 1.2     |
| The received record counter for an epoch MUST be initialized to zero when that epoch is first used.                                                                                     | TBD          |
| For each received record, the receiver MUST verify that the record contains a sequence number that does not duplicate the sequence number of any other record                           | DTLS 1.2     |
| The window MUST NOT be updated due to a received record until that record has been deprotected successfully                                                                             | DTLS 1.2     |
| Implementations which choose to generate an alert [for invalid records] instead MUST generate fatal alerts                                                                              | TBD          |
| Implementations MUST count the number of received packets that fail authentication with each key.                                                                                       | TBD          |
| Therefore, TLS_AES_128_CCM_8_SHA256 MUST NOT be used in DTLS without additional safeguards against forgery.                                                                             | No           |
| Implementations MUST set usage limits for AEAD_AES_128_CCM_8 based on an understanding of any additional forgery protections that are used.                                             | TBD          |
| Any TLS cipher suite that is specified for use with DTLS MUST define limits on the use of the associated AEAD function                                                                  | N/A          |
| DTLS servers MUST NOT echo the "legacy_session_id" value from the client                                                                                                                | TBD          |
| endpoints MUST NOT send ChangeCipherSpec messages                                                                                                                                       | TBD          |
| The client MUST send a new ClientHello with the cookie added as an extension                                                                                                            | TBD          |
| the legacy_cookie field in the ClientHello message MUST be set to a zero-length vector                                                                                                  | TBD          |
| When responding to a HelloRetryRequest, the client MUST create a new ClientHello message following the description in Section 4.1.2 of [TLS13]                                          | TBD          |
| Clients MUST be prepared to do a cookie exchange with every handshake.                                                                                                                  | DTLS 1.2     |
| If a server receives a ClientHello with an invalid cookie, it MUST terminate the handshake with an "illegal_parameter" alert                                                            | TBD          |
| clients MUST abort the handshake with an "unexpected_message" alert in response to any second HelloRetryRequest which was sent in the same connection                                   | TLS 1.3      |
| If the sequence number is less than next_receive_seq, the message MUST be discarded                                                                                                     | DTLS 1.2     |
| DTLS 1.3-compliant implementations MUST NOT use the HelloVerifyRequest to execute a return-routability check.                                                                           | TBD          |
| A dual-stack DTLS 1.2 / DTLS 1.3 client MUST, however, be prepared to interact with a DTLS 1.2 server                                                                                   | TBD          |
| the legacy_version field MUST be set to {254, 253}                                                                                                                                      | TBD          |
| A client which has a cached session ID set by a pre-DTLS 1.3 server SHOULD set this field to that value. Otherwise, it MUST be set as a zero-length vector                              | TBD          |
| A DTLS 1.3-only client MUST set the legacy_cookie field to zero length                                                                                                                  | TBD          |
| If a DTLS 1.3 ClientHello is received with any other value in this field [ie. legacy_cookie], the server MUST abort the handshake with an "illegal_parameter" alert                     | TBD          |
| When transmitting the handshake message, the sender divides the message into a series of N contiguous data ranges. The ranges MUST NOT overlap                                          | DTLS 1.2?    |
| Each handshake message fragment that is placed into a record MUST be delivered in a single UDP datagram                                                                                 | DTLS 1.2?    |
| When a DTLS implementation receives a handshake message fragment corresponding to the next expected handshake message sequence number, it MUST process it                               | DTLS 1.2?    |
| DTLS implementations MUST be able to handle overlapping fragment ranges                                                                                                                 | DTLS 1.2     |
| Senders MUST NOT change handshake message bytes upon retransmission                                                                                                                     | TBD          |
| when in the FINISHED state, the server MUST respond to retransmission of the client's final flight with a retransmit of its ACK                                                         | TBD          |
| Implementations MUST either discard or buffer all application data records for epoch 3 and above until they have received the Finished message from the peer                            | TBD          |
| implementations MUST NOT send KeyUpdate, NewConnectionId, or RequestConnectionId messages if an earlier message of the same type has not yet been acknowledged                          | TBD          |
| Any data received with an epoch/sequence number pair after that of a valid received closure alert MUST be ignored                                                                       | TBD          |
| [The server] MUST NOT destroy the existing association until the client has demonstrated reachability                                                                                   | DTLS 1.2     |
| After a correct Finished message is received, the server MUST abandon the previous association                                                                                          | DTLS 1.2     |
| If a DTLS implementation would need to wrap the epoch value, it MUST terminate the connection.                                                                                          | DTLS 1.2     |
| Implementations MUST NOT acknowledge records containing handshake messages or fragments which have not been processed or buffered                                                       | TBD          |
| For post-handshake messages, ACKs SHOULD be sent once for each received and processed handshake record                                                                                  | TBD          |
| During the handshake, ACK records MUST be sent with an epoch which is equal to or higher than the record which is being acknowledged                                                    | TBD          |
| After the handshake, implementations MUST use the highest available sending epoch                                                                                                       | TBD          |
| flights MUST be ACKed unless they are implicitly acknowledged                                                                                                                           | TBD          |
| ACKs MUST NOT be sent for records of any content type other than handshake or for records which cannot be deprotected                                                                   | TBD          |
| Once all the messages in a flight have been acknowledged, the implementation MUST cancel all retransmissions of that flight                                                             | TBD          |
| Implementations MUST treat a record as having been acknowledged if it appears in any ACK                                                                                                | TBD          |
| the receipt of any record responding to a given flight MUST be taken as an implicit acknowledgement for the entire flight to which it is responding.                                    | TBD          |
| KeyUpdates MUST be acknowledged                                                                                                                                                         | TBD          |
| implementations MUST NOT send records with the new keys or send a new KeyUpdate until the previous KeyUpdate has been acknowledged                                                      | TBD          |
| receivers MUST retain the pre-update keying material until receipt and successful decryption of a message using the new keys                                                            | TBD          |
| sending implementations MUST NOT allow the epoch to exceed 2^48-1                                                                                                                       | DTLS 1.2     |
| receiving implementations MUST NOT enforce this rule [i.e. epoch exceeding 2^48-1]                                                                                                      | TBD          |
| sending implementations MUST NOT send its own KeyUpdate if that would cause it to exceed these limits [i.e. epoch exceeding 2^48-1]                                                     | TBD          |
| If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.                                                                           | No           |
| Endpoints MUST NOT have more than one NewConnectionId message outstanding                                                                                                               | No           |
| Implementations which either did not negotiate the "connection_id" extension or which have negotiated receiving an empty CID MUST NOT send NewConnectionId                              | No           |
| Implementations MUST NOT send RequestConnectionId when sending an empty Connection ID                                                                                                   | No           |
| Implementations which detect a violation of these rules MUST terminate the connection with an "unexpected_message" alert                                                                | TBD          |
| Endpoints MUST NOT send a RequestConnectionId message when an existing request is still unfulfilled                                                                                     | No           |
| Endpoints MUST NOT send either of these messages [i.e. NewConnectionId and RequestConnectionId] if they did not negotiate a CID.                                                        | No           |
| If an implementation receives these messages [i.e. NewConnectionId, RequestConnectionId] when CIDs were not negotiated, it MUST abort the connection with an "unexpected_message" alert | TBD          |
| If no CID is negotiated, then the receiver MUST reject any records it receives that contain a CID.                                                                                      | TBD          |
| The cookie MUST depend on the client's address.                                                                                                                                         | Yes          |
| It MUST NOT be possible for anyone other than the issuing entity to generate cookies that are accepted as valid by that entity.                                                         | TBD          |
| DTLS implementations MUST NOT update the address they send to in response to packets from a different address                                                                           | TBD          |
