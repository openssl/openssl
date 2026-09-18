Provider-defined TLS 1.3 ciphersuites
=====================================

The capability contract is in [provider-base(7)](../man7/provider-base.pod).
Capability macros extend the source API; no public function or ABI symbol
is added.

Discovery and retained implementations
--------------------------------------

Discovery follows TLS-GROUP's name/property lookup rather than TLS-SIGALG's
provider-origin check. This permits one provider to advertise a suite whose
AEAD or digest is supplied by another provider selected through the context's
library context and property query.

Descriptors retain the fetched EVP objects instead of storing names for a
later fetch. This preserves the selected implementation and its provider
references. It does not extend the lifetime of the library context; callers
must still follow the existing library-context lifetime rules.

The registry is immutable after SSL_CTX creation. Its owned stack is sorted
by wire ID; a shallow second stack supplies the name index. Both use OpenSSL's
existing stack lookup. The descriptor limit bounds registry storage and lookup,
not the execution time of arbitrary provider callbacks.

A capability return value of zero cannot distinguish unsupported capability
from provider failure. Fetch failure similarly lacks the distinction needed
here between unavailability and operational failure. The compatibility behaviour
and its limits are specified in provider-base(7); this patch adds no heuristic
for classifying either result.

Canonicalisation and ownership
------------------------------

The context registry owns each dynamic descriptor. A session takes a counted
reference because it can outlive the SSL and SSL_CTX that created it.
Static-table descriptors keep their existing lifetime.

Provider descriptors stored in per-SSL cipher stacks are canonicalised to the
connection's session_ctx. Existing shallow-stack ownership therefore remains
sufficient. An SSL without its own combined cipher list borrows the list of
its current SSL_CTX; that view is distinct from its saved TLS 1.3 list.

Pointer identity cannot match independently created context registries.
Provider-suite membership checks compare wire IDs and descriptor equivalence,
including the held EVP implementations, before using the session_ctx object.
Static-suite membership retains the existing pointer comparison.

SSL_set_SSL_CTX() does not replace the saved TLS 1.3 list. This patch adds no
post-SNI check against the target context's TLS 1.3 list. Explicit per-SSL
ciphersuite changes still apply. Rebinding to another library context or
property query is outside this design.

Sessions
--------

The provider-cipher marker is separate from not_resumable: session duplication
and ticket processing can reset the latter. It also cannot be derived from the
current cipher, since cipher replacement must not erase the session's
provenance. Successful in-place session decoding is handled as documented in
[SSL_SESSION_get0_cipher(3)](../man3/SSL_SESSION_get0_cipher.pod).
Received tickets pass the common extension parser and are then discarded.
SSL_clear() drops a provider-marked session.

A built-in ticket or external PSK may negotiate a provider suite with the same
transcript hash, following [RFC 8446 section 4.6.1][resumption]. The resulting
provider session is not resumable. Shared input sessions must be copied before
assigning the new descriptor; this keeps the original ticket or cache entry
unchanged.

Record-layer boundary
---------------------

The fixed AEAD profile reuses the stream TLS 1.3 record path. Discovery checks
metadata, not a trial encryption. Stronger compatibility probing needs a
defined side-effect-free EVP contract.

DTLS 1.3 record-number encryption and QUIC header protection need companion
algorithms that the capability does not declare. kTLS would bypass the
provider's AEAD and its per-key limits, so it is excluded.

Proactive KeyUpdate thresholds, optional provider-origin restrictions, other
nonce/tag/digest profiles, provider-backed external PSK and 0-RTT, and
cross-library-context rebinding require separate contracts. They are not
implemented by this capability.

[resumption]: https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.1
