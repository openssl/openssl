Introducing configuration granularity for X.509 chain verification
------------------------------------------------------------------

Currently OpenSSL has a quite limited support of setting the requirements for
X.509 verification.  SECLEVEL parameter allows this check in TLS context. For
regular X.509 verification it is not granular enough.

This document describes possible configuration mechanism providing a better
granularity and level of system control.

We propose new section, [crypto_algorithm_limits] with the following parameters:

**PermittedAlgorithms** enumerates the algorithms that are only permitted in the
chain.  If present, the certificates having a different algorithm should be
considered invalid in the context of chain building.  If absent, any algorithm
is permitted.

For each algorithm (mostly relevant for RSA and EC) there may be a subsection
named [crypto_algorithm_limits_ALGNAME] with algorithm-dependent parameters. If
present, the alg-specific limitations are applied.

Example configuration
---------------------

[crypto_algorithm_limits]
PermittedAlgorithm = RSA,EC,ML-DSA-65,SOME-UNKNOWN-ALGORITHM

[crypto_algorithm_limits_RSA]
MinBits=2048

[crypto_algorithm_limits_EC]
Curves=P-521

Limitations of the proposed design
----------------------------------

It will work well for the known algorithms but it's not obvious how to extend
it to the algorithms not known to the library but provided by 3rd-party
providers in case when the algorithms are parameterized.

In theory syntax like

[crypto_algorithm_limits_SOME-UNKNOWN-ALGORITHM]
ParamName1=PARAM1
ParamLimit1=LIMIT1
ParamLimitType=MinValue|enum-values

can work but it would be quite fragile.
