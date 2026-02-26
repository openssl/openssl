Introducing configuration granularity for X.509 chain verification
==================================================================

Currently OpenSSL has a quite limited support of setting the requirements for
X.509 verification.  SECLEVEL parameter allows this check in TLS context. For
regular X.509 verification it is not granular enough.

This document describes possible configuration mechanism providing a better
granularity and level of system control.

We propose new sections, [OPNAME_algorithm_limits] to specify the parameters
for particular algorithms. OPNAME as of now can be `sign` or `verify`.

This sections contain the algorithms that are only permitted in the
chain.  If present, the certificates having a different algorithm should be
considered invalid in the context of chain building.  If absent, any algorithm
is permitted.

For each algorithm (mostly relevant for RSA and EC) there may be a subsection
named [crypto_algorithm_limits_ALGNAME] with algorithm-dependent parameters. If
present, the alg-specific limitations are applied.

Example configuration
---------------------

    [sign_algorithm_limits]
    RSA = @RSA_limits
    EC = @EC_limits
    MLDSA65 = @MLDSA65_limits
    UNKNOWN = @UNKNOWN_limits

    [RSA_limits]
    MinBits=2048

    [EC_limits]
    Curves=P-521

    [MLDSA65_limits]
    # Override the name given in @crypto_algorithm_limits
    id = ML-DSA-65

    [UNKNOWN_limits]
    # Override the name given in @crypto_algorithm_limits
    id = SOME-UNKNOWN-ALGORITHM

Limitations of the proposed design
----------------------------------

It will work well for the known algorithms but it's not obvious how to extend
it to the algorithms not known to the library but provided by 3rd-party
providers in case when the algorithms are parameterized.

In theory syntax like

[UNKNOWN_limits]
ParamName1=PARAM1
ParamLimit1=LIMIT1
ParamLimitType=MinValue|enum-values

can work but it would be quite fragile.
