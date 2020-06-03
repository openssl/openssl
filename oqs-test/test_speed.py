import common
import pytest
import sys
import os

input_msg = "[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README).)\nOQS-OpenSSL_1_1_1\t is a fork of OpenSSL 1.1.1 that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project."

@pytest.mark.parametrize('sig_name', common.signatures)
def test_sig_speed(ossl, ossl_config, test_artifacts_dir, sig_name):
    common.run_subprocess([ossl, 'speed', '-seconds', '1', sig_name])

# Hybrid KEMs are not integrated to EVP layer yet (issue #59), hence are not
# speed tested: Thus exclude them from testing. Also exclude oqs_kem_default
# as that may be set to a hybrid too
@pytest.mark.parametrize('kem_name', [i for i in common.key_exchanges if not (i.startswith("p256_") or i.startswith("p384_") or i.startswith("p521_") or i == "oqs_kem_default")])
def test_kem_speed(ossl, ossl_config, test_artifacts_dir, kem_name):
    common.run_subprocess([ossl, 'speed', '-seconds', '1', kem_name])

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
