import common
import pytest
import sys
import os

input_msg = "[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README).)\nOQS-OpenSSL_1_1_1\t is a fork of OpenSSL 1.1.1 that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project."

@pytest.mark.parametrize('sig_name', common.signatures)
def test_sig(ossl, ossl_config, test_artifacts_dir, sig_name, worker_id):
    if (sys.platform.startswith("win") and ("rainbowVclassic" in sig_name)):
        pytest.skip('rainbowVclassic not supported in windows')
    common.gen_keys(ossl, ossl_config, sig_name, test_artifacts_dir, worker_id)
    sign_out = common.run_subprocess([ossl, 'cms', '-sign',
                                                    '-signer', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_name)),
                                                    '-inkey', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_name)),
                                                    '-nodetach',
                                                    '-outform', 'pem',
                                                    '-binary'],
                                      input=input_msg.encode())
    common.run_subprocess([ossl, 'cms', '-verify',
                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_name)),
                                  '-inform', 'pem',
                                  '-crlfeol',
                                  '-out', os.path.join(test_artifacts_dir, '{}_{}_verify_out'.format(worker_id, sig_name))],
                                  input=sign_out.encode())
    with open(os.path.join(test_artifacts_dir, '{}_{}_verify_out'.format(worker_id, sig_name)), 'r') as verify_out:
        assert input_msg == verify_out.read(), "Signature verification failed."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
