import helpers
import oqs_algorithms
import pytest
import sys
import subprocess
import time
import os

@pytest.fixture(params=oqs_algorithms.signatures)
def ossl_server_sig(ossl, ossl_config, test_artifacts_dir, request, worker_id):
    # Setup: start ossl server
    helpers.gen_keys(ossl, ossl_config, request.param, test_artifacts_dir, worker_id)
    ossl_server = helpers.start_ossl_server(ossl, test_artifacts_dir, request.param, worker_id)
    time.sleep(0.5)
    # Run tests
    yield request.param
    # Teardown: stop ossl server
    ossl_server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.key_exchanges)
def test_sig_kem_pair(ossl, ossl_server_sig, test_artifacts_dir, kex_name, worker_id):
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', kex_name,
                                           '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, ossl_server_sig)),
                                           '-verify_return_error',
                                           '-connect', 'localhost:{}'.format(str(44433 + helpers.worker_id_to_num(worker_id)))],
                                    input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
