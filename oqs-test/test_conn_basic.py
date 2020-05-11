import oqs_algorithms
import helpers
import pytest
import sys
import subprocess
import time
import os

@pytest.fixture()
def ossl_server(ossl, ossl_config, test_artifacts_dir, worker_id):
    # Setup: start ossl server
    helpers.gen_keys(ossl, ossl_config, 'oqs_sig_default', test_artifacts_dir, worker_id)
    ossl_server = helpers.start_ossl_server(ossl, test_artifacts_dir, 'oqs_sig_default', worker_id)
    time.sleep(0.5)
    # Run tests
    yield
    # Teardown: stop ossl server
    ossl_server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.key_exchanges)
def test_kem(ossl, ossl_server, test_artifacts_dir, kex_name, worker_id):
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', kex_name,
                                           '-CAfile', os.path.join(test_artifacts_dir, '{}_oqs_sig_default_CA.crt'.format(worker_id)),
                                           '-verify_return_error',
                                           '-connect', 'localhost:{}'.format(str(44433 + helpers.worker_id_to_num(worker_id)))],
                                    input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in output:
        print(output)
        assert False, "Server temp key missing."

@pytest.mark.parametrize('sig_name', oqs_algorithms.signatures)
def test_sig(ossl, ossl_config, test_artifacts_dir, sig_name, worker_id):
    helpers.gen_keys(ossl, ossl_config, sig_name, test_artifacts_dir, worker_id)
    server_port = str(44433 + helpers.worker_id_to_num(worker_id))
    ossl_server = helpers.start_ossl_server(ossl, test_artifacts_dir, 'oqs_sig_default', worker_id)
    time.sleep(0.5)
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', 'oqs_kem_default',
                                           '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_name)),
                                           '-verify_return_error',
                                           '-connect', 'localhost:{}'.format(server_port)],
                                    input='Q'.encode())
    ossl_server.kill()
    if not "Server Temp Key: oqs_kem_default" in output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
