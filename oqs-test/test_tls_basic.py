import oqs_algorithms
import helpers
import pytest
import sys
import os

@pytest.fixture()
def server_port(ossl, ossl_config, test_artifacts_dir, worker_id):
    # Setup: start ossl server
    helpers.gen_keys(ossl, ossl_config, 'oqs_sig_default', test_artifacts_dir, worker_id)
    server, port = helpers.start_server(ossl, test_artifacts_dir, 'oqs_sig_default', worker_id)
    # Run tests
    yield port
    # Teardown: stop ossl server
    server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.key_exchanges)
def test_kem(ossl, server_port, test_artifacts_dir, kex_name, worker_id):
    client_output = helpers.run_subprocess([ossl, 's_client',
                                                  '-groups', kex_name,
                                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_oqs_sig_default_CA.crt'.format(worker_id)),
                                                  '-verify_return_error',
                                                  '-connect', 'localhost:{}'.format(server_port)],
                                            input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in client_output:
        print(client_output)
        assert False, "Server temp key missing."

@pytest.mark.parametrize('sig_name', oqs_algorithms.signatures)
def test_sig(ossl, ossl_config, test_artifacts_dir, sig_name, worker_id):
    helpers.gen_keys(ossl, ossl_config, sig_name, test_artifacts_dir, worker_id)
    server, server_port = helpers.start_server(ossl, test_artifacts_dir, sig_name, worker_id)
    client_output = helpers.run_subprocess([ossl, 's_client',
                                                  '-groups', 'oqs_kem_default',
                                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_name)),
                                                  '-verify_return_error',
                                                  '-connect', 'localhost:{}'.format(server_port)],
                                    input='Q'.encode())
    server.kill()
    if not "Server Temp Key: oqs_kem_default" in client_output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
