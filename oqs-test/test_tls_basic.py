import common
import pytest
import sys
import os

@pytest.fixture()
def sig_default_server_port(ossl, ossl_config, test_artifacts_dir, worker_id):
    # Setup: start ossl server
    common.gen_keys(ossl, ossl_config, 'dilithium2', test_artifacts_dir, worker_id)
    server, port = common.start_server(ossl, test_artifacts_dir, 'dilithium2', worker_id)
    # Run tests
    yield port
    # Teardown: stop ossl server
    server.kill()

@pytest.fixture(params=common.signatures)
def parametrized_sig_server(request, ossl, ossl_config, test_artifacts_dir, worker_id):
    if (sys.platform.startswith("win") and ("rainbowVclassic" in request.param)):
        pytest.skip('rainbowVclassic not supported in windows')
    # Setup: start ossl server
    common.gen_keys(ossl, ossl_config, request.param, test_artifacts_dir, worker_id)
    server, port = common.start_server(ossl, test_artifacts_dir, request.param, worker_id)
    # Run tests
    yield request.param, port
    # Teardown: stop ossl server
    server.kill()

@pytest.mark.parametrize('kex_name', common.key_exchanges)
def test_kem(ossl, sig_default_server_port, test_artifacts_dir, kex_name, worker_id):
    if (sys.platform.startswith("win") and ("bike" in kex_name)):
        pytest.skip('BIKE not supported in windows')
    client_output = common.run_subprocess([ossl, 's_client',
                                                  '-groups', kex_name,
                                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_dilithium2_CA.crt'.format(worker_id)),
                                                  '-verify_return_error',
                                                  '-connect', 'localhost:{}'.format(sig_default_server_port)],
                                            input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in client_output:
        print(client_output)
        assert False, "Server temp key missing."

def test_sig(parametrized_sig_server, ossl, test_artifacts_dir, worker_id):
    server_sig = parametrized_sig_server[0]
    if (sys.platform.startswith("win") and ("rainbowVclassic" in server_sig)):
        pytest.skip('rainbowVclassic not supported in windows')
    server_port = parametrized_sig_server[1]

    client_output = common.run_subprocess([ossl, 's_client',
                                                  '-groups', 'frodo640aes',
                                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, server_sig)),
                                                  '-verify_return_error',
                                                  '-connect', 'localhost:{}'.format(server_port)],
                                    input='Q'.encode())
    if not "Server Temp Key: frodo640aes" in client_output:
        print(client_output)
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
