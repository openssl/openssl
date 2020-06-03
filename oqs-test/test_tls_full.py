import common
import pytest
import sys
import os

@pytest.fixture(params=common.signatures)
def server(ossl, ossl_config, test_artifacts_dir, request, worker_id):
    # Setup: start ossl server
    common.gen_keys(ossl, ossl_config, request.param, test_artifacts_dir, worker_id)
    server, port = common.start_server(ossl, test_artifacts_dir, request.param, worker_id)
    # Run tests
    yield (request.param, port)
    # Teardown: stop ossl server
    server.kill()

@pytest.mark.parametrize('kex_name', common.key_exchanges)
def test_sig_kem_pair(ossl, server, test_artifacts_dir, kex_name, worker_id):
    client_output = common.run_subprocess([ossl, 's_client',
                                                  '-groups', kex_name,
                                                  '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, server[0])),
                                                  '-verify_return_error',
                                                  '-connect', 'localhost:{}'.format(server[1])],
                                    input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in client_output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
