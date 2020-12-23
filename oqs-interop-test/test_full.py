import common
import pytest
import sys
import subprocess
import os

@pytest.fixture(params=common.signatures)
def parametrized_sig_server(request, client_type, test_artifacts_dir, worker_id):
    # Setup: start server
    server, server_port = common.start_server(client_type, test_artifacts_dir, request.param, worker_id)

    # Run tests
    yield request.param, server_port

    # Teardown: stop server
    server.kill()

@pytest.mark.parametrize('kex_name', common.key_exchanges)
def test_kex_sig_pair(kex_name, parametrized_sig_server, bssl_alg_to_id, client_type, test_artifacts_dir, worker_id):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]

    if client_type == "ossl":
        client_output = common.run_subprocess([common.OSSL, 's_client',
                                                            '-groups', kex_name,
                                                            '-connect', 'localhost:{}'.format(server_port)],
                                               input='Q'.encode())
        if kex_name.startswith('p256'):
            kex_full_name = "{} hybrid".format(kex_name)
        else:
            kex_full_name = kex_name
        if (not "Server Temp Key: {}".format(kex_full_name) in client_output) or (not "Peer signature type:" in client_output) or (not "Server certificate" in client_output):
            print(client_output)
            assert False

    elif client_type == "bssl":
        common.run_subprocess([common.BSSL_SHIM, '-port', str(server_port),
                                                 '-expect-version', 'TLSv1.3',
                                                 '-curves', bssl_alg_to_id[kex_name],
                                                 '-expect-curve-id', bssl_alg_to_id[kex_name],
                                                 '-expect-peer-signature-algorithm', bssl_alg_to_id[server_sig],
                                                 '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_{}_cert_chain'.format(worker_id, server_sig)),
                                                 '-verify-fail',
                                                 '-shim-shuts-down'])

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
