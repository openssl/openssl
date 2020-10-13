import common
import pytest
import sys
import subprocess
import os

@pytest.fixture()
def sig_default_server_port(client_type, test_artifacts_dir, worker_id):
    server, server_port = common.start_server(client_type, test_artifacts_dir, "oqs_sig_default", worker_id)

    # Run tests
    yield server_port

    # Teardown: stop server
    server.kill()

@pytest.fixture(params=common.signatures)
def parametrized_sig_server(request, client_type, test_artifacts_dir, worker_id):
    server, server_port = common.start_server(client_type, test_artifacts_dir, request.param, worker_id)

    # Run tests
    yield request.param, server_port

    # Teardown: stop server
    server.kill()

@pytest.mark.parametrize('kex_name', common.key_exchanges)
def test_kex(kex_name, bssl_alg_to_id, test_artifacts_dir, sig_default_server_port, client_type, worker_id):
    if client_type == "ossl":
        client_output = common.run_subprocess([common.OSSL, 's_client',
                                                            '-groups', kex_name,
                                                            '-connect', 'localhost:{}'.format(sig_default_server_port)],
                                               input='Q'.encode())
        if kex_name.startswith('p256'):
            kex_full_name = "{} hybrid".format(kex_name)
        else:
            kex_full_name = kex_name
        if (not "Server Temp Key: {}".format(kex_full_name) in client_output) or (not "issuer=C = US, O = BoringSSL" in client_output):
            print(client_output)
            assert False

    elif client_type == "bssl":
        common.run_subprocess([common.BSSL_SHIM, '-port', str(sig_default_server_port),
                                                 '-expect-version', 'TLSv1.3',
                                                 '-curves', bssl_alg_to_id[kex_name],
                                                 '-expect-curve-id', bssl_alg_to_id[kex_name],
                                                 '-expect-peer-signature-algorithm', bssl_alg_to_id['oqs_sig_default'],
                                                 '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_oqs_sig_default_cert_chain'.format(worker_id)),
                                                 '-verify-fail',
                                                 '-shim-shuts-down'])

def test_sig(parametrized_sig_server, bssl_alg_to_id, client_type, test_artifacts_dir, worker_id):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]

    if client_type == "ossl":
        client_output = common.run_subprocess([common.OSSL, 's_client',
                                                            '-groups', 'oqs_kem_default',
                                                            '-connect', 'localhost:{}'.format(server_port)],
                                               input='Q'.encode())
        if not (("Server Temp Key: oqs_kem_default" in client_output) or ("issuer=C = US, O = BoringSSL" in client_output)) :
            print(client_output)
            assert False

    elif client_type == "bssl":
        common.run_subprocess([common.BSSL_SHIM, '-port', str(server_port),
                                                 '-expect-version', 'TLSv1.3',
                                                 '-curves', bssl_alg_to_id['oqs_kem_default'],
                                                 '-expect-curve-id', bssl_alg_to_id['oqs_kem_default'],
                                                 '-expect-peer-signature-algorithm', bssl_alg_to_id[server_sig],
                                                 '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_{}_cert_chain'.format(worker_id, server_sig)),
                                                 '-verify-fail',
                                                 '-shim-shuts-down'])

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
