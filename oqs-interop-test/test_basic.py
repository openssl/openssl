import ossl_algorithms
import bssl_algorithms
import common
import pytest
import sys
import subprocess
import time
import os
import psutil

PORT_BIND_TIMEOUT = 100

@pytest.fixture()
def sig_default_server_port(server_prog, server_type, client_prog, client_type, test_artifacts_dir, worker_id):
    server, server_port = common.start_server(server_prog, server_type, client_prog, client_type, test_artifacts_dir, "oqs_sig_default", worker_id)

    # Run tests
    yield server_port

    # Teardown: stop server
    server.kill()

@pytest.fixture(params=ossl_algorithms.signatures)
def parametrized_sig_server(request, server_prog, server_type, client_prog, client_type, test_artifacts_dir, worker_id):
    server, server_port = common.start_server(server_prog, server_type, client_prog, client_type, test_artifacts_dir, request.param, worker_id)

    # Run tests
    yield request.param, server_port

    # Teardown: stop server
    server.kill()

@pytest.mark.parametrize('kex_name', ossl_algorithms.key_exchanges)
def test_kex(kex_name, test_artifacts_dir, sig_default_server_port, client_prog, client_type, worker_id):
    if kex_name not in bssl_algorithms.kex_to_nid:
        pytest.skip("{} is unsupported by OQS-BoringSSL.".format(kex_name))
    if client_type == "ossl":
        client_output = common.run_subprocess([client_prog, 's_client',
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
        common.run_subprocess([client_prog, '-port', str(sig_default_server_port),
                                             '-expect-version', 'TLSv1.3',
                                             '-curves', bssl_algorithms.kex_to_nid[kex_name],
                                             '-expect-curve-id', bssl_algorithms.kex_to_nid[kex_name],
                                             '-expect-peer-signature-algorithm', bssl_algorithms.sig_to_code_point['oqs_sig_default'],
                                             '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_oqs_sig_default_cert_chain'.format(worker_id)),
                                             '-verify-fail',
                                             '-shim-shuts-down'])

def test_sig(parametrized_sig_server, client_prog, client_type, test_artifacts_dir, worker_id):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]


    if client_type == "ossl":
        client_output = common.run_subprocess([client_prog, 's_client',
                                                             '-groups', 'oqs_kem_default',
                                                             '-connect', 'localhost:{}'.format(server_port)],
                                         input='Q'.encode())
        if not (("Server Temp Key: oqs_kem_default" in client_output) or ("issuer=C = US, O = BoringSSL" in client_output)) :
            print(client_output)
            assert False
    elif client_type == "bssl":
        common.run_subprocess([client_prog, '-port', str(server_port),
                                             '-expect-version', 'TLSv1.3',
                                             '-curves', bssl_algorithms.kex_to_nid['oqs_kem_default'],
                                             '-expect-curve-id', bssl_algorithms.kex_to_nid['oqs_kem_default'],
                                             '-expect-peer-signature-algorithm', bssl_algorithms.sig_to_code_point[server_sig],
                                             '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_{}_cert_chain'.format(worker_id, server_sig)),
                                             '-verify-fail',
                                             '-shim-shuts-down'])

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
