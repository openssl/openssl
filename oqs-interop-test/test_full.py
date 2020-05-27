import helpers
import ossl_algorithms
import bssl_algorithms
import pytest
import sys
import subprocess
import time
import os
import psutil

@pytest.fixture(params=ossl_algorithms.signatures)
def parametrized_sig_server(request, server_prog, server_type, test_artifacts_dir, worker_id):
    # Setup: start server
    sig_alg = request.param
    if sig_alg not in bssl_algorithms.sig_to_code_point:
        pytest.skip("{} is unsupported by OQS-BoringSSL.".format(sig_alg))
    if server_type == "ossl":
        helpers.gen_openssl_keys(server_prog, os.path.join('apps', 'openssl.cnf'), sig_alg, test_artifacts_dir, worker_id)
        command = [server_prog, 's_server',
                                '-cert', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_alg)),
                                '-key', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_alg)),
                                '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_alg)),
                                '-tls1_3',
                                '-quiet',
                                '-accept', '0']
    elif server_type == "bssl":
        command = [server_prog, 'server',
                                '-accept', '0',
                                '-sig-alg', sig_alg,
                                '-loop']
    print(" > " + " ".join(command))
    server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)

    # Find and return the port that the server is bound to.
    server_conn = psutil.Process(server.pid).connections()[0]

    # Run tests
    yield sig_alg, server_conn.laddr.port

    # Teardown: stop server
    server.kill()

@pytest.mark.parametrize('kex_name', ossl_algorithms.key_exchanges)
def test_kex_sig_pair(kex_name, parametrized_sig_server, client_prog, client_type, test_artifacts_dir, worker_id):
    server_sig = parametrized_sig_server[0]
    server_port = parametrized_sig_server[1]

    if kex_name not in bssl_algorithms.kex_to_nid:
        pytest.skip("{} is unsupported by OQS-BoringSSL.".format(kex_name))

    if client_type == "ossl":
        client_output = helpers.run_subprocess([client_prog, 's_client',
                                                             '-groups', kex_name,
                                                             '-connect', 'localhost:{}'.format(server_port)],
                                         input='Q'.encode())
        if kex_name.startswith('p256'):
            kex_full_name = "{} hybrid".format(kex_name)
        else:
            kex_full_name = kex_name
        if (not "Server Temp Key: {}".format(kex_full_name) in client_output) or (not "issuer=C = US, O = BoringSSL" in client_output):
            print(client_output)
            assert False
    elif client_type == "bssl":
        helpers.run_subprocess([client_prog, '-port', str(server_port),
                                             '-expect-version', 'TLSv1.3',
                                             '-curves', bssl_algorithms.kex_to_nid[kex_name],
                                             '-expect-curve-id', bssl_algorithms.kex_to_nid[kex_name],
                                             '-expect-peer-signature-algorithm', bssl_algorithms.sig_to_code_point[server_sig],
                                             '-expect-peer-cert-file', os.path.join(test_artifacts_dir, '{}_{}_cert_chain'.format(worker_id, server_sig)),
                                             '-verify-fail',
                                             '-shim-shuts-down'])

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
