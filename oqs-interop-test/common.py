import os
import subprocess
import pathlib
import psutil
import shutil
import time

SERVER_START_ATTEMPTS = 60

BSSL_SHIM = os.path.join('boringssl', 'build', 'ssl', 'test', 'bssl_shim')
BSSL = os.path.join('boringssl', 'build', 'tool', 'bssl')
OSSL = os.path.join('apps', 'openssl')

key_exchanges = [
    'oqs_kem_default', 'p256_oqs_kem_default',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','bike1l1cpa','bike1l3cpa','bike1l1fo','bike1l3fo','kyber512','kyber768','kyber1024','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hrss701','lightsaber','saber','firesaber','sidhp434','sidhp503','sidhp610','sidhp751','sikep434','sikep503','sikep610','sikep751','kyber90s512','kyber90s768','kyber90s1024','hqc128_1_cca2','hqc192_1_cca2','hqc192_2_cca2','hqc256_1_cca2','hqc256_2_cca2','hqc256_3_cca2',
    # post-quantum + classical key exchanges
    'p256_frodo640aes','p256_frodo640shake','p384_frodo976aes','p384_frodo976shake','p521_frodo1344aes','p521_frodo1344shake','p256_bike1l1cpa','p384_bike1l3cpa','p256_bike1l1fo','p384_bike1l3fo','p256_kyber512','p384_kyber768','p521_kyber1024','p256_ntru_hps2048509','p384_ntru_hps2048677','p521_ntru_hps4096821','p384_ntru_hrss701','p256_lightsaber','p384_saber','p521_firesaber','p256_sidhp434','p256_sidhp503','p384_sidhp610','p521_sidhp751','p256_sikep434','p256_sikep503','p384_sikep610','p521_sikep751','p256_kyber90s512','p384_kyber90s768','p521_kyber90s1024','p256_hqc128_1_cca2','p384_hqc192_1_cca2','p384_hqc192_2_cca2','p521_hqc256_1_cca2','p521_hqc256_2_cca2','p521_hqc256_3_cca2',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_END
]

signatures = [
##### OQS_TEMPLATE_FRAGMENT_PQ_SIG_ALGS_START
    'oqs_sig_default',
    'dilithium2',
    'dilithium3',
    'dilithium4',
    'falcon512',
    'falcon1024',
    'picnicl1full',
    'picnic3l1',
    'rainbowIaclassic',
    'rainbowVcclassic',
    'sphincsharaka128frobust',
##### OQS_TEMPLATE_FRAGMENT_PQ_SIG_ALGS_END
]

def run_subprocess(command, working_dir='.', expected_returncode=0, input=None):
    """
    Helper function to run a shell command and report success/failure
    depending on the exit status of the shell command.
    """

    # Note we need to capture stdout/stderr from the subprocess,
    # then print it, which pytest will then capture and
    # buffer appropriately
    print(working_dir + " > " + " ".join(command))
    result = subprocess.run(
        command,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
    )
    if result.returncode != expected_returncode:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode('utf-8')


def gen_openssl_keys(ossl, sig_alg, test_artifacts_dir, filename_prefix):
    pathlib.Path(test_artifacts_dir).mkdir(parents=True, exist_ok=True)

    CA_cert_path = os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg))
    server_cert_path = os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(filename_prefix, sig_alg))

    ossl_config = os.path.join('apps', 'openssl.cnf')

    run_subprocess([ossl, 'req', '-x509', '-new',
                                 '-newkey', sig_alg,
                                 '-keyout', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                 '-out', CA_cert_path,
                                 '-nodes',
                                     '-subj', '/CN=oqstest_CA',
                                     '-days', '365',
                                 '-config', ossl_config])
    run_subprocess([ossl, 'req', '-new',
                          '-newkey', sig_alg,
                          '-keyout', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(filename_prefix, sig_alg)),
                          '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                          '-nodes',
                              '-subj', '/CN=oqstest_server',
                          '-config', ossl_config])
    run_subprocess([ossl, 'x509', '-req',
                                  '-in', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                                  '-out', server_cert_path,
                                  '-CA', CA_cert_path,
                                  '-CAkey', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                  '-CAcreateserial',
                                  '-days', '365'])

    with open(os.path.join(test_artifacts_dir, '{}_{}_cert_chain'.format(filename_prefix, sig_alg)),'wb') as out_file:
        for f in [server_cert_path, CA_cert_path]:
            with open(f, 'rb') as in_file:
                shutil.copyfileobj(in_file, out_file)

def start_server(client_type, test_artifacts_dir, sig_alg, worker_id):
    if client_type == "ossl":
        server_command = [BSSL, 'server',
                                '-accept', '0',
                                '-sig-alg', sig_alg,
                                '-loop']
    elif client_type == "bssl":
        gen_openssl_keys(OSSL, sig_alg, test_artifacts_dir, worker_id)
        server_command = [OSSL, 's_server',
                                '-cert', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_alg)),
                                '-key', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_alg)),
                                '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_alg)),
                                '-tls1_3',
                                '-quiet',
                                '-accept', '0']

    print(". > " + " ".join(server_command))
    server = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    server_info = psutil.Process(server.pid)

    # Try SERVER_START_ATTEMPTS times to see
    # what port the server is bound to.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        if server_info.connections():
            break
        else:
            server_start_attempt += 1
            time.sleep(2)
    server_port = str(server_info.connections()[0].laddr.port)

    if client_type == "ossl":
        client_command = [OSSL, 's_client', '-connect', 'localhost:{}'.format(server_port)]
    elif client_type == "bssl":
        client_command = [BSSL_SHIM, '-port', server_port, '-shim-shuts-down']

    # Check SERVER_START_ATTEMPTS times to see
    # if the server is responsive.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        result = subprocess.run(client_command, input='Q'.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            break
        else:
            server_start_attempt += 1
            time.sleep(2)

    if server_start_attempt > SERVER_START_ATTEMPTS:
        raise Exception('Cannot start server')

    return server, server_port
