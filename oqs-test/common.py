import os
import subprocess
import pathlib
import psutil
import time

key_exchanges = [
    'oqs_kem_default', 'p256_oqs_kem_default',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','bike1l1cpa','bike1l3cpa','kyber512','kyber768','kyber1024','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hrss701','lightsaber','saber','firesaber','sidhp434','sidhp503','sidhp610','sidhp751','sikep434','sikep503','sikep610','sikep751','bike1l1fo','bike1l3fo','kyber90s512','kyber90s768','kyber90s1024','hqc128','hqc192','hqc256','ntrulpr653','ntrulpr761','ntrulpr857','sntrup653','sntrup761','sntrup857',
    # post-quantum + classical key exchanges
    'p256_frodo640aes','p256_frodo640shake','p384_frodo976aes','p384_frodo976shake','p521_frodo1344aes','p521_frodo1344shake','p256_bike1l1cpa','p384_bike1l3cpa','p256_kyber512','p384_kyber768','p521_kyber1024','p256_ntru_hps2048509','p384_ntru_hps2048677','p521_ntru_hps4096821','p384_ntru_hrss701','p256_lightsaber','p384_saber','p521_firesaber','p256_sidhp434','p256_sidhp503','p384_sidhp610','p521_sidhp751','p256_sikep434','p256_sikep503','p384_sikep610','p521_sikep751','p256_bike1l1fo','p384_bike1l3fo','p256_kyber90s512','p384_kyber90s768','p521_kyber90s1024','p256_hqc128','p384_hqc192','p521_hqc256','p256_ntrulpr653','p384_ntrulpr761','p384_ntrulpr857','p256_sntrup653','p384_sntrup761','p384_sntrup857',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_END
]
signatures = [
    'ecdsap256', 'rsa3072',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_START
    # post-quantum signatures
    'oqs_sig_default','dilithium2','dilithium3','dilithium5','dilithium2_aes','dilithium3_aes','dilithium5_aes','falcon512','falcon1024','picnicl1full','picnic3l1','rainbowIclassic','rainbowVclassic','sphincsharaka128frobust','sphincssha256128frobust','sphincsshake256128frobust',
    # post-quantum + classical signatures
    'p256_oqs_sig_default','rsa3072_oqs_sig_default','p256_dilithium2','rsa3072_dilithium2','p384_dilithium3','p521_dilithium5','p256_dilithium2_aes','rsa3072_dilithium2_aes','p384_dilithium3_aes','p521_dilithium5_aes','p256_falcon512','rsa3072_falcon512','p521_falcon1024','p256_picnicl1full','rsa3072_picnicl1full','p256_picnic3l1','rsa3072_picnic3l1','p256_rainbowIclassic','rsa3072_rainbowIclassic','p521_rainbowVclassic','p256_sphincsharaka128frobust','rsa3072_sphincsharaka128frobust','p256_sphincssha256128frobust','rsa3072_sphincssha256128frobust','p256_sphincsshake256128frobust','rsa3072_sphincsshake256128frobust',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_END
]

SERVER_START_ATTEMPTS = 10

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

def start_server(ossl, test_artifacts_dir, sig_alg, worker_id):
    command = [ossl, 's_server',
                      '-cert', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_alg)),
                      '-key', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_alg)),
                      '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_alg)),
                      '-tls1_3',
                      '-quiet',
                      # On UNIX-like systems, binding to TCP port 0
                      # is a request to dynamically generate an unused
                      # port number.
                      # TODO: Check if Windows behaves similarly
                      '-accept', '0']

    print(" > " + " ".join(command))
    server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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

    # Check SERVER_START_ATTEMPTS times to see
    # if the server is responsive.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        result = subprocess.run([ossl, 's_client', '-connect', 'localhost:{}'.format(server_port)],
                                input='Q'.encode(),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode == 0:
            break
        else:
            server_start_attempt += 1
            time.sleep(2)

    if server_start_attempt > SERVER_START_ATTEMPTS:
        raise Exception('Cannot start OpenSSL server')

    return server, server_port

def gen_keys(ossl, ossl_config, sig_alg, test_artifacts_dir, filename_prefix):
    pathlib.Path(test_artifacts_dir).mkdir(parents=True, exist_ok=True)
    if sig_alg == 'ecdsap256':
        run_subprocess([ossl, 'ecparam',
                              '-name', 'prime256v1',
                              '-out', os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))])
        run_subprocess([ossl, 'req', '-x509', '-new',
                                     '-newkey', 'ec:{}'.format(os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))),
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_ecdsap256_CA.key'.format(filename_prefix)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_ecdsap256_CA.crt'.format(filename_prefix)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_CA',
                                         '-days', '365',
                                     '-config', ossl_config])
        run_subprocess([ossl, 'req', '-new',
                                     '-newkey', 'ec:{}'.format(os.path.join(test_artifacts_dir, '{}_prime256v1.pem'.format(filename_prefix))),
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_ecdsap256_srv.key'.format(filename_prefix)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_ecdsap256_srv.csr'.format(filename_prefix)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_server',
                                     '-config', ossl_config])
    else:
        if sig_alg == 'rsa3072':
            ossl_sig_alg_arg = 'rsa:3072'
        else:
            ossl_sig_alg_arg = sig_alg
        run_subprocess([ossl, 'req', '-x509', '-new',
                                     '-newkey', ossl_sig_alg_arg,
                                     '-keyout', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                     '-out', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg)),
                                     '-nodes',
                                         '-subj', '/CN=oqstest_CA',
                                         '-days', '365',
                                     '-config', ossl_config])
        run_subprocess([ossl, 'req', '-new',
                              '-newkey', ossl_sig_alg_arg,
                              '-keyout', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(filename_prefix, sig_alg)),
                              '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                              '-nodes',
                                  '-subj', '/CN=oqstest_server',
                              '-config', ossl_config])

    run_subprocess([ossl, 'x509', '-req',
                                  '-in', os.path.join(test_artifacts_dir, '{}_{}_srv.csr'.format(filename_prefix, sig_alg)),
                                  '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(filename_prefix, sig_alg)),
                                  '-CA', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg)),
                                  '-CAkey', os.path.join(test_artifacts_dir, '{}_{}_CA.key'.format(filename_prefix, sig_alg)),
                                  '-CAcreateserial',
                                  '-days', '365'])
