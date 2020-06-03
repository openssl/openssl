import os
import subprocess
import pathlib
import psutil
import shutil
import time

SERVER_START_ATTEMPTS = 100

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


def gen_openssl_keys(ossl, ossl_config, sig_alg, test_artifacts_dir, filename_prefix):
    pathlib.Path(test_artifacts_dir).mkdir(parents=True, exist_ok=True)

    CA_cert_path = os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(filename_prefix, sig_alg))
    server_cert_path = os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(filename_prefix, sig_alg))

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

def start_server(server_prog, server_type, client_prog, client_type, test_artifacts_dir, sig_alg, worker_id):
    if server_type == "bssl":
        server_command = [server_prog, 'server',
                                       '-accept', '0',
                                       '-sig-alg', sig_alg,
                                       '-loop']
    elif server_type == "ossl":
        gen_openssl_keys(server_prog, os.path.join('apps', 'openssl.cnf'), sig_alg, test_artifacts_dir, worker_id)
        server_command = [server_prog, 's_server',
                                       '-cert', os.path.join(test_artifacts_dir, '{}_{}_srv.crt'.format(worker_id, sig_alg)),
                                       '-key', os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_alg)),
                                       '-CAfile', os.path.join(test_artifacts_dir, '{}_{}_CA.crt'.format(worker_id, sig_alg)),
                                       '-tls1_3',
                                       '-quiet',
                                       '-accept', '0']

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
            time.sleep(3)
    server_port = str(server_info.connections()[0].laddr.port)

    if client_type == "bssl":
        client_command = [client_prog, '-port', server_port, '-shim-shuts-down']
    elif client_type == "ossl":
        client_command = [client_prog, 's_client', '-connect', 'localhost:{}'.format(server_port)]

    # Check SERVER_START_ATTEMPTS times to see
    # if the server is responsive.
    server_start_attempt = 1
    while server_start_attempt <= SERVER_START_ATTEMPTS:
        result = subprocess.run(client_command, input='Q'.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            break
        else:
            server_start_attempt += 1
            time.sleep(3)

    if server_start_attempt > SERVER_START_ATTEMPTS:
        raise Exception('Cannot start server')

    return server, server_port
