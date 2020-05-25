import os
import subprocess
import pathlib
import psutil
import time

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
    s_server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)

    # Find and return the port that s_server is bound to.
    s_server_info = psutil.Process(s_server.pid).connections()[0]
    return s_server, s_server_info.laddr.port

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
