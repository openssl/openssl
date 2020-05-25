import os
import subprocess
import pathlib
import psutil
import shutil
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

    with open(os.path.join(test_artifacts_dir, '{}_cert_chain'.format(filename_prefix)),'wb') as out_file:
        for f in [server_cert_path, CA_cert_path]:
            with open(f, 'rb') as in_file:
                shutil.copyfileobj(in_file, out_file)
