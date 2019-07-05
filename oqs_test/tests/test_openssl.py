import helpers
import os
import sys
import time

kex_algs_master_111 = ['oqs_kem_default', 'bike1l1', 'bike1l3', 'bike1l5', 'bike2l1', 'bike2l3', 'bike2l5', 'bike3l1', 'bike3l3', 'bike3l5', 'frodo640aes', 'frodo640cshake', 'frodo976aes', 'frodo976cshake', 'newhope512cca', 'newhope1024cca', 'sidh503', 'sidh751', 'sike503', 'sike751', 'p256-oqs_kem_default', 'p256-bike1l1', 'p256-bike2l1', 'p256-bike3l1', 'p256-frodo640aes', 'p256-frodo640cshake', 'p256-newhope512cca', 'p256-sidh503', 'p256-sike503'] # ADD_MORE_OQS_KEM_HERE
sig_algs_master_111 = ['rsa', 'ecdsa', 'picnicl1fs', 'qteslaI', 'qteslaIIIsize', 'qteslaIIIspeed', 'rsa3072_picnicl1fs', 'rsa3072_qteslaI', 'p256_picnicl1fs', 'p256_qteslaI', 'p384_qteslaIIIsize', 'p384_qteslaIIIspeed', 'dilithium2', 'dilithium3', 'dilithium4'] # ADD_MORE_OQS_SIG_HERE

kex_algs = kex_algs_master_111
sig_algs = sig_algs_master_111

def test_gen_keys():
    global sig_algs
    for sig_alg in sig_algs:
        yield (gen_keys, sig_alg)

def gen_keys(sig_alg):
    if sig_alg == 'ecdsa':
        # generate curve parameters
        helpers.run_subprocess(
            [
                'apps/openssl', 'ecparam',
                '-out', 'secp384r1.pem',
                '-name', 'secp384r1'
            ],
            os.path.join('..')
        )
        # generate CA key and cert
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-x509', '-new',
                '-newkey', 'ec:secp384r1.pem',
                '-keyout', '{}_CA.key'.format(sig_alg),
                '-out', '{}_CA.crt'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest CA',
                '-days', '365',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
        # generate server CSR
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-new',
                '-newkey', 'ec:secp384r1.pem',
                '-keyout', '{}_srv.key'.format(sig_alg),
                '-out', '{}_srv.csr'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest server',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
    else:
        # generate CA key and cert
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-x509', '-new',
                '-newkey', sig_alg,
                '-keyout', '{}_CA.key'.format(sig_alg),
                '-out', '{}_CA.crt'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest CA',
                '-days', '365',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
        # generate server CSR
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-new',
                '-newkey', sig_alg,
                '-keyout', '{}_srv.key'.format(sig_alg),
                '-out', '{}_srv.csr'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest server',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
    # generate server cert
    helpers.run_subprocess(
        [
            'apps/openssl', 'x509', '-req',
            '-in', '{}_srv.csr'.format(sig_alg),
            '-out', '{}_srv.crt'.format(sig_alg),
            '-CA', '{}_CA.crt'.format(sig_alg),
            '-CAkey', '{}_CA.key'.format(sig_alg),
            '-CAcreateserial',
            '-days', '365'
        ],
        os.path.join('..')
    )

def test_connection():
    global sig_algs, kex_algs
    port = 23567
    for sig_alg in sig_algs:
        for kex_alg in kex_algs:
            yield(run_connection, sig_alg, kex_alg, port)
            port = port + 1

def run_connection(sig_alg, kex_alg, port):
    cmd = os.path.join('oqs_test', 'scripts', 'do_openssl-111.sh');
    helpers.run_subprocess(
        [cmd],
        os.path.join('..'),
        env={'SIGALG': sig_alg, 'KEXALG': kex_alg, 'PORT': str(port)}
    )

if __name__ == '__main__':
    try:
        import nose2
        nose2.main()
    except ImportError:
        import nose
        nose.runmodule()
