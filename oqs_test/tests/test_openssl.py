import helpers
import os
import sys
import time

kex_algs_master_111 = [
    'oqs_kem_default',
    ##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_START
    'frodo640aes',
    'frodo640shake',
    'frodo976aes',
    'frodo976shake',
    'frodo1344aes',
    'frodo1344shake',
     ##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_END
    ]
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
                '-subj', '/CN=oqstest_CA',
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
                '-subj', '/CN=oqstest_server',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
    else:
        # generate CA key and cert
        if sig_alg == 'rsa': sig_alg_sized = "rsa:3072"
        else: sig_alg_sized = "rsa"
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-x509', '-new',
                '-newkey', sig_alg_sized,
                '-keyout', '{}_CA.key'.format(sig_alg),
                '-out', '{}_CA.crt'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest_CA',
                '-days', '365',
                '-config', 'apps/openssl.cnf'
            ],
            os.path.join('..')
        )
        # generate server CSR
        helpers.run_subprocess(
            [
                'apps/openssl', 'req', '-new',
                '-newkey', sig_alg_sized,
                '-keyout', '{}_srv.key'.format(sig_alg),
                '-out', '{}_srv.csr'.format(sig_alg),
                '-nodes',
                '-subj', '/CN=oqstest_server',
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
