import helpers
import os
import sys
import time

kex_algs_master_111 = [
    'oqs_kem_default',
    'p256-oqs_kem_default',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','bike1l1cpa','bike1l3cpa','bike1l1fo','bike1l3fo','kyber512','kyber768','kyber1024','newhope512cca','newhope1024cca','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hrss701','lightsaber','saber','firesaber','sidhp434','sidhp503','sidhp610','sidhp751','sikep434','sikep503','sikep610','sikep751',
    # post-quantum + classical key exchanges
    'p256-frodo640aes','p256-frodo640shake','p256-frodo976aes','p256-frodo976shake','p256-frodo1344aes','p256-frodo1344shake','p256-bike1l1cpa','p256-bike1l3cpa','p256-bike1l1fo','p256-bike1l3fo','p256-kyber512','p256-kyber768','p256-kyber1024','p256-newhope512cca','p256-newhope1024cca','p256-ntru_hps2048509','p256-ntru_hps2048677','p256-ntru_hps4096821','p256-ntru_hrss701','p256-lightsaber','p256-saber','p256-firesaber','p256-sidhp434','p256-sidhp503','p256-sidhp610','p256-sidhp751','p256-sikep434','p256-sikep503','p256-sikep610','p256-sikep751',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_END
    ]
sig_algs_master_111 = [
    'rsa',
    'ecdsa',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_MASTER_START
    # post-quantum signatures
    'oqsdefault','dilithium2','dilithium3','dilithium4','picnicl1fs','qteslapi','qteslapiii',
    # post-quantum + classical signatures
    'p256-oqsdefault','rsa3072-oqsdefault','p256-dilithium2','rsa3072-dilithium2','p384-dilithium4','p256-picnicl1fs','rsa3072-picnicl1fs','p256-qteslapi','rsa3072-qteslapi','p384-qteslapiii',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_MASTER_END
    ]

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
