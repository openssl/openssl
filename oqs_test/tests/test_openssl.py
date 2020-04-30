import helpers
import os
import sys
import time

kex_algs_master_111 = [
    'oqs_kem_default',
    'p256_oqs_kem_default',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','bike1l1cpa','bike1l3cpa','bike1l1fo','bike1l3fo','kyber512','kyber768','kyber1024','newhope512cca','newhope1024cca','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hrss701','lightsaber','saber','firesaber','sidhp434','sidhp503','sidhp610','sidhp751','sikep434','sikep503','sikep610','sikep751','ledacryptkemlt12','ledacryptkemlt32','ledacryptkemlt52','kyber90s512','kyber90s768','kyber90s1024','babybear','mamabear','papabear','babybearephem','mamabearephem','papabearephem',
    # post-quantum + classical key exchanges
    'p256_frodo640aes','p256_frodo640shake','p256_frodo976aes','p256_frodo976shake','p256_frodo1344aes','p256_frodo1344shake','p256_bike1l1cpa','p256_bike1l3cpa','p256_bike1l1fo','p256_bike1l3fo','p256_kyber512','p256_kyber768','p256_kyber1024','p256_newhope512cca','p256_newhope1024cca','p256_ntru_hps2048509','p256_ntru_hps2048677','p256_ntru_hps4096821','p256_ntru_hrss701','p256_lightsaber','p256_saber','p256_firesaber','p256_sidhp434','p256_sidhp503','p256_sidhp610','p256_sidhp751','p256_sikep434','p256_sikep503','p256_sikep610','p256_sikep751','p256_ledacryptkemlt12','p256_ledacryptkemlt32','p256_ledacryptkemlt52','p256_kyber90s512','p256_kyber90s768','p256_kyber90s1024','p256_babybear','p256_mamabear','p256_papabear','p256_babybearephem','p256_mamabearephem','p256_papabearephem',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_MASTER_END
    ]
sig_algs_master_111 = [
    'rsa:3072',
    'ecdsa',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_MASTER_START
    # post-quantum signatures
    'oqs_sig_default','dilithium2','dilithium3','dilithium4','picnicl1fs','picnic2l1fs','qteslapi','qteslapiii',
    # post-quantum + classical signatures
    'p256_oqs_sig_default','rsa3072_oqs_sig_default','p256_dilithium2','rsa3072_dilithium2','p384_dilithium4','p256_picnicl1fs','rsa3072_picnicl1fs','p256_picnic2l1fs','rsa3072_picnic2l1fs','p256_qteslapi','rsa3072_qteslapi','p384_qteslapiii',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_MASTER_END
    ]

kex_algs = kex_algs_master_111
sig_algs = sig_algs_master_111

def test_gen_keys():
    try:
        st=os.environ['SKIP_TESTS']
    except KeyError:
        st=""
    if "gen_keys" in st:
        return -1

    global sig_algs
    for sig_alg in sig_algs:
        yield (gen_keys, sig_alg)

def gen_keys(sig_alg):
    cmd = os.path.join('oqs_test', 'scripts', 'do_genkey.sh');
    helpers.run_subprocess(
         [cmd],
          os.path.join('..'),
          env={'SIGALG': sig_alg}
    )

def test_connection():
    try:
        st=os.environ['SKIP_TESTS']
    except KeyError:
        st=""
    if "connection" in st:
        return -1

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

def test_cms():
   try:
        st=os.environ['SKIP_TESTS']
   except KeyError:
        st=""
   if "cms" in st:
        return -1

   global sig_algs
   for sig_alg in sig_algs:
       yield(run_cms, sig_alg)

def run_cms(sig_alg ):
    cmd = os.path.join('oqs_test', 'scripts', 'do_openssl-cms.sh');
    helpers.run_subprocess(
        [cmd],
        os.path.join('..'),
        env={'SIGALG': sig_alg}
    )

def test_speed():
   try:
        st=os.environ['SKIP_TESTS']
   except KeyError:
        st=""
   if "speed" in st:
        return -1

   yield(run_speed)

def run_speed():
    cmd = os.path.join('oqs_test', 'scripts', 'do_openssl-speed.sh');
    helpers.run_subprocess(
        [cmd],
        os.path.join('..')
    )

def test_cleanup():
    global sig_algs
    # cleanup all keys and certs
    for sig_alg in sig_algs:
        os.remove(os.path.join("..",sig_alg+"_srv.key"))
        os.remove(os.path.join("..",sig_alg+"_srv.csr"))
        os.remove(os.path.join("..",sig_alg+"_srv.crt"))
        os.remove(os.path.join("..",sig_alg+"_CA.key"))
        os.remove(os.path.join("..",sig_alg+"_CA.srl"))
        os.remove(os.path.join("..",sig_alg+"_CA.crt"))
    # cleanup CMS result file
    os.remove(os.path.join("..","result"))


if __name__ == '__main__':
    try:
        import nose2
        nose2.main()
    except ImportError:
        import nose
        nose.runmodule()
