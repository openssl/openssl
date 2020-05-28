key_exchanges = [
    'oqs_kem_default', 'p256_oqs_kem_default',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_START
    # post-quantum key exchanges
    'frodo640aes','frodo640shake','frodo976aes','frodo976shake','frodo1344aes','frodo1344shake','bike1l1cpa','bike1l3cpa','bike1l1fo','bike1l3fo','kyber512','kyber768','kyber1024','newhope512cca','newhope1024cca','ntru_hps2048509','ntru_hps2048677','ntru_hps4096821','ntru_hrss701','lightsaber','saber','firesaber','sidhp434','sidhp503','sidhp610','sidhp751','sikep434','sikep503','sikep610','sikep751','kyber90s512','kyber90s768','kyber90s1024','babybear','mamabear','papabear','babybearephem','mamabearephem','papabearephem',
    # post-quantum + classical key exchanges
    'p256_frodo640aes','p256_frodo640shake','p256_frodo976aes','p256_frodo976shake','p256_frodo1344aes','p256_frodo1344shake','p256_bike1l1cpa','p256_bike1l3cpa','p256_bike1l1fo','p256_bike1l3fo','p256_kyber512','p256_kyber768','p256_kyber1024','p256_newhope512cca','p256_newhope1024cca','p256_ntru_hps2048509','p256_ntru_hps2048677','p256_ntru_hps4096821','p256_ntru_hrss701','p256_lightsaber','p256_saber','p256_firesaber','p256_sidhp434','p256_sidhp503','p256_sidhp610','p256_sidhp751','p256_sikep434','p256_sikep503','p256_sikep610','p256_sikep751','p256_kyber90s512','p256_kyber90s768','p256_kyber90s1024','p256_babybear','p256_mamabear','p256_papabear','p256_babybearephem','p256_mamabearephem','p256_papabearephem',
##### OQS_TEMPLATE_FRAGMENT_KEX_ALGS_END
]
signatures = [
    'ecdsap256', 'rsa3072',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_START
    # post-quantum signatures
    'oqs_sig_default','dilithium2','dilithium3','dilithium4','falcon512','falcon1024','mqdss3148','picnicl1fs','picnic2l1fs','qteslapi','qteslapiii',
    # post-quantum + classical signatures
    'p256_oqs_sig_default','rsa3072_oqs_sig_default','p256_dilithium2','rsa3072_dilithium2','p256_dilithium3','rsa3072_dilithium3','p384_dilithium4','p256_falcon512','rsa3072_falcon512','p521_falcon1024','p256_mqdss3148','rsa3072_mqdss3148','p256_picnicl1fs','rsa3072_picnicl1fs','p256_picnic2l1fs','rsa3072_picnic2l1fs','p256_qteslapi','rsa3072_qteslapi','p384_qteslapiii',
##### OQS_TEMPLATE_FRAGMENT_SIG_ALGS_END
]
