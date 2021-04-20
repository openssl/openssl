import common
import pytest
import sys
import os
import random

input_msg = "[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README).)\nOQS-OpenSSL_1_1_1\t is a fork of OpenSSL 1.1.1 that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project."

# return a list of permissible digest algorithm names from -list output:
def dgst_algs(alg_list):
   algs = []
   alg_list = alg_list.replace("\n", " ")
   idx=alg_list.find("-")
   while idx > 0:
      sidx = alg_list.find(" ",idx+1)
      if sidx < 0:
          print("No space found. Weird.")
          return algs
      else:
          algs.append(alg_list[idx:sidx])
          alg_list = alg_list[sidx+1:]
      idx=alg_list.find("-")
   return algs


@pytest.mark.parametrize('sig_name', common.signatures)
def test_sigverify(ossl, ossl_config, test_artifacts_dir, sig_name, worker_id):
    common.gen_keys(ossl, ossl_config, sig_name, test_artifacts_dir, worker_id)

    # determine available digest algorithms
    dgsts_out = common.run_subprocess([ossl, 'dgst', '-list'])
    dgst_list = dgst_algs(dgsts_out)
    # now pick a random digest algorithm; for EC and RSA only accept a SHA[1|2]*
    test_dgst = dgst_list[random.randint(0, len(dgst_list)-1)]
    while (sig_name.startswith("ec") or sig_name.startswith("rsa")) and not (test_dgst.startswith("-sha1") or test_dgst.startswith("-sha2")):
       test_dgst = dgst_list[random.randint(0, len(dgst_list)-1)]

    # do sign/verify with the picked digest
    sign_out = common.run_subprocess([ossl, 'dgst', test_dgst, '-sign',
                                                    os.path.join(test_artifacts_dir, '{}_{}_srv.key'.format(worker_id, sig_name)),
                                                    '-out', os.path.join(test_artifacts_dir, '{}_{}_srv.signature'.format(worker_id, sig_name))],
                                      input=input_msg.encode())
    verify_out = common.run_subprocess([ossl, 'dgst', test_dgst, '-verify',
                                  os.path.join(test_artifacts_dir, '{}_{}_srv.pubk'.format(worker_id, sig_name)),
                                  '-signature', os.path.join(test_artifacts_dir, '{}_{}_srv.signature'.format(worker_id, sig_name))],
                                      input=input_msg.encode())
    assert "Verified OK" in verify_out

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
