#!/bin/bash

set -e

export CC=$CC_OQS

enable_disable_str=
if [[ ${USE_OPENSSL} == 1 ]];then
  enable_disable_str=" --enable-openssl"
  if [[ ! -z "${OPENSSL_DIR// }" ]];then
     enable_disable_str+=" --with-openssl-dir=${OPENSSL_DIR}"
  fi
fi

if [[ ${AES_NI} == 0 ]];then
  enable_disable_str+=" --disable-aes-ni"
fi

if [[ ${ENABLE_CODE_MCBITS} == 1 ]];then
  enable_disable_str+=" --enable-kex-code-mcbits"
  if [[ ! -z "${SODIUM_DIR// }" ]];then
     enable_disable_str+=" --with-sodium-dir=${SODIUM_DIR}"
  fi
fi

if [[ ${ENABLE_SIDH_IQC_REF} == 1 ]];then
  enable_disable_str+=" --enable-kex-sidh-iqc-ref"
    if [[ ! -z "${GMP_DIR// }" ]];then
     enable_disable_str+=" --with-gmp-dir=${GMP_DIR}"
  fi
fi

if [[ ${ENABLE_KEX_LWE_FRODO} == 0 ]];then
  enable_disable_str+=" --disable-kex-lwe-frodo"
fi

if [[ ${ENABLE_KEX_NTRU} == 0 ]];then
  enable_disable_str+=" --disable-kex-ntru"
fi

if [[ ${ENABLE_KEX_RLWE_MSRLN16} == 0 ]];then
  enable_disable_str+=" --disable-kex-rlwe-msrln16"
fi

if [[ ${ENABLE_KEX_RLWE_NEWHOPE} == 0 ]];then
  enable_disable_str+=" --disable-kex-rlwe-newhope"
fi

if [[ ${ENABLE_KEX_SIDH_MSR} == 0 ]];then
  enable_disable_str+=" --disable-kex-sidh-cln16"
fi

if [[ ${ENABLE_SIG_PICNIC} == 0 ]];then
  enable_disable_str+=" --disable-sig-picnic"
fi

if [[ ${ENABLE_KEX_RLWE_NEWHOPE_AVX2} == 1 ]];then
  enable_disable_str+=" --enable-kex-rlwe-newhope-avx2"
fi

autoreconf -i
./configure --enable-silent-rules ${enable_disable_str}
make clean
make
make test

for f in $(ls .travis/*-check.sh); do
    bash $f;
done


