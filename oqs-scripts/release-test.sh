#!/bin/bash

# To be run as part of a release test only on Linux

# must be run in main folder
# on a serious machine (48+ cores, say)

if [ -d oqs-scripts ]; then
    # just a temp setup
    git checkout -b reltest
    sed -i "s/enable\: false/enable\: true/g" oqs-template/generate.yml && \
    python3 oqs-template/generate.py && \
    oqs-scripts/clone_liboqs.sh && \
    oqs-scripts/build_liboqs.sh && \
    ./Configure no-shared linux-x86_64 -lm  && make generate_crypto_objects && \
    make -j 48 && make test && \
    python3 -m pytest --numprocesses=auto oqs-test/test_tls_full.py oqs-test/test_cms.py oqs-test/test_speed.py && \
    LIBOQS_LIBTYPE=shared oqs-scripts/build_liboqs.sh && \
    cp oqs/lib/*.so* . && \
    make clean && ./Configure shared linux-x86_64 -lm && \
    make -j 48 && LD_LIBRARY_PATH=. make test && \
    LD_LIBRARY_PATH=. python3 -m pytest --numprocesses=auto oqs-test/test_tls_full.py oqs-test/test_cms.py oqs-test/test_speed.py
    # revert temp setup
    git reset --hard
else
    echo "$0 must be run in main oqs-openssl folder. Exiting."
fi

