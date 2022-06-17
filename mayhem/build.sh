#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CONFIGURE_FLAGS="no-asm"
fi

./config --debug enable-fuzz-libfuzzer -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers --with-fuzzer-lib=/usr/lib/libFuzzingEngine $CFLAGS -fno-sanitize=alignment $CONFIGURE_FLAGS

make -j$(nproc) LDCMD="$CXX $CXXFLAGS"

fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test '!' -name \*.pl)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	zip -j $OUT/${fuzzer}_seed_corpus.zip fuzz/corpora/${fuzzer}/*
done

cp $SRC/*.options $OUT/
cp fuzz/oids.txt $OUT/asn1.dict
cp fuzz/oids.txt $OUT/x509.dict
