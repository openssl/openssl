all: aes/aes.proof aes/aes128enc.proof aes/aes128dec.proof aes/aes256enc.proof aes/aes256dec.proof

broken: sha/sha1.proof sha/sha256.aig chacha.aig

openssl:
	cd .. && make clean && make build_generated && make -j 40 crypto/aes/aes_core.o crypto/sha/sha1_one.o crypto/sha/sha1dgst.o crypto/sha/sha256.o crypto/chacha/chacha_enc.o

clean:
	rm -f */*.bc */*.aig */*.proof

aes/aes.proof: aes/aes.cry aes/aes.saw
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes/aes.saw
	touch aes/aes.proof

aes/aes128enc-wrap.bc: aes/aes128enc-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes/aes256enc-wrap.bc: aes/aes256enc-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes/aes128dec-wrap.bc: aes/aes128dec-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes/aes256dec-wrap.bc: aes/aes256dec-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

sha/sha1-wrap.bc: sha/sha1-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

sha/sha256-wrap.bc: sha/sha256-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

chacha-wrap.bc: chacha-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -I../crypto/include -o $@ $^

# note that the .o file is really a .bc if OpenSSL has been built correctly.
aes/aes128enc.bc: aes/aes128enc-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes/aes128enc.bc aes/aes128enc-wrap.bc ../crypto/aes/aes_core.o

aes/aes256enc.bc: aes/aes256enc-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes/aes256enc.bc aes/aes256enc-wrap.bc ../crypto/aes/aes_core.o

aes/aes128dec.bc: aes/aes128dec-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes/aes128dec.bc aes/aes128dec-wrap.bc ../crypto/aes/aes_core.o

aes/aes256dec.bc: aes/aes256dec-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes/aes256dec.bc aes/aes256dec-wrap.bc ../crypto/aes/aes_core.o

sha/sha1.bc: sha/sha1-wrap.bc ../crypto/sha/sha1_one.o ../crypto/sha/sha1dgst.o
	$(LINK) -o sha/sha1.bc $^

sha/sha256.bc: sha/sha256-wrap.bc ../crypto/sha/sha256.o
	$(LINK) -o sha/sha256.bc $^

chacha.bc: chacha-wrap.bc ../crypto/chacha/chacha_enc.o
	$(LINK) -o chacha.bc $^

aes/aes128enc.aig: aes/aes128enc.bc
	time $(SAW)/bin/lss aes/aes128enc.bc

aes/aes256enc.aig: aes/aes256enc.bc
	time $(SAW)/bin/lss aes/aes256enc.bc

aes/aes128dec.aig: aes/aes128dec.bc
	time $(SAW)/bin/lss aes/aes128dec.bc

aes/aes256dec.aig: aes/aes256dec.bc
	time $(SAW)/bin/lss aes/aes256dec.bc

sha/sha1.aig: sha/sha1.bc
	time $(SAW)/bin/lss sha/sha1.bc

sha/sha256.aig: sha/sha256.bc
	time $(SAW)/bin/lss sha/sha256.bc

chacha.aig: chacha.bc
	time $(SAW)/bin/lss chacha.bc

aes/aes128enc.proof: aes/aes128enc.aig aes/aes128enc.saw AES/AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes/aes128enc.saw
	touch aes/aes128enc.proof

aes/aes256enc.proof: aes/aes256enc.aig aes/aes256enc.saw AES/AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes/aes256enc.saw
	touch aes/aes256enc.proof

aes/aes128dec.proof: aes/aes128dec.aig aes/aes128dec.saw AES/AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes/aes128dec.saw
	touch aes/aes128dec.proof

aes/aes256dec.proof: aes/aes256dec.aig aes/aes256dec.saw AES/AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes/aes256dec.saw
	touch aes/aes256dec.proof

sha/sha1.proof: sha/sha1.aig sha/sha1.saw sha/sha1.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw sha/sha1.saw
	touch sha/sha1.proof
