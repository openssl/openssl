all: aes.proof aes128enc.proof aes128dec.proof aes256enc.proof aes256dec.proof

broken: sha1.proof sha256.aig chacha.aig

clean:
	rm -f *.bc *.aig *.proof

aes.proof: aes.cry aes.saw
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes.saw
	touch aes.proof

aes128enc-wrap.bc: aes128enc-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes256enc-wrap.bc: aes256enc-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes128dec-wrap.bc: aes128dec-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

aes256dec-wrap.bc: aes256dec-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

sha1-wrap.bc: sha1-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

sha256-wrap.bc: sha256-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -o $@ $^

chacha-wrap.bc: chacha-wrap.c
	$(CLANG) -c -emit-llvm -I../include -I$(SAW)/include -I../crypto/include -o $@ $^

# note that the .o file is really a .bc if OpenSSL has been built correctly.
aes128enc.bc: aes128enc-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes128enc.bc aes128enc-wrap.bc ../crypto/aes/aes_core.o

aes256enc.bc: aes256enc-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes256enc.bc aes256enc-wrap.bc ../crypto/aes/aes_core.o

aes128dec.bc: aes128dec-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes128dec.bc aes128dec-wrap.bc ../crypto/aes/aes_core.o

aes256dec.bc: aes256dec-wrap.bc ../crypto/aes/aes_core.o
	$(LINK) -o aes256dec.bc aes256dec-wrap.bc ../crypto/aes/aes_core.o

sha1.bc: sha1-wrap.bc ../crypto/sha/sha1_one.o ../crypto/sha/sha1dgst.o
	$(LINK) -o sha1.bc $^

sha256.bc: sha256-wrap.bc ../crypto/sha/sha256.o
	$(LINK) -o sha256.bc $^

chacha.bc: chacha-wrap.bc ../crypto/chacha/chacha_enc.o
	$(LINK) -o chacha.bc $^

aes128enc.aig: aes128enc.bc
	time $(SAW)/bin/lss aes128enc.bc

aes256enc.aig: aes256enc.bc
	time $(SAW)/bin/lss aes256enc.bc

aes128dec.aig: aes128dec.bc
	time $(SAW)/bin/lss aes128dec.bc

aes256dec.aig: aes256dec.bc
	time $(SAW)/bin/lss aes256dec.bc

sha1.aig: sha1.bc
	time $(SAW)/bin/lss sha1.bc

sha256.aig: sha256.bc
	time $(SAW)/bin/lss sha256.bc

chacha.aig: chacha.bc
	time $(SAW)/bin/lss chacha.bc

aes128enc.proof: aes128enc.aig aes128enc.saw AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes128enc.saw
	touch aes128enc.proof

aes256enc.proof: aes256enc.aig aes256enc.saw AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes256enc.saw
	touch aes256enc.proof

aes128dec.proof: aes128dec.aig aes128dec.saw AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes128dec.saw
	touch aes128dec.proof

aes256dec.proof: aes256dec.aig aes256dec.saw AESTBox.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw aes256dec.saw
	touch aes256dec.proof

sha1.proof: sha1.aig sha1.saw sha1.cry
	PATH=$(PATH):$(Z3) $(SAW)/bin/saw sha1.saw
	touch aes256dec.proof
