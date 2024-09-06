CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -z noexecstack
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all speed shared clean

all: test speed shared nistkat

test: \
  test/test_kyber512 \
  test/test_kyber768 \
  test/test_kyber1024 \
  test/test_vectors512 \
  test/test_vectors768 \
  test/test_vectors1024 \

speed: \
  test/test_speed512 \
  test/test_speed768 \
  test/test_speed1024 \

shared: \
  lib/libpqcrystals_kyber512_ref.so \
  lib/libpqcrystals_kyber768_ref.so \
  lib/libpqcrystals_kyber1024_ref.so \
  lib/libpqcrystals_fips202_ref.so \

nistkat: \
	nistkat/PQCgenKAT_kem512 \
	nistkat/PQCgenKAT_kem768 \
	nistkat/PQCgenKAT_kem1024 \


lib/libpqcrystals_fips202_ref.so: fips202.c fips202.h
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) fips202.c -o $@

lib/libpqcrystals_kyber512_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=2 $(SOURCES) symmetric-shake.c -o $@

lib/libpqcrystals_kyber768_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=3 $(SOURCES) symmetric-shake.c -o $@

lib/libpqcrystals_kyber1024_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=4 $(SOURCES) symmetric-shake.c -o $@

test/test_kyber512: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_kyber768: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_kyber1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_vectors512: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_vectors768: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_vectors1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_speed512: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed768: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

nistkat/PQCgenKAT_kem512: $(SOURCESKECCAK) $(HEADERSKECCAK) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(NISTFLAGS) -DKYBER_K=2 -o $@ $(SOURCESKECCAK) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto

nistkat/PQCgenKAT_kem768: $(SOURCESKECCAK) $(HEADERSKECCAK) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(NISTFLAGS) -DKYBER_K=3 -o $@ $(SOURCESKECCAK) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto

nistkat/PQCgenKAT_kem1024: $(SOURCESKECCAK) $(HEADERSKECCAK) nistkat/PQCgenKAT_kem.c nistkat/rng.c nistkat/rng.h
	$(CC) $(NISTFLAGS) -DKYBER_K=4 -o $@ $(SOURCESKECCAK) nistkat/rng.c nistkat/PQCgenKAT_kem.c $(LDFLAGS) -lcrypto

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test/test_kyber512
	-$(RM) -f test/test_kyber768
	-$(RM) -f test/test_kyber1024
	-$(RM) -f test/test_vectors512
	-$(RM) -f test/test_vectors768
	-$(RM) -f test/test_vectors1024
	-$(RM) -f test/test_speed512
	-$(RM) -f test/test_speed768
	-$(RM) -f test/test_speed1024
	-$(RM) -f nistkat/PQCgenKAT_kem512
	-$(RM) -f nistkat/PQCgenKAT_kem768
	-$(RM) -f nistkat/PQCgenKAT_kem1024
	-$(RM) -f nistkat/*.req
	-$(RM) -f nistkat/*.rsp
	-$(RM) -rf lib/

