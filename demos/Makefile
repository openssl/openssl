MODULES= bio digest encode encrypt kdf keyexch mac pkcs12 pkey signature sslecho
all:
	@ : 
	@set -e; for i in $(MODULES); do \
		( cd $$i; ${MAKE} all); \
	done
clean:
	@ : 
	@set -e; for i in $(MODULES); do \
		( cd $$i; ${MAKE} clean); \
	done
test:
	@ : 
	@set -e; for i in $(MODULES); do \
		( cd $$i; ${MAKE} test); \
	done