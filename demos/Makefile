MODULES=bio digest encode encrypt kdf keyexch mac pkey signature sslecho

all:
	@set -e; for i in $(MODULES); do \
		${MAKE} -C $$i all; \
	done
clean:
	@set -e; for i in $(MODULES); do \
		${MAKE} -C $$i clean; \
	done
test:
	@set -e; for i in $(MODULES); do \
		${MAKE} -C $$i test; \
	done
