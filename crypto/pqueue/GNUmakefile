#
# OpenSSL/crypto/pqueue/GNUmakefile
#

include crypto/pqueue/Makefile
-include $(SRC_crypto_pqueue:.c=.d)

crypto/pqueue/%.o: crypto/pqueue/%.c
	$(CC) $(CFLAGS_crypto_pqueue) $(CPPFLAGS) -c -o $@ $<
