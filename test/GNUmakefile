#
# OpenSSL/test/GNUmakefile
#

include test/Makefile
-include $(SRC_test:.c=.d)

test/%.o: test/%.c
	$(CC) $(CFLAGS_test) $(CPPFLAGS) -c -o $@ $<

# Any reason not to just leave these on?
export OPENSSL_DEBUG_MEMORY=on
export OPENSSL_CONF=apps/openssl.cnf
