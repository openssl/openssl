#
# OpenSSL/demos/prime/GNUmakefile
#

include demos/prime/Makefile
-include $(SRC_demos_prime:.c=.d)

demos/prime/%.o: demos/prime/%.c
	$(CC) $(CFLAGS_demos_prime) $(CPPFLAGS) -c -o $@ $<
