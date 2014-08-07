#
# OpenSSL/test/GNUmakefile
#

include test/Makefile
-include $(SRC_test:.c=.d)

test/%.o: test/%.c
	$(CC) $(CFLAGS_test) $(CPPFLAGS) -c -o $@ $<
