#
# OpenSSL/ssl/GNUmakefile
#

include ssl/Makefile
-include $(SRC_ssl:.c=.d)

ssl/%.o: ssl/%.c
	$(CC) $(CFLAGS_ssl) $(CPPFLAGS) -c -o $@ $<
