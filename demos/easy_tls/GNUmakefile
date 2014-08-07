#
# OpenSSL/demos/easy_tls/GNUmakefile
#

include demos/easy_tls/Makefile
-include $(SRC_demos_easy_tls:.c=.d)

demos/easy_tls/%.o: demos/easy_tls/%.c
	$(CC) $(CFLAGS_demos_easy_tls) $(CPPFLAGS) -c -o $@ $<
