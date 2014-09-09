#
# OpenSSL/tools/GNUmakefile
#

include tools/Makefile
-include $(SRC_tools:.c=.d)

tools/%.o: tools/%.c
	$(CC) $(CFLAGS_tools) $(CPPFLAGS) -c -o $@ $<
