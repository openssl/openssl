#
# OpenSSL/demos/err/GNUmakefile
#

include demos/err/Makefile
-include $(SRC_demos_err:.c=.d)

demos/err/%.o: demos/err/%.c
	$(CC) $(CFLAGS_demos_err) $(CPPFLAGS) -c -o $@ $<
