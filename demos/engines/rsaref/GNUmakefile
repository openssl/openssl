#
# OpenSSL/demos/engines/rsaref/GNUmakefile
#

include demos/engines/rsaref/Makefile
-include $(SRC_demos_engines_rsaref:.c=.d)

demos/engines/rsaref/%.o: demos/engines/rsaref/%.c
	$(CC) $(CFLAGS_demos_engines_rsaref) $(CPPFLAGS) -c -o $@ $<
