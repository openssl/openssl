#
# OpenSSL/demos/engines/zencod/GNUmakefile
#

include demos/engines/zencod/Makefile
-include $(SRC_demos_engines_zencod:.c=.d)

demos/engines/zencod/%.o: demos/engines/zencod/%.c
	$(CC) $(CFLAGS_demos_engines_zencod) $(CPPFLAGS) -c -o $@ $<
