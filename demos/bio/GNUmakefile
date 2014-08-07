#
# OpenSSL/demos/bio/GNUmakefile
#

include demos/bio/Makefile
-include $(SRC_demos_bio:.c=.d)

demos/bio/%.o: demos/bio/%.c
	$(CC) $(CFLAGS_demos_bio) $(CPPFLAGS) -c -o $@ $<
