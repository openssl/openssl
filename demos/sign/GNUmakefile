#
# OpenSSL/demos/sign/GNUmakefile
#

include demos/sign/Makefile
-include $(SRC_demos_sign:.c=.d)

demos/sign/%.o: demos/sign/%.c
	$(CC) $(CFLAGS_demos_sign) $(CPPFLAGS) -c -o $@ $<
