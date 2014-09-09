#
# OpenSSL/apps/GNUmakefile
#

include apps/Makefile
-include $(SRC_apps:.c=.d)

apps/%.o: apps/%.c
	$(CC) $(CFLAGS_apps) $(CPPFLAGS) -c -o $@ $<
