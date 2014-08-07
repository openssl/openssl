#
# OpenSSL/engines/ccgost/GNUmakefile
#

include engines/ccgost/Makefile
-include $(SRC_engines_ccgost:.c=.d)

engines/ccgost/%.o: engines/ccgost/%.c
	$(CC) $(CFLAGS_engines_ccgost) $(CPPFLAGS) -c -o $@ $<
