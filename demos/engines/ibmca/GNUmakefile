#
# OpenSSL/demos/engines/ibmca/GNUmakefile
#

include demos/engines/ibmca/Makefile
-include $(SRC_demos_engines_ibmca:.c=.d)

demos/engines/ibmca/%.o: demos/engines/ibmca/%.c
	$(CC) $(CFLAGS_demos_engines_ibmca) $(CPPFLAGS) -c -o $@ $<
