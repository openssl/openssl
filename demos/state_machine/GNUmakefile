#
# OpenSSL/demos/state_machine/GNUmakefile
#

include demos/state_machine/Makefile
-include $(SRC_demos_state_machine:.c=.d)

demos/state_machine/%.o: demos/state_machine/%.c
	$(CC) $(CFLAGS_demos_state_machine) $(CPPFLAGS) -c -o $@ $<
