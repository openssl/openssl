#
# OpenSSL/demos/engines/cluster_labs/GNUmakefile
#

include demos/engines/cluster_labs/Makefile
-include $(SRC_demos_engines_cluster_labs:.c=.d)

demos/engines/cluster_labs/%.o: demos/engines/cluster_labs/%.c
	$(CC) $(CFLAGS_demos_engines_cluster_labs) $(CPPFLAGS) -c -o $@ $<
