#
# OpenSSL/ssl/GNUmakefile
#

include ssl/Makefile
-include $(SRC_ssl:.c=.d)

ifdef SHARED_LIBS
$(SHARED_LIB_ssl): ssl/lib
shared_ssl: $(SHARED_LIB_ssl)
else
all_ssl: ssl/lib
shared_ssl:
endif

ssl/%.o: ssl/%.c
	$(CC) $(CFLAGS_ssl) $(CPPFLAGS) -c -o $@ $<
