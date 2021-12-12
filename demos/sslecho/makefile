PROG ?= sslecho

all: $(PROG)

# Debug version.
#
$(PROG): main.c
	$(CC) -O0 -g3 -W -Wall -I/usr/include/openssl -L/usr/lib/x86_64-linux-gnu -o $(PROG) main.c -lssl -lcrypto

clean:
	rm -rf $(PROG) *.o *.obj
