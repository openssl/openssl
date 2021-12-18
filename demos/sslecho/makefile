PROG ?= sslecho

# Set OPENSSL_V3 to '1' to build directly from the OpenSSL tree using openssl.so.3.
# You must 'Configure/make' OpenSSL to create the headers and libs.
#
# Set to '0' to build from system that has libssl.so.1.1 and it's headers.
# The include and library paths shown are from a Linux Mint 20.2 system, and
# should be the same for Ubuntu.
#
OPENSSL_V3 = 0

all: $(PROG)

# Debug version.
#
$(PROG): main.c

ifeq ($(OPENSSL_V3) , 1)

	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) main.c -lssl -lcrypto

else

	$(CC) -O0 -g3 -W -Wall -I/usr/include/openssl -L/usr/lib/x86_64-linux-gnu -o $(PROG) main.c -lssl -lcrypto

endif

clean:
	rm -rf $(PROG) *.o *.obj
