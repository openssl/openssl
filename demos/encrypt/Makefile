#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./rsa_encrypt

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto

all: rsa_encrypt

%.o: %.c
	$(CC) $(CFLAGS) -c $<

rsa_encrypt: rsa_encrypt.o

test: ;

clean:
	$(RM) *.o rsa_encrypt
