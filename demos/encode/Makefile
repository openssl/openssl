#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./rsa_encode

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

all: rsa_encode

%.o: %.c
	$(CC) $(CFLAGS) -c $<

rsa_encode: rsa_encode.o

test: ;

clean:
	$(RM) *.o rsa_encode
