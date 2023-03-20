#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./rsa_encode

CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto

TESTS=ec_encode rsa_encode

all: $(TESTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%_encode: %_encode.o

test:

clean:
	$(RM) *.o $(TESTS)
