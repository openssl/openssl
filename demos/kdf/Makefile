#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./hkdf

CFLAGS = -I../../include -g
LDFLAGS = -L../..
LDLIBS = -lcrypto

all: hkdf

%.o: %.c
	$(CC) $(CFLAGS) -c $<

hkdf: hkdf.o

test: ;

clean:
	$(RM) *.o hkdf
