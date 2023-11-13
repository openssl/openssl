#
# To run the demo when linked with a shared library (default) ensure that
# libcrypto and libssl are on the library path. For example:
#
#    LD_LIBRARY_PATH=../.. ./ossl-nghttp3-demo www.example.com:443

CFLAGS  = -I../../include -g -Wall -Wsign-compare
LDFLAGS = -L../..
LDLIBS  = -lcrypto -lssl -lnghttp3

all: ossl-nghttp3-demo

clean:
	$(RM) ossl-nghttp3-demo *.o

ossl-nghttp3-demo: ossl-nghttp3-demo.o ossl-nghttp3.o
	$(CC) $(CFLAGS) -o "$@" $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"
