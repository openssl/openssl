CFLAGS = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS = -lcrypto -lssl -lnghttp3

all: ossl-nghttp3-demo

clean:
	$(RM) -f ossl-nghttp3-demo *.o

ossl-nghttp3-demo: ossl-nghttp3-demo.o ossl-nghttp3.o
	$(CC) $(CFLAGS) -o "$@" $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"
