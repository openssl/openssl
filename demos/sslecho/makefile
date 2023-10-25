PROG ?= sslecho

all: $(PROG)

# Debug version.
#
$(PROG): main.c

	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) main.c -lssl -lcrypto

test:

clean:
	rm -rf $(PROG) *.o *.obj
