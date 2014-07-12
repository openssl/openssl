CFLAGS_demos_prime= -g -I../../include -Wall
LIBS_demos_prime=  -L../.. -lcrypto
EXAMPLES_demos_prime=prime

all: all_demos_prime
all_demos_prime: $(EXAMPLES_demos_prime) 

prime: prime.o
	$(CC) -o prime prime.o $(LIBS_demos_prime)

clean: clean_demos_prime
clean_demos_prime:	
	rm -f $(EXAMPLES_demos_prime) *.o

test: test_demos_prime
test_demos_prime: all
	@echo Test creating a 128-bit prime
	./prime 128
	@echo Test creating a 256-bit prime
	./prime 256
	@echo Test creating a 512-bit prime
	./prime 512

.c.o:
	$(CC) $(CFLAGS_demos_prime) $(CPPFLAGS) -c -o $@ $<
