CFLAGS= -g -I../../include -Wall
LIBS=  -L../.. -lcrypto
EXAMPLES=prime

all: all_demos_prime
all_demos_prime: $(EXAMPLES) 

prime: prime.o
	$(CC) -o prime prime.o $(LIBS)

clean: clean_demos_prime
clean_demos_prime:	
	rm -f $(EXAMPLES) *.o

test: test_demos_prime
test_demos_prime: all
	@echo Test creating a 128-bit prime
	./prime 128
	@echo Test creating a 256-bit prime
	./prime 256
	@echo Test creating a 512-bit prime
	./prime 512
