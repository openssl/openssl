CC=cc
CFLAGS= -g -I../../include
LIBS= -L/usr/local/ssl/lib -L../.. -lcrypto
EXAMPLES=example1 example2 example3 example4

all: $(EXAMPLES) 

example1: example1.o loadkeys.o 
	$(CC) -o example1 example1.o loadkeys.o $(LIBS)

example2: example2.o loadkeys.o
	$(CC) -o example2 example2.o loadkeys.o $(LIBS)

example3: example3.o 
	$(CC) -o example3 example3.o $(LIBS)

example4: example4.o
	$(CC) -o example4 example4.o $(LIBS)

	
clean:	
	rm -f $(EXAMPLES) *.o

