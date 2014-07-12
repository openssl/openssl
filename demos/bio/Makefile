CFLAGS= -g -I../../include
LIBS= -L../.. ../../libssl.a ../../libcrypto.a -ldl
EXAMPLES=saccept sconnect client-arg client-conf

all: all_demos_bio
all_demos_bio: $(EXAMPLES) 

saccept: saccept.o
	$(CC) -o saccept saccept.o $(LIBS)

sconnect: sconnect.o
	$(CC) -o sconnect sconnect.o $(LIBS)

client-arg: client-arg.o
	$(CC) -o client-arg client-arg.o $(LIBS)

client-conf: client-conf.o
	$(CC) -o client-conf client-conf.o $(LIBS)

clean: clean_demos_bio
clean_demos_bio:	
	rm -f $(EXAMPLES) *.o

