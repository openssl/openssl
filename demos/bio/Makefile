CFLAGS_demos_bio= -g -I../../include
LIBS_demos_bio= -L../.. ../../libssl.a ../../libcrypto.a -ldl
EXAMPLES_demos_bio=saccept sconnect client-arg client-conf

all: all_demos_bio
all_demos_bio: $(EXAMPLES_demos_bio) 

saccept: saccept.o
	$(CC) -o saccept saccept.o $(LIBS_demos_bio)

sconnect: sconnect.o
	$(CC) -o sconnect sconnect.o $(LIBS_demos_bio)

client-arg: client-arg.o
	$(CC) -o client-arg client-arg.o $(LIBS_demos_bio)

client-conf: client-conf.o
	$(CC) -o client-conf client-conf.o $(LIBS_demos_bio)

clean: clean_demos_bio
clean_demos_bio:	
	rm -f $(EXAMPLES_demos_bio) *.o

.c.o:
	$(CC) $(CFLAGS_demos_bio) $(CPPFLAGS) -c -o $@ $<
