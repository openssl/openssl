CFLAGS_demos_bio= -g -I../../include
LIBS_demos_bio= -L. libssl.a libcrypto.a -ldl
EXAMPLES_demos_bio=saccept sconnect client-arg client-conf

all: all_demos_bio
all_demos_bio: $(EXAMPLES_demos_bio) 

demos/bio/saccept: demos/bio/saccept.o
	$(CC) -o demos/bio/saccept demos/bio/saccept.o $(LIBS_demos_bio)

demos/bio/sconnect: demos/bio/sconnect.o
	$(CC) -o demos/bio/sconnect demos/bio/sconnect.o $(LIBS_demos_bio)

demos/bio/client-arg: demos/bio/client-arg.o
	$(CC) -o demos/bio/client-arg demos/bio/client-arg.o $(LIBS_demos_bio)

demos/bio/client-conf: demos/bio/client-conf.o
	$(CC) -o demos/bio/client-conf demos/bio/client-conf.o $(LIBS_demos_bio)

clean: clean_demos_bio
clean_demos_bio:	
	rm -f $(EXAMPLES_demos_bio) demos/bio/*.o

