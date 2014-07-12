CFLAGS= -g -I../../include -Wall
LIBS=  -L../.. -lcrypto
EXAMPLES=sign

all: all_demos_sign
all_demos_sign: $(EXAMPLES) 

sign: sign.o
	$(CC) -o sign sign.o $(LIBS)

clean: clean_demos_sign
clean_demos_sign:	
	rm -f $(EXAMPLES) *.o

test: test_demos_sign
test_demos_sign: all
	./sign
