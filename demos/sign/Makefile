CFLAGS_demos_sign= -g -I../../include -Wall
LIBS_demos_sign=  -L. -lcrypto
EXAMPLES_demos_sign=sign

all: all_demos_sign
all_demos_sign: $(EXAMPLES_demos_sign) 

demos/sign/sign: demos/sign/sign.o
	$(CC) -o demos/sign/sign demos/sign/sign.o $(LIBS_demos_sign)

clean: clean_demos_sign
clean_demos_sign:	
	rm -f $(EXAMPLES_demos_sign) demos/sign/*.o

test: test_demos_sign
test_demos_sign: all_demos_sign
	demos/sign/sign

