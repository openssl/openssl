# Minimal makefile to generate error codes and link a test app
SRC= main.c
OBJ= main.o
HEADER=test_err.h
ERROBJ= test_err.o
CC=gcc
CFLAGS=-I../../include
LDFLAGS=-L../.. -lcrypto

PERL=perl

testapp: $(OBJ) $(ERROBJ) $(HEADER)
	$(CC) -o testapp $(OBJ) $(ERROBJ) $(LDFLAGS)
	
errors:
	$(PERL) ../../util/mkerr.pl -conf test_err.ec \
		-nostatic -write $(SRC)
