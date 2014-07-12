# Minimal makefile to generate error codes and link a test app
SRC_demos_err= main.c
OBJ_demos_err= main.o
HEADER_demos_err=test_err.h
ERROBJ= test_err.o
CFLAGS_demos_err=-I../../include
LDFLAGS_demos_err=-L../.. -lcrypto


testapp: $(OBJ_demos_err) $(ERROBJ) $(HEADER_demos_err)
	$(CC) -o testapp $(OBJ_demos_err) $(ERROBJ) $(LDFLAGS_demos_err)
	
errors: errors_demos_err
errors_demos_err:
	$(PERL) ../../util/mkerr.pl -conf test_err.ec \
		-nostatic -write $(SRC_demos_err)

.c.o:
	$(CC) $(CFLAGS_demos_err) $(CPPFLAGS) -c -o $@ $<
