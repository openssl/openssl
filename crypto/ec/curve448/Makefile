all: libcurve448.so.1 curve448_test

arch_32/f_impl.o: arch_32/f_impl.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o arch_32/f_impl.o arch_32/f_impl.c

f_arithmetic.o: f_arithmetic.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o f_arithmetic.o f_arithmetic.c

f_generic.o: f_generic.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o f_generic.o f_generic.c

scalar.o: scalar.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o scalar.o scalar.c

curve448_tables.o: curve448_tables.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o curve448_tables.o curve448_tables.c

curve448.o: curve448.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o curve448.o curve448.c

eddsa.o: eddsa.c
	gcc -std=c90 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_32 -c -o eddsa.o eddsa.c

libcurve448.so.1: arch_32/f_impl.o f_arithmetic.o f_generic.o scalar.o curve448_tables.o eddsa.o curve448.o
	gcc -shared -Wl,-soname,libcurve448.so.1,-z,defs -Wl,--gc-sections -o libcurve448.so.1 arch_32/f_impl.o f_arithmetic.o f_generic.o scalar.o curve448_tables.o eddsa.o curve448.o -L../../.. -lcrypto
	ln -f -s libcurve448.so.1 libcurve448.so

curve448_test: curve448_test.c
	gcc -g -I. -I../../../include -L../../.. -L. -o curve448_test curve448_test.c -lcurve448 -lcrypto

test:
	../../../util/shlib_wrap.sh ./curve448_test

testfull:
	../../../util/shlib_wrap.sh ./curve448_test -f

clean:
	rm arch_32/f_impl.o f_arithmetic.o f_generic.o scalar.o curve448_tables.o curve448.o eddsa.o libcurve448.so.1 curve448_test libcurve448.so
