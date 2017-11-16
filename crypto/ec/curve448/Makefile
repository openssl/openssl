all: libcurve448.so.1 curve448_test

shake.o: shake.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -c -o shake.o shake.c

arch_x86_64/f_impl.o: arch_x86_64/f_impl.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o arch_x86_64/f_impl.o arch_x86_64/f_impl.c

f_arithmetic.o: f_arithmetic.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o f_arithmetic.o f_arithmetic.c

f_generic.o: f_generic.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o f_generic.o f_generic.c

scalar.o: scalar.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o scalar.o scalar.c

decaf_tables.o: decaf_tables.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o decaf_tables.o decaf_tables.c

decaf.o: decaf.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o decaf.o decaf.c

eddsa.o: eddsa.c
	gcc -std=c99 -fno-strict-aliasing -pedantic -Wall -Wextra -Werror -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -O2 -march=native  -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC  -I . -I../../../include -I arch_x86_64 -c -o eddsa.o eddsa.c

libcurve448.so.1: shake.o arch_x86_64/f_impl.o f_arithmetic.o f_generic.o scalar.o decaf_tables.o eddsa.o decaf.o
	gcc  -shared -Wl,-soname,libcurve448.so.1,-z,defs -Wl,--gc-sections -o libcurve448.so.1 shake.o arch_x86_64/f_impl.o f_arithmetic.o f_generic.o scalar.o decaf_tables.o eddsa.o decaf.o -L../../.. -lcrypto 

curve448_test: curve448_test.c
	gcc -g -I. -I../../../include -L../../.. -L. -o curve448_test curve448_test.c -lcurve448 -lcrypto

test:
	../../../util/shlib_wrap.sh ./curve448_test

testfull:
	../../../util/shlib_wrap.sh ./curve448_test -f

clean:
	rm shake.o arch_x86_64/f_impl.o f_arithmetic.o f_generic.o scalar.o decaf_tables.o decaf.o eddsa.o libcurve448.so.1 curve448_test
