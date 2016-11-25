CC=cl6x
CFLAGS=-mv$${C6XSILICON:-6400+} -o2 -I. -Ic6x/inc -Ifips -DNO_SYS_TYPES_H
OBJ_D=c6x/tmp
OUT_D=c6x

all:	$(OUT_D)/fips_algvs.out

$(OBJ_D)/fips_algvs.obj:	test/fips_algvs.c
	$(CC) --obj_directory=$(OBJ_D) $(CFLAGS) -c $<

$(OUT_D)/fips_algvs.out:	$(OBJ_D)/fips_algvs.obj $(OUT_D)/fipscanister.obj c6x/fips_algvs.cmd
	$(OUT_D)/fips_standalone_sha1 -verify $(OUT_D)/fipscanister.obj
	$(CC) -z -o $@ -m $(OUT_D)/fips_algvs.map $< $(OUT_D)/fipscanister.obj c6x/fips_algvs.cmd
	$(OUT_D)/incore6x $@ || rm $@
