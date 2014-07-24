# this is executed only when linking with external fipscanister.o
fips_standalone_sha1$(EXE_EXT):	sha/fips_standalone_sha1.c
	if [ -z "$(HOSTCC)" ] ; then \
		$(CC) $(CFLAGS_fips) -DFIPSCANISTER_O -o $@ sha/fips_standalone_sha1.c $(FIPSLIBDIR)fipscanister.o $(EX_LIBS) ; \
	else \
		$(HOSTCC) $(HOSTCFLAGS) -o $ $@ -I../include -I../crypto sha/fips_standalone_sha1.c ../crypto/sha/sha1dgst.c ; \
	fi
