$! To compile mttest on VMS.
$!
$! WARNING: only tested with DEC C so far.
$!
$!
$!
$! Define USER_CCFLAGS
$!
$ @[--]vms_build_info.com
$ WRITE SYS$OUTPUT " Using USER_CCFLAGS = ", USER_CCFLAGS
$
$ arch := vax
$ if f$getsyi("CPU") .ge. 128 then arch := axp
$ define/user openssl [--.include.openssl]
$ cc/def=PTHREADS mttest.c
$ link /MAP/FULL/CROSS mttest, -
	[--.'arch'.exe.ssl]libssl/lib, -
	[--.'arch'.exe.crypto]libcrypto/lib, -
	SYS$DISK:[--]SSL_IDENT.OPT/OPTION

