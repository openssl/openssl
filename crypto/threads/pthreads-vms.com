$! To compile mttest on VMS.
$!
$! WARNING: only tested with DEC C so far.
$
$ arch := vax
$ if f$getsyi("CPU") .ge. 128 then arch := axp
$ define/user openssl [--.include.openssl]
$ cc/def=PTHREADS mttest.c
$ link mttest,[--.'arch'.exe.ssl]libssl/lib,[--.'arch'.exe.crypto]libcrypto/lib
