$!
$! Compile crypto.c as several subset modules and insert in crypto-xxx.olb.
$! If P1 is specifed, it specifies alternate list of subsets to compile.
$!
$ libname = "CRYPTO-AXP.OLB"
$ subset_list = "LIB,ASN1,BN,BUFFER,CONF,DES,DH,DSA,ERROR,EVP,IDEA,LHASH,MD," + -
	"METH,OBJECTS,PEM,RAND,RC,RSA,SHA,STACK,TXT_DB,X509"
$ if p1 .nes. "" then subset_list = p1
$!
$ if f$getsyi("CPU") .lt. 128 then libname = "CRYPTO-VAX.OLB"
$ if f$search(libname) .eqs. "" then library/create/object/log 'libname'
$!
$ cc = "cc/include=[-.include]/prefix=all" + P2
$!
$ i = 0
$ next_subset:
$    subset = f$element(i,",",subset_list)
$    if subset .eqs. "," then goto done
$    i = i + 1
$    create crypto_'subset'.subset
#include "crypto.c"
$    ofile = "sys$disk:[]crypto_" + subset + ".obj"
$    on warning then goto next_subset
$    write sys$output "Compiling ", ofile
$    cc /object='ofile' crypto_'subset'.subset -
	/define=(CRYPTO_SUBSET,CRYPTO_'subset'_SUBSET)
$    library/replace/log 'libname'/module=CRYPTO_'subset' 'ofile'
$    goto next_subset
$!
$ done:
$ exit
