$! TESTS.COM  --  Performs the necessary tests
$!
$! P1	tests to be performed.  Empty means all.
$
$	__proc = f$element(0,";",f$environment("procedure"))
$	__here = f$parse(f$parse("A.;",__proc) - "A.;","[]A.;") - "A.;"
$	__save_default = f$environment("default")
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$	texe_dir := sys$disk:[-.'__arch'.exe.test]
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	set default '__here'
$	on control_y then goto exit
$	on error then goto exit
$
$	if p1 .nes. ""
$	then
$	    tests = p1
$	else
$	    tests := -
	test_des,test_idea,test_sha,test_md5,test_hmac,test_md2,test_mdc2,-
	test_rc2,test_rc4,test_rc5,test_bf,test_cast,-
	test_rand,test_bn,test_enc,test_x509,test_rsa,test_crl,test_sid,-
	test_reqgen,test_req,test_pkcs7,test_verify,test_dh,test_dsa,-
	test_ss,test_ssl,test_ca
$	endif
$	tests = f$edit(tests,"COLLAPSE")
$
$	BNTEST :=	bntest
$	EXPTEST :=	exptest
$	IDEATEST :=	ideatest
$	SHATEST :=	shatest
$	SHA1TEST :=	sha1test
$	MDC2TEST :=	mdc2test
$	RMDTEST :=	rmdtest
$	MD2TEST :=	md2test
$	MD5TEST :=	md5test
$	HMACTEST :=	hmactest
$	RC2TEST :=	rc2test
$	RC4TEST :=	rc4test
$	RC5TEST :=	rc5test
$	BFTEST :=	bftest
$	CASTTEST :=	casttest
$	DESTEST :=	destest
$	RANDTEST :=	randtest
$	DHTEST :=	dhtest
$	DSATEST :=	dsatest
$	METHTEST :=	methtest
$	SSLTEST :=	ssltest
$	RSATEST :=	rsa_oaep_test
$
$	tests_i = 0
$ loop_tests:
$	tests_e = f$element(tests_i,",",tests)
$	tests_i = tests_i + 1
$	if tests_e .eqs. "," then goto exit
$	goto 'tests_e'
$
$ test_des:
$	mcr 'texe_dir''destest'
$	goto loop_tests
$ test_idea:
$	mcr 'texe_dir''ideatest'
$	goto loop_tests
$ test_sha:
$	mcr 'texe_dir''shatest'
$	mcr 'texe_dir''sha1test'
$	goto loop_tests
$ test_mdc2:
$	mcr 'texe_dir''mdc2test'
$	goto loop_tests
$ test_md5:
$	mcr 'texe_dir''md5test'
$	goto loop_tests
$ test_hmac:
$	mcr 'texe_dir''hmactest'
$	goto loop_tests
$ test_md2:
$	mcr 'texe_dir''md2test'
$	goto loop_tests
$ test_rmd:
$	mcr 'texe_dir''rmdtest'
$	goto loop_tests
$ test_bf:
$	mcr 'texe_dir''bftest'
$	goto loop_tests
$ test_cast:
$	mcr 'texe_dir''casttest'
$	goto loop_tests
$ test_rc2:
$	mcr 'texe_dir''rc2test'
$	goto loop_tests
$ test_rc4:
$	mcr 'texe_dir''rc4test'
$	goto loop_tests
$ test_rc5:
$	mcr 'texe_dir''rc5test'
$	goto loop_tests
$ test_rand:
$	mcr 'texe_dir''randtest'
$	goto loop_tests
$ test_enc:
$	@testenc.com
$	goto loop_tests
$ test_x509:
$	define sys$error nla0:
$	write sys$output "test normal x509v1 certificate"
$	@tx509.com
$	write sys$output "test first x509v3 certificate"
$	@tx509.com v3-cert1.pem
$	write sys$output "test second x509v3 certificate"
$	@tx509.com v3-cert2.pem
$	deassign sys$error
$	goto loop_tests
$ test_rsa:
$	define sys$error nla0:
$	@trsa.com
$	deassign sys$error
$	mcr 'texe_dir''rsatest'
$	goto loop_tests
$ test_crl:
$	define sys$error nla0:
$	@tcrl.com
$	deassign sys$error
$	goto loop_tests
$ test_sid:
$	define sys$error nla0:
$	@tsid.com
$	deassign sys$error
$	goto loop_tests
$ test_req:
$	define sys$error nla0:
$	@treq.com
$	@treq.com testreq2.pem
$	deassign sys$error
$	goto loop_tests
$ test_pkcs7:
$	define sys$error nla0:
$	@tpkcs7.com
$	@tpkcs7d.com
$	deassign sys$error
$	goto loop_tests
$ test_bn:
$	write sys$output "starting big number library test, could take a while..."
$	create bntest-vms.fdl
FILE
	ORGANIZATION	sequential
RECORD
	FORMAT		stream_lf
$	create/fdl=bntest-vms.fdl bntest-vms.sh
$	open/append foo bntest-vms.sh
$	type/output=foo: sys$input:
<< __FOO__ bc | awk '{ \
if ($$0 != "0") {print "error"; exit(1); } \
if (((NR+1)%64) == 0) print NR+1," tests done"; }'
$	define/user sys$output bntest-vms.tmp
$	mcr 'texe_dir''bntest'
$	copy bntest-vms.tmp foo:
$	delete bntest-vms.tmp;*
$	type/output=foo: sys$input:
__FOO__
$	close foo
$	write sys$output "-- copy the [.test]bntest-vms.sh file to a Unix system and run it"
$	write sys$output "-- through sh or bash to verify that the bignum operations went well."
$	write sys$output ""
$	write sys$output "test a^b%c implementations"
$	mcr 'texe_dir''exptest'
$	goto loop_tests
$ test_verify:
$	write sys$output "The following command should have some OK's and some failures"
$	write sys$output "There are definitly a few expired certificates"
$	@tverify.com
$	goto loop_tests
$ test_dh:
$	write sys$output "Generate as set of DH parameters"
$	mcr 'texe_dir''dhtest'
$	goto loop_tests
$ test_dsa:
$	write sys$output "Generate as set of DSA parameters"
$	mcr 'texe_dir''dsatest'
$	goto loop_tests
$ test_reqgen:
$	write sys$output "Generate and verify a certificate request"
$	@testgen.com
$	goto loop_tests
$ test_ss:
$	write sys$output "Generate and certify a test certificate"
$	@testss.com
$	goto loop_tests
$ test_ssl:
$	write sys$output "test SSL protocol"
$	@testssl.com
$	goto loop_tests
$ test_ca:
$	write sys$output "Generate and certify a test certificate via the 'ca' program"
$	@testca.com
$	goto loop_tests
$
$
$ exit:
$	set default '__save_default'
$	exit
