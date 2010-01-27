$! TESTS.COM  --  Performs the necessary tests
$!
$! P1	tests to be performed.  Empty means all.
$
$	__proc = f$element(0,";",f$environment("procedure"))
$	__here = f$parse(f$parse("A.;",__proc) - "A.;","[]A.;") - "A.;"
$	__save_default = f$environment("default")
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then -
	   __arch = f$edit( f$getsyi( "ARCH_NAME"), "UPCASE")
$	if __arch .eqs. "" then __arch := UNK
$	texe_dir := sys$disk:[-.'__arch'.exe.test]
$	exe_dir := sys$disk:[-.'__arch'.exe.apps]
$
$	sslroot = f$parse("sys$disk:[-.apps];",,,,"syntax_only") - "].;"+ ".]"
$	define /translation_attributes = concealed sslroot 'sslroot'
$
$	set default '__here'
$
$	on control_y then goto exit
$	on error then goto exit
$
$	if p1 .nes. ""
$	then
$	    tests = p1
$	else
$! NOTE: This list reflects the list of dependencies following the
$! "alltests" target in Makefile.  This should make it easy to see
$! if there's a difference that needs to be taken care of.
$	    tests := -
	test_des,test_idea,test_sha,test_md4,test_md5,test_hmac,-
	test_md2,test_mdc2,test_wp,-
	test_rmd,test_rc2,test_rc4,test_rc5,test_bf,test_cast,test_aes,-
	test_rand,test_bn,test_ec,test_ecdsa,test_ecdh,-
	test_enc,test_x509,test_rsa,test_crl,test_sid,-
	test_gen,test_req,test_pkcs7,test_verify,test_dh,test_dsa,-
	test_ss,test_ca,test_engine,test_evp,test_ssl,test_tsa,test_ige,-
	test_jpake,test_cms
$	endif
$	tests = f$edit(tests,"COLLAPSE")
$
$	BNTEST :=	bntest
$	ECTEST :=	ectest
$	ECDSATEST :=	ecdsatest
$	ECDHTEST :=	ecdhtest
$	EXPTEST :=	exptest
$	IDEATEST :=	ideatest
$	SHATEST :=	shatest
$	SHA1TEST :=	sha1test
$	MDC2TEST :=	mdc2test
$	RMDTEST :=	rmdtest
$	MD2TEST :=	md2test
$	MD4TEST :=	md4test
$	MD5TEST :=	md5test
$	HMACTEST :=	hmactest
$	WPTEST :=	wp_test
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
$	RSATEST :=	rsa_test
$	ENGINETEST :=	enginetest
$	EVPTEST :=	evp_test
$	IGETEST :=	igetest
$	JPAKETEST :=	jpaketest
$
$	tests_i = 0
$ loop_tests:
$	tests_e = f$element(tests_i,",",tests)
$	tests_i = tests_i + 1
$	if tests_e .eqs. "," then goto exit
$	gosub 'tests_e'
$	goto loop_tests
$
$ test_evp:
$	mcr 'texe_dir''evptest' evptests.txt
$	return
$ test_des:
$	mcr 'texe_dir''destest'
$	return
$ test_idea:
$	mcr 'texe_dir''ideatest'
$	return
$ test_sha:
$	mcr 'texe_dir''shatest'
$	mcr 'texe_dir''sha1test'
$	return
$ test_mdc2:
$	mcr 'texe_dir''mdc2test'
$	return
$ test_md5:
$	mcr 'texe_dir''md5test'
$	return
$ test_md4:
$	mcr 'texe_dir''md4test'
$	return
$ test_hmac:
$	mcr 'texe_dir''hmactest'
$	return
$ test_wp:
$	mcr 'texe_dir''wptest'
$	return
$ test_md2:
$	mcr 'texe_dir''md2test'
$	return
$ test_rmd:
$	mcr 'texe_dir''rmdtest'
$	return
$ test_bf:
$	mcr 'texe_dir''bftest'
$	return
$ test_cast:
$	mcr 'texe_dir''casttest'
$	return
$ test_rc2:
$	mcr 'texe_dir''rc2test'
$	return
$ test_rc4:
$	mcr 'texe_dir''rc4test'
$	return
$ test_rc5:
$	mcr 'texe_dir''rc5test'
$	return
$ test_rand:
$	mcr 'texe_dir''randtest'
$	return
$ test_enc:
$	@testenc.com
$	return
$ test_x509:
$	define sys$error nla0:
$	write sys$output "test normal x509v1 certificate"
$	@tx509.com
$	write sys$output "test first x509v3 certificate"
$	@tx509.com v3-cert1.pem
$	write sys$output "test second x509v3 certificate"
$	@tx509.com v3-cert2.pem
$	deassign sys$error
$	return
$ test_rsa:
$	define sys$error nla0:
$	@trsa.com
$	deassign sys$error
$	mcr 'texe_dir''rsatest'
$	return
$ test_crl:
$	define sys$error nla0:
$	@tcrl.com
$	deassign sys$error
$	return
$ test_sid:
$	define sys$error nla0:
$	@tsid.com
$	deassign sys$error
$	return
$ test_req:
$	define sys$error nla0:
$	@treq.com
$	@treq.com testreq2.pem
$	deassign sys$error
$	return
$ test_pkcs7:
$	define sys$error nla0:
$	@tpkcs7.com
$	@tpkcs7d.com
$	deassign sys$error
$	return
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
<< __FOO__ sh -c "`sh ./bctest`" | perl -e '$i=0; while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $1";} elsif (!/^0$/) {die "\nFailed! bc: $_";} else {print STDERR "."; $i++;}} print STDERR "\n$i tests passed\n"'
$	define/user sys$output bntest-vms.tmp
$	mcr 'texe_dir''bntest'
$	copy bntest-vms.tmp foo:
$	delete bntest-vms.tmp;*
$	type/output=foo: sys$input:
__FOO__
$	close foo
$	write sys$output "-- copy the [.test]bntest-vms.sh and [.test]bctest files to a Unix system and"
$	write sys$output "-- run bntest-vms.sh through sh or bash to verify that the bignum operations"
$	write sys$output "-- went well."
$	write sys$output ""
$	write sys$output "test a^b%c implementations"
$	mcr 'texe_dir''exptest'
$	return
$ test_ec:
$	write sys$output "test elliptic curves"
$	mcr 'texe_dir''ectest'
$	return
$ test_ecdsa:
$	write sys$output "test ecdsa"
$	mcr 'texe_dir''ecdsatest'
$	return
$ test_ecdh:
$	write sys$output "test ecdh"
$	mcr 'texe_dir''ecdhtest'
$	return
$ test_verify:
$	write sys$output "The following command should have some OK's and some failures"
$	write sys$output "There are definitly a few expired certificates"
$	@tverify.com
$	return
$ test_dh:
$	write sys$output "Generate a set of DH parameters"
$	mcr 'texe_dir''dhtest'
$	return
$ test_dsa:
$	write sys$output "Generate a set of DSA parameters"
$	mcr 'texe_dir''dsatest'
$	return
$ test_gen:
$	write sys$output "Generate and verify a certificate request"
$	@testgen.com
$	return
$ maybe_test_ss:
$	testss_RDT = f$cvtime(f$file_attributes("testss.com","RDT"))
$	if f$cvtime(f$file_attributes("keyU.ss","RDT")) .les. testss_RDT then -
		goto test_ss
$	if f$cvtime(f$file_attributes("certU.ss","RDT")) .les. testss_RDT then -
		goto test_ss
$	if f$cvtime(f$file_attributes("certCA.ss","RDT")) .les. testss_RDT then -
		goto test_ss
$	return
$ test_ss:
$	write sys$output "Generate and certify a test certificate"
$	@testss.com
$	return
$ test_engine: 
$	write sys$output "Manipulate the ENGINE structures"
$	mcr 'texe_dir''enginetest'
$	return
$ test_ssl:
$	write sys$output "test SSL protocol"
$	gosub maybe_test_ss
$	@testssl.com keyU.ss certU.ss certCA.ss
$	return
$ test_ca:
$	set noon
$	define/user sys$output nla0:
$	mcr 'exe_dir'openssl no-rsa
$	save_severity=$SEVERITY
$	set on
$	if save_severity
$	then
$	    write sys$output "skipping CA.com test -- requires RSA"
$	else
$	    write sys$output "Generate and certify a test certificate via the 'ca' program"
$	    @testca.com
$	endif
$	return
$ test_aes: 
$!	write sys$output "test AES"
$!	!mcr 'texe_dir''aestest'
$	return
$ test_tsa:
$	set noon
$	define/user sys$output nla0:
$	mcr 'exe_dir'openssl no-rsa
$	save_severity=$SEVERITY
$	set on
$	if save_severity
$	then
$	    write sys$output "skipping testtsa.com test -- requires RSA"
$	else
$	    @testtsa.com
$	endif
$	return
$ test_ige: 
$	write sys$output "Test IGE mode"
$	mcr 'texe_dir''igetest'
$	return
$ test_jpake: 
$	write sys$output "Test JPAKE"
$	mcr 'texe_dir''jpaketest'
$	return
$ test_cms:
$	write sys$output "CMS consistency test"
$	perl CMS-TEST.PL
$	return
$
$
$ exit:
$	set default '__save_default'
$	deassign sslroot
$	exit
