$!
$! SSL$IVP.COM  --  Performs some tests to show that OpenSSL
$!		    was installed properly, and it working
$!		     correctly.  
$!
$! Note:  This command procedure is based heavily on TESTS.COM.
$!	  Any changes to this file should be considered for 
$!	  TESTS.COM as well.
$!
$! P1	tests to be performed.  Empty means all.
$
$	__proc = f$element(0,";",f$environment("procedure"))
$	__here = f$parse(f$parse("A.;",__proc) - "A.;","[]A.;") - "A.;"
$	__save_default = f$environment("default")
$	__arch := VAX
$	if f$getsyi("cpu") .ge. 128 then __arch := AXP
$!
$ show time
$!
$ arch_name = f$edit(f$getsyi("arch_name"),"UPCASE")
$!
$ texe_dir := ssl$root:[test]
$ exe_dir  := ssl$root:['arch_name'_EXE]
$!
$! set default '__here'
$ on control_y then goto exit
$!
$! Try to run through as many tests as possible
$! rather than exit out on the first error.
$!
$!	on error then goto exit
$
$	if p1 .nes. ""
$	then
$	    tests = p1
$	else
$	    tests := -
		test_des,test_idea,test_sha,test_md4,test_md5,test_hmac,-
		test_md2,test_mdc2,-
		test_rmd,test_rc2,test_rc4,test_rc5,test_bf,test_cast,-
		test_rand,test_dh  !,test_bn,test_dsa
$	endif ! if p1
$!
$	tests = f$edit(tests,"COLLAPSE")
$!
$!       BNTEST :=       bntest
$       EXPTEST :=      exptest
$       IDEATEST :=     ideatest
$       SHATEST :=      shatest
$       SHA1TEST :=     sha1test
$       MDC2TEST :=     mdc2test
$       RMDTEST :=      rmdtest
$       MD2TEST :=      md2test
$       MD4TEST :=      md4test
$       MD5TEST :=      md5test
$       HMACTEST :=     hmactest
$       RC2TEST :=      rc2test
$       RC4TEST :=      rc4test
$       RC5TEST :=      rc5test
$       BFTEST :=       bftest
$       CASTTEST :=     casttest
$       DESTEST :=      destest
$       RANDTEST :=     randtest
$       DHTEST :=       dhtest
$!       DSATEST :=      dsatest
$       METHTEST :=     methtest
$       SSLTEST :=      ssltest
$       RSATEST :=      rsa_test
$
$	tests_i = 0
$ loop_tests:
$	tests_e = f$element(tests_i,",",tests)
$	tests_i = tests_i + 1
$	if tests_e .eqs. "," then goto exit
$       write sys$output " "
$       write sys$output " Executing ''tests_e' ... "
$       write sys$output " "
$	gosub 'tests_e'
$	goto loop_tests
$
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
<< __FOO__ bc | perl -e 'while (<STDIN>) {if (/^test (.*)/) {print STDERR "\nverify $1";} elsif (!/^0$/) {die "\nFailed! bc: $_";} print STDERR "."; $i++;} print STDERR "\n$i tests passed\n"'
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
$	return
$ test_dh:
$	write sys$output "Generate a set of DH parameters"
$	mcr 'texe_dir''dhtest'
$	return
$ test_dsa:
$	write sys$output "Generate a set of DSA parameters"
$	mcr 'texe_dir''dsatest'
$	return
$!
$ exit:
$!	set default '__save_default'
$ show time
$	exit
