$!
$! This procedure compiles the SSL sources into 2 libraries:
$!	[.CRYPTO]CRYPTO-xxx.OLB		! crypto-graphics subroutines
$!	[.SSL]SSL-xxx.OLB		! SSL protocol.
$!
$!  where 'xxx' specifies the machine achitecture: AXP or VAX
$!
$!  To perform 1 sub-option, specify P1 as one of:
$!	INCLUDE CRYPTO SSL SSL_TASK
$!
$!  Requirements:
$!	DECC 4.0   	(may work with other versions)
$!	OpenVMS 6.1	(may work with other versions)
$!
$ original_default = f$environment("DEFAULT")
$ proc = f$environment("PROCEDURE")
$ proc_dir = f$parse("1.1;1",proc) - "1.1;1"
$ set default 'proc_dir'
$!
$! Copy all include files to [.include]
$!
$ set noon
$ if P1 .nes. "" then goto do_'p1'
$ do_include
$ write sys$output "Rebuilding [.include] directory..."
$ delete [.include]*.h;*
$ backup [.*...]*.h; includes.bck/save
$ backup includes.bck/save [.include]
$ delete includes.bck;
$ if p1 .nes. "" then goto cleanup
$!
$! Build crypto lib.
$!
$ do_crypto:
$ write sys$Output "Making CRYPTO library"
$ set default [.crypto]
$ @libvms
$ set default [-]
$ if p1 .nes. "" then goto cleanup
$!
$! Build SSL lib.
$!
$ do_ssl:
$ write sys$output "Making SSL library"
$ set default [.ssl]
$ libname = "ssl-axp.olb"
$ if f$getsyi("CPU") .lt. 128 then libname = "ssl-vax.olb"
$ if f$search(libname) .eqs. "" then library/create/log 'libname'
$ cc ssl.c/include=[-.include]/prefix=all
$ library/replace 'libname' ssl.obj
$ set default [-]
$ if p1 .nes. "" then goto cleanup
$!
$ do_ssl_task:
$ write sys$output "Building SSL_TASK.EXE, the DECnet-based SSL engine"
$ set default [.ssl]
$ libname = "ssl-axp.olb"
$ if f$getsyi("CPU") .lt. 128 then libname = "ssl-vax.olb"
$ cc ssl_task/include=[-.include]/prefix=all
$ cryptolib = "[-.crypto]crypto-" + f$element(1,"-",libname)
$ link ssl_task,'libname'/library,'cryptolib'/library
$!
$ cleanup:
$ set default 'original_default'
$ write sys$output "Done"
