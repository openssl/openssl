
@echo off
echo Generating x86 for MASM assember

echo Bignum
cd crypto\bn\asm
perl x86.pl win32 > bn_win32.asm
cd ..\..\..

echo DES
cd crypto\des\asm
perl des-586.pl win32 > d_win32.asm
cd ..\..\..

echo "crypt(3)"

cd crypto\des\asm
perl crypt586.pl win32 > y_win32.asm
cd ..\..\..

echo Blowfish

cd crypto\bf\asm
perl bf-586.pl win32 > b_win32.asm
cd ..\..\..

echo CAST5
cd crypto\cast\asm
perl cast-586.pl win32 > c_win32.asm
cd ..\..\..

echo RC4
cd crypto\rc4\asm
perl rc4-586.pl win32 > r4_win32.asm
cd ..\..\..

echo MD5
cd crypto\md5\asm
perl md5-586.pl win32 > m5_win32.asm
cd ..\..\..

echo SHA1
cd crypto\sha\asm
perl sha1-586.pl win32 > s1_win32.asm
cd ..\..\..

echo RIPEMD160
cd crypto\ripemd\asm
perl rmd-586.pl win32 > rm_win32.asm
cd ..\..\..

echo RC5\32
cd crypto\rc5\asm
perl rc5-586.pl win32 > r5_win32.asm
cd ..\..\..

echo on

perl util\mkfiles.pl >MINFO
rem perl util\mk1mf.pl no-sock %1 VC-MSDOS >ms\msdos.mak
rem perl util\mk1mf.pl %1 VC-W31-32 >ms\w31.mak
rem perl util\mk1mf.pl dll %1 VC-W31-32 >ms\w31dll.mak
perl util\mk1mf.pl %1 VC-WIN32 >ms\nt.mak
perl util\mk1mf.pl dll %1 VC-WIN32 >ms\ntdll.mak

perl util\mkdef.pl 16 libeay %1 > ms\libeay16.def
perl util\mkdef.pl 32 libeay %1 > ms\libeay32.def
perl util\mkdef.pl 16 ssleay %1 > ms\ssleay16.def
perl util\mkdef.pl 32 ssleay %1 > ms\ssleay32.def
