@echo off

perl Configure OS2-EMX
perl util\mkfiles.pl > MINFO

@rem create make file
perl util\mk1mf.pl OS2-EMX > OS2-EMX.mak
perl util\mk1mf.pl dll OS2-EMX > OS2-EMX-DLL.mak

echo Generating export definition files
perl util\mkdef.pl crypto OS2 > os2\crypto.def
perl util\mkdef.pl ssl OS2 > os2\ssl.def

echo Generating x86 for GNU assember

echo Bignum
cd crypto\bn\asm
rem perl x86.pl a.out > bn-os2.asm
perl bn-586.pl a.out > bn-os2.asm 
perl co-586.pl a.out > co-os2.asm 
cd ..\..\..

echo DES
cd crypto\des\asm
perl des-586.pl a.out > d-os2.asm
cd ..\..\..

echo crypt(3)
cd crypto\des\asm
perl crypt586.pl a.out > y-os2.asm
cd ..\..\..

echo Blowfish
cd crypto\bf\asm
perl bf-586.pl a.out > b-os2.asm
cd ..\..\..

echo CAST5
cd crypto\cast\asm
perl cast-586.pl a.out > c-os2.asm
cd ..\..\..

echo RC4
cd crypto\rc4\asm
perl rc4-586.pl a.out > r4-os2.asm
cd ..\..\..

echo MD5
cd crypto\md5\asm
perl md5-586.pl a.out > m5-os2.asm
cd ..\..\..

echo SHA1
cd crypto\sha\asm
perl sha1-586.pl a.out > s1-os2.asm
cd ..\..\..

echo RIPEMD160
cd crypto\ripemd\asm
perl rmd-586.pl a.out > rm-os2.asm
cd ..\..\..

echo RC5\32
cd crypto\rc5\asm
perl rc5-586.pl a.out > r5-os2.asm
cd ..\..\..
