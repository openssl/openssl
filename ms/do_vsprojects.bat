@setLocal
@if NOT "%_DEBUG%" GEQ "1" @echo off

pushd %~dp0\..
rem get vs tools
call ms\setVSVars.bat VS12VC
call "%_VS12VC%\vcvarsall" x86

rem create VS Project
if not exist vsout mkdir vsout

rem INITONCE common preprocessing across configurations
set INITONCE=YES

rem copy the solution file and create the appropriate projects
copy ms\vstemplates\vstemplates.sln vsout\openSSL.sln
rem call makeProject Target Version Static/Dynamic Unicode OpenSSLGuid TestGuid WinRTGuid
rem if you add or change the targets, update ms\vstemplates\vstemplates.sln
call:makeProject Store 8.1 Static Unicode 5BAD3295-3CC2-4416-A65F-16B304654800 107269C7-4696-409E-971F-8AD55BE9D522 9A5F9DB2-028F-4C9E-A38D-5DDD1CC1E7D3
call:makeProject Store 8.1 Dll    Unicode 74B83832-68A4-4F38-80C1-DDAFD6A8411C F837355F-32CD-4477-A063-9F13E455CBC7 E1D6D4AD-C927-4E7E-93F7-E9B436867687
call:makeProject Phone 8.1 Static Unicode 4EBEC75C-CC8F-4BF2-86FE-01E0D63FF657 77F024B2-24DA-444C-8CAF-670106BEF31B DA7F914C-C21C-46BC-BCDA-543AAC73CD09
call:makeProject Phone 8.1 Dll    Unicode 2D015673-B1A5-47A8-BA8E-CE9D609B2170 3141D5D9-8BB1-41FA-BE64-EBEC6C06B29F 0CB58F0E-F496-49A9-8636-87FCB42AE929
call:makeProject Phone 8.0 Static Unicode EABB977A-C639-4C0B-B785-B0010A5F3AE4 53F8E5E1-EB37-4A12-BDB0-D98EB128C47A AA718494-573E-4C61-B098-6F01DE171F99
call:makeProject Phone 8.0 Dll    Unicode 00B50F7D-EB0B-463F-B18D-CE55903646F5 E4127FE0-F956-4925-8C39-BEABDBD7E174 499EBAFA-3460-4F0D-8984-A7D9798A8967

goto :eof

:makeProject
	set PROJECTLOC=NT-%1-%2-%3-%4
	if not exist vsout\%PROJECTLOC% mkdir vsout\%PROJECTLOC%
	if not exist vsout\%PROJECTLOC%-testapp mkdir vsout\%PROJECTLOC%-testapp
	xcopy ms\vstemplates\OpenSSLTestApp%1%2 vsout\%PROJECTLOC%-testapp /h /k /r /e /i /y >nul
	xcopy ms\vstemplates\winrt%1%2 vsout\%PROJECTLOC%-winrtcomponent /h /k /r /e /i /y >nul
	xcopy ms\vstemplates\Makefile%1 vsout\%PROJECTLOC% /h /k /r /e /i /y >nul

	call:makeConfiguration %1 %2 %3 %4 Debug   Win32
	call:makeConfiguration %1 %2 %3 %4 Debug   arm
	call:makeConfiguration %1 %2 %3 %4 Release Win32
	call:makeConfiguration %1 %2 %3 %4 Release arm
	if "%1"=="Phone" goto:skipx64
	call:makeConfiguration %1 %2 %3 %4 Debug   x64
	call:makeConfiguration %1 %2 %3 %4 Release x64
    :skipx64
	perl ms\do_vsproject.pl %1 %2 %3 %4 %5 %6 %7
goto :eof

:makeConfiguration
	set EXTRAFLAGS=
	set Dll=
	if "%1"=="Phone" set VC-CONFIGURATION=VC-WINPHONE
	if "%1"=="Store" set VC-CONFIGURATION=VC-WINSTORE
	if "%3"=="Dll" set Dll=dll
	if "%4"=="Unicode" set EXTRAFLAGS=%EXTRAFLAGS% -DUNICODE -D_UNICODE
	if "%5"=="Debug" set EXTRAFLAGS=%EXTRAFLAGS% -Zi
	if "%2"=="8.0" set EXTRAFLAGS=%EXTRAFLAGS% -DOPENSSL_WINAPP_NOCRYPTOGRAPHICBUFFER
	if not exist vsout\%PROJECTLOC%\%5\%6\tmp mkdir vsout\%PROJECTLOC%\%5\%6\tmp
	if not exist vsout\%PROJECTLOC%\%5\%6\bin mkdir vsout\%PROJECTLOC%\%5\%6\bin	
	echo creating project vsout\%PROJECTLOC%
	rem goto :doProject
	perl Configure no-asm no-hw no-dso %VC-CONFIGURATION% %EXTRAFLAGS%
	perl util\mkfiles.pl >MINFO
	perl util\mk1mf.pl no-asm %Dll% %VC-CONFIGURATION%>vsout\%PROJECTLOC%\nt-%5-%6.mak
	if "%INITONCE%"=="YES" call :initonce vsout\%PROJECTLOC%\nt-%5-%6.mak
goto :eof

:initonce
	rem common setup across configurations
	perl util\mkdef.pl crypto ssl update
	perl util\mkdef.pl 32 libeay > %TMP%\libeay32.def
	rem patch for building DLL build.
	perl -ne "print unless /ENGINE_load_rsax/" %TMP%\libeay32.def > ms\libeay32.def
	perl util\mkdef.pl 32 ssleay > ms\ssleay32.def
	nmake -f %1 init
	set INITONCE=
goto :eof
