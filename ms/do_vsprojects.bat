@setLocal
@echo off
rem get vs tools
call ms\setVSVars.bat VS12VC
call "%_VS12VC%\vcvarsall" x86

rem create VS Project
if not exist vsout mkdir vsout

rem INITONCE common preprocessing across configurations
set INITONCE=YES


echo.> vsout\openssl.sln
echo Microsoft Visual Studio Solution File, Format Version 12.00>> vsout\openssl.sln
echo # Visual Studio 2013>> vsout\openssl.sln

call:makeProject Store 8.1 Static Unicode
call:makeProject Store 8.1 Dll    Unicode
call:makeProject Phone 8.1 Static Unicode
call:makeProject Phone 8.1 Dll    Unicode
call:makeProject Phone 8.0 Static Unicode
call:makeProject Phone 8.0 Dll    Unicode

echo.>> vsout\openssl.sln
goto :eof

:makeProject
	set PROJECTLOC=NT-%1-%2-%3-%4
	if not exist vsout\%PROJECTLOC% mkdir vsout\%PROJECTLOC%
	if not exist vsout\%PROJECTLOC%-testapp mkdir vsout\%PROJECTLOC%-testapp
	xcopy ms\vstemplates\OpenSSLTestApp%1%2 vsout\%PROJECTLOC%-testapp /h /k /r /e /i /y >nul
	xcopy ms\vstemplates\winrt%1%2 vsout\%PROJECTLOC%-winrtcomponent /h /k /r /e /i /y >nul
	xcopy ms\vstemplates\Makefile%1 vsout\%PROJECTLOC% /h /k /r /e /i /y >nul

	for /f "delims=" %%A in ('uuidgen') do set "GUID=%%A"
	for /f "delims=" %%A in ('uuidgen') do set "TESTGUID=%%A"
	for /f "delims=" %%A in ('uuidgen') do set "WINRTGUID=%%A"

	call:makeConfiguration %1 %2 %3 %4 Debug   Win32
	call:makeConfiguration %1 %2 %3 %4 Debug   arm
	call:makeConfiguration %1 %2 %3 %4 Release Win32
	call:makeConfiguration %1 %2 %3 %4 Release arm
	if "%1"=="Phone" goto:skipx64
	call:makeConfiguration %1 %2 %3 %4 Debug   x64
	call:makeConfiguration %1 %2 %3 %4 Release x64
    :skipx64
	perl ms\do_vsproject.pl %1 %2 %3 %4 %GUID% %TESTGUID% %WINRTGUID%
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
