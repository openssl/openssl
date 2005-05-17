@echo off

rem ========================================================================
rem   Batch file to assist in setting up the necessary enviroment for
rem   building OpenSSL for NetWare.
rem
rem   usage:
rem      set_env [target]
rem
rem      target      - "netware-clib" - Clib build
rem                  - "netware-libc" - LibC build
rem
rem

if "a%1" == "a" goto usage
               
set LIBC_BUILD=
set CLIB_BUILD=

if "%1" == "netware-clib" set CLIB_BUILD=Y
if "%1" == "netware-clib" set LIBC_BUILD=

if "%1" == "netware-libc"  set LIBC_BUILD=Y
if "%1" == "netware-libc"  set CLIB_BUILD=

rem   Location of tools (compiler, linker, etc)
set TOOLS=d:\i_drive\tools

rem   If Perl for Win32 is not already in your path, add it here
set PERL_PATH=

rem   Define path to the Metrowerks command line tools
rem   ( compiler, assembler, linker)
set METROWERKS_PATH=%TOOLS%\codewar\pdk_21\tools\command line tools
rem set METROWERKS_PATH=%TOOLS%\codewar\PDK_40\Other Metrowerks Tools\Command Line Tools

rem   If using gnu make define path to utility
set GNU_MAKE_PATH=%TOOLS%\gnu

rem   If using ms nmake define path to nmake
set MS_NMAKE_PATH=%TOOLS%\msvc\600\bin

rem   If using NASM assembler define path
set NASM_PATH=%TOOLS%\nasm

rem   Update path to include tool paths
set path=%path%;%METROWERKS_PATH%
if not "%GNU_MAKE_PATH%" == "" set path=%path%;%GNU_MAKE_PATH%
if not "%MS_NMAKE_PATH%" == "" set path=%path%;%MS_NMAKE_PATH%
if not "%NASM_PATH%"     == "" set path=%path%;%NASM_PATH%
if not "%PERL_PATH%"     == "" set path=%path%;%PERL_PATH%

rem   Set MWCIncludes to location of Novell NDK includes
if "%LIBC_BUILD%" == "Y" set MWCIncludes=%TOOLS%\ndk\libc\include;%TOOLS%\ndk\libc\include\winsock;.\engines
if "%CLIB_BUILD%" == "Y" set MWCIncludes=%TOOLS%\ndk\nwsdk\include\nlm;.\engines
set include=

rem   Set Imports to location of Novell NDK import files
if "%LIBC_BUILD%" == "Y" set IMPORTS=%TOOLS%\ndk\libc\imports
if "%CLIB_BUILD%" == "Y" set IMPORTS=%TOOLS%\ndk\nwsdk\imports

rem   Set PRELUDE to the absolute path of the prelude object to link with in
rem   the Metrowerks NetWare PDK - NOTE: for Clib builds "clibpre.o" is 
rem   recommended, for LibC NKS builds libcpre.o must be used
if "%LIBC_BUILD%" == "Y" set PRELUDE=%IMPORTS%\libcpre.o
if "%CLIB_BUILD%" == "Y" set PRELUDE=%IMPORTS%\clibpre.o


if "%LIBC_BUILD%" == "Y" echo Enviroment configured for LibC build
if "%LIBC_BUILD%" == "Y" echo use "netware\build.bat netware-libc ..." 

if "%CLIB_BUILD%" == "Y" echo Enviroment configured for CLib build
if "%CLIB_BUILD%" == "Y" echo use "netware\build.bat netware-clib ..." 
goto end

:usage
rem ===============================================================
echo .
echo . No target build specified!
echo .
echo . usage: set_env [target]
echo .
echo .   target      - "netware-clib" - Clib build
echo .               - "netware-libc" - LibC build
echo .



:end

