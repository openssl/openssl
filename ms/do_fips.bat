@echo off

SET ASM=%1

if NOT X%PROCESSOR_ARCHITECTURE% == X goto defined 

echo Processor Architecture Undefined: defaulting to X86

goto X86

:defined

if %PROCESSOR_ARCHITECTURE% == x86 goto X86

if %PROCESSOR_ARCHITECTURE% == IA64 goto IA64

if %PROCESSOR_ARCHITECTURE% == AMD64 goto AMD64

echo Processor Architecture Unrecognized: defaulting to X86

:X86
echo Auto Configuring for X86

SET TARGET=VC-WIN32
if x%ASM% == xno-asm goto compile
SET ASM=nasm

goto compile

:IA64

echo Auto Configuring for IA64
SET TARGET=VC-WIN64I
perl ms\uplink.pl win64i > ms\uptable.asm
if ERRORLEVEL 1 goto error
ias -o ms\uptable.obj ms\uptable.asm
if ERRORLEVEL 1 goto error

goto compile

:AMD64

echo Auto Configuring for AMD64
SET TARGET=VC-WIN64A
perl ms\uplink.pl win64a > ms\uptable.asm
if ERRORLEVEL 1 goto error
ml64 -c -Foms\uptable.obj ms\uptable.asm
if ERRORLEVEL 1 goto error

if x%ASM% == xno-asm goto compile
SET ASM=ml64

:compile

perl Configure %TARGET% fipscanisteronly
pause

echo on

perl util\mkfiles.pl >MINFO
@if ERRORLEVEL 1 goto error
perl util\mk1mf.pl dll %ASM% %TARGET% >ms\ntdll.mak
@if ERRORLEVEL 1 goto error

nmake -f ms\ntdll.mak clean
nmake -f ms\ntdll.mak
@if ERRORLEVEL 1 goto error

@echo.
@echo.
@echo.
@echo ***************************
@echo ****FIPS BUILD SUCCESS*****
@echo ***************************

@goto end

:error

@echo.
@echo.
@echo.
@echo ***************************
@echo ****FIPS BUILD FAILURE*****
@echo ***************************

:end
