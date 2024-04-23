
######################################################
# NSIS windows installer script file
# Requirements: NSIS 3.0 must be installed with the MUI plugin
# Usage notes:
# This script expects the following filesystem layout when being built
# relative to this files location:
# ..\LICENSE.TXT
# x32\openssl.exe
# x32\libcrypto-3.dll
# x32\libssh-3.dll
# x32\providers\fips.dll
# x32\providers\legacy.dll
# x64\openssl.exe
# x64\libcrypto-3-x64.dll
# x64\libssh-3-x64.dll
# x64\providers\fips.dll
# x64\providers\legacy.dll
# ####################################################

!include "MUI.nsh"

# The name of the output file we create when building this
# NOTE version is passed with the /D option on the command line
OutFile "openssl-${VERSION}-installer.exe"

# The name that will appear in the installer title bar
NAME "openssl ${VERSION}"

# This section is run if installation of 32 bit binaries are selected
Section "32 Bit Binaries"
	SetOutPath $INSTDIR\x32
	File x32\libcrypto-3.dll
	File x32\libssl-3.dll
	File x32\openssl.exe
	SetOutPath $INSTDIR\x32\providers
	File x32\providers\fips.dll
	File x32\providers\legacy.dll
SectionEnd


# This section is run if installation of the 64 bit binaries are selectd
Section "64 Bit Binaries"
	SetOutPath $INSTDIR\x64
	File x64\libcrypto-3-x64.dll
	File x64\libssl-3-x64.dll
	File x64\openssl.exe
	SetOutPath $INSTDIR\x64\providers
	File x64\providers\fips.dll
	File x64\providers\legacy.dll
SectionEnd

# Give the user the opportunity to include the uninstaller
Section "Uninstaller"
	WriteUninstaller $INSTDIR\uninstall.exe
SectionEnd

# This is run on uninstall
Section "Uninstall"
	RMDIR /r $INSTDIR
SectionEnd

!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_LICENSE ../LICENSE.TXT

!insertmacro MUI_PAGE_COMPONENTS

!define MUI_DIRECTORYPAGE_TEXT_DESTINATION "c:\Program Files\openssl-${VERSION}"
!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
