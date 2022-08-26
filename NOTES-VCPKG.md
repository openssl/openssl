Notes on vcpkg
==============================

vcpkg is a full platform package manager, you can also use vcpkg to
build and install openssl.

Build and install
-------------------

You can simply use the following step to install openssl with vcpkg:

 1. `git clone https://github.com/microsoft/vcpkg.git`
 2. `./bootstrap-vcpkg.sh` for Linux or OSX and `./bootstrap-vcpkg.bat` for Windows
 3. `./vcpkg install openssl`
