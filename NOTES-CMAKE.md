Notes for CMake generator
===========================

Requirement details
-------------------

In addition to the obvious CMake requirement, these are required as well:

## Perl

We recommend Strawberry Perl, or alternatively ActiveState Perl on Windows.
Use the appropriate package manager for Unix systems to acquire Perl.

please see the [Notes for Windows platforms](NOTES-WINDOWS.md) or [Notes for Unix platforms](NOTES-UNIX.md).


## Windows

### Netwide Assembler (NASM) on Windows

NASM is the only currently supported assembler on Windows. It is available from <https://www.nasm.us> and has great support with CMake.

Quick start
-----------

 1. Install Perl (and NASM is necessary)

 3. Make sure CMake, Perl, and NASM are all on your PATH.

 5. From the root of the OpenSSL source directory enter
    - `perl Configure CMake`

    The perl Configure script will produce `openssl-config.cmake` in the root OpenSSL source directory.

 6. You can now configure CMake in the root OpenSSL source directory using the CMakeLists.txt file.
 
 7. Additionally, you can embed OpenSSL directly into a custom CMake project by using `add_subdirectory(<OPENSSL_SOURCE_DIR> <OPENSSL_BINARY_DIR>)`, this even suppoort automatic perl configuration if the `OPENSSL_CONFIGURE_OPTIONS` CMake variable is set.

The CMake scripts produce a CMake target for each library that OpenSSL was configured for, they can be referenced in a CMake script using the aliased form `OpenSSL::<target>` or `openssl_<target>`, for example `OpenSSL::libcrypto` or `openssl_libcrypto`.

For the full installation instructions, or if anything goes wrong at any stage,
check the INSTALL.md file.

CMake Variables
---------------

    PERL_EXECUTABLE                     - The Perl executable path
    OPENSSL_CONFIGURE_OPTIONS           - Sets the options to configure with Perl, skips Perl configuration if unset

    OPENSSL_SRCDIR                      - The OpenSSL root source directory
    OPENSSL_POSITION_INDEPENDENT_CODE   - Set when the target OS should produce PIC executables
    OPENSSL_LIBS                        - The CMake library targets
    OPENSSL_SHLIBS                      - The CMake shared library targets only
    OPENSSL_MODULES                     - The CMake module targets
    OPENSSL_PROGRAMS                    - The CMake application/program targets

    OPENSSL_STATIC_TARGETS              - The CMake static library targets
    OPENSSL_SHARED_TARGETS              - The CMake shared library targets
    OPENSSL_DSO_TARGETS                 - The CMake DSO/module targets
    OPENSSL_BIN_TARGETS                 - The CMake application/program targets

    OPENSSL_SOURCES_<target>            - The source files for a specific target
    OPENSSL_LINK_DEFS_<target>          - The linker defs files for a specific target
    OPENSSL_INCLUDES_<target>           - The include directories for a specific target
    OPENSSL_DEFINES_<target>            - The compiler definitions for a specific target
    OPENSSL_LINK_LIBRARIES_<target>     - The link libraries for a specific target
    OPENSSL_DEPENDENCIES_<target>       - The dependencies for a specific target

CMake Targets
-------------

    OpenSSL::libcommon (openssl_libcommon)                     - The libcommon static library
    OpenSSL::libdefault (openssl_libdefault)                   - The libdefault static library
    OpenSSL::libcrypto (openssl_libcrypto)                     - The libcrypto static library
    OpenSSL::libcrypto_<version> (openssl_libcrypto_<version>) - The libcrypto shared library
    OpenSSL::libssl (openssl_libssl)                           - The libssl static library
    OpenSSL::libssl_<version> (openssl_libssl_<version>)       - The libssl shared library
    OpenSSL::liblegacy (openssl_liblegacy)                     - The liblegacy static library
    OpenSSL::legacy (openssl_legacy)                           - The liblegacy shared library
    OpenSSL::libapps (openssl_libapps)                         - The libapps static library
    OpenSSL::openssl (openssl_openssl)                         - The openssl command line program

    openssl_docs - Generates the OpenSSL documenation and manuals


Installation directories
------------------------

Installation is not supported in the supplied CMake scripts yet, however you can set your own installation via your own custom CMake script and using `add_subdirectory(<OPENSSL_SOURCE_DIR> <OPENSSL_BINARY_DIR>)` and referencing the target you want to install, etc.

