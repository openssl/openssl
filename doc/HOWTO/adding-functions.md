ADDING FUNCTIONS to OPENSSL
===========================

This document describes the way to add custom modifications to OpenSSL
sources.

If you are adding new C source files
------------------------------------

Please update the `build.info` files in the directories where you placed the
C source files, to include a line like this for each new C source file:

-   In `crypto/` or any of its subdirectories (intended for `libcrypto`):

        SOURCE[../libcrypto]={name-of-C-source-file}

-   In `ssl/` or any of its subdirectories (intended for `libssl`):

        SOURCE[../libssl]={name-of-C-source-file}

Do note that the path given as the `SOURCE` attribute must be adapted
appropriately for the location of the `build.info` file, as it's a relative
path to where the library itself is built, for example:

-   For `crypto/build.info`, the library path should be `../libcrypto`
-   For `crypto/evp/build.info`, the library path should be
    `../../libcrypto`
-   For `ssl/build.info`, the library path should be `../libssl`
-   For `ssl/quic/build.info`, the library path should be `../../libssl`

To know more about `build.info` files, please read [doc/internal/man7/build.info.pod].
For better viewing, consider converting it to HTML or PDF using `pod2html`
or `pod2pdf`.

Adding new public functions
---------------------------

If you are adding new public functions to the custom library build, you need to
either add a prototype in one of the existing OpenSSL header files, or
provide a new header file and edit.

Only headers in the `include/openssl` subdirectory are considered for public
functions.  If you're creating a new header file, it must be located in that
directory.

Functions declared in `include/openssl` header files are assumed to be part
of the `libcrypto` library unless specified otherwise.  *If your new
functions are meant for the `libssl` library*, you will need to edit
[Configurations/unix-Makefile.tmpl] and add the header file name in the
array `my @sslheaders_tmpl`.

Listing the symbol for export
-----------------------------

A public function is exported only if it is named in `util/libcrypto.sym`,
or in `util/libssl.sym` for a function belonging to `libssl`.  Add a line
for it, anywhere in the file, naming any features it depends on:

    BIO_set_dgram_foo
    OCSP_crlID_new                          OCSP

The format is described in [doc/internal/man7/sym.pod].

Updating OpenSSL's bookkeeping files
------------------------------------

OpenSSL generates files related to OIDs (in the `crypto/objects/` folder)
and error messages.  To bring them up to date, please do the following:

    ./Configure --strict-warnings [your-options]
    make update

If you plan to submit the changes you made to OpenSSL (see
[CONTRIBUTING.md]), it's also worth running the following, to ensure that
documentation has correct format.

    make doc-nits

More details are at
  [doc/HOWTO/documenting-functions-macros.md](Documenting Functions and Macros)

[doc/internal/man7/build.info.pod]: ../doc/internal/man7/build.info.pod
[doc/internal/man7/sym.pod]: ../internal/man7/sym.pod
[Configurations/unix-Makefile.tmpl]: ../../Configurations/unix-Makefile.tmpl
[CONTRIBUTING.md]: ../../CONTRIBUTING.md
