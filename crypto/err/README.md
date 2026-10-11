Adding new libraries
====================

When adding a new sub-library to OpenSSL:

- assign it a library number `ERR_LIB_XXX` in `include/openssl/err.h`;
- add its name to `ERR_str_libraries[]` in `crypto/err/err.c`;
- add a call to `ossl_err_load_XXX_strings()` in
  `ossl_err_load_crypto_strings()` in `crypto/err/err_all.c`.  That
  function is defined in the generated source named below;
- add an entry to `crypto/err/openssl.ec`:

      L      XXX     include/openssl/xxxerr.h    crypto/xxx/xxx_err.c

  The fields after the library name are the public header, the source
  file, and an optional private header.  `NONE` stands for a file that
  is not wanted.  The public header must be under `include/openssl/`,
  and a private header may only be given for an internal library;

- add the files named on that entry to the block of generated error
  files in `.gitignore`.

Those files are produced during the build from `crypto/err/openssl.ec`
and `crypto/err/openssl.txt`, and are not in git.  They are left
read-only: an edit to one is lost the next time it is generated.

Adding new error codes
======================

Raise an error with `ERR_raise()`, using a reason name of the form
`XXX_R_...`:

    ERR_raise(ERR_LIB_XXX, XXX_R_SOMETHING_FAILED);

and add a line for the reason at the end of the library's section of
`crypto/err/openssl.txt`, with the number one more than the last
line's:

    142:XXX_R_SOMETHING_FAILED:something failed

The fields are the reason number, the reason name and the string
returned by `ERR_reason_error_string()`; the header of
`crypto/err/openssl.txt` describes them.  The number is unique within
the library and is part of the API: an existing reason's number never
changes.
