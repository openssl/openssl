Notes on C-99
=============

This file contains a list of C-99 features we don't allow for OpenSSL.
Starting with 3.6 OpenSSL project is going to gradually adopt C-99 features.
The plan is to bring those features in using small steps. Either with new
code where particular C-99 construct makes sense (think of designated initializers),
or when refactoring existing code and using C-99 language feature improves
readability/maintainability of the code. Unfortunately according to overview
[here](https://en.cppreference.com/w/c/compiler_support/99) the adoption of C-99 standard varies from compiler to compiler.
For certain compilers the level of C-99 support is uncertain.

To tackle around it we need to have a plan to bring in C-99 without disrupting
OpenSSL adoption on platforms which are not part of the mainstream and where
the recent compilers might not be readily available. The C-99 adoption policy
for OpenSSL is permissive, meaning that if particular C-99 feature is not listed
here in this file it can be used. As soon as we learn the particular C-99 construct
is not suitable for some platform then decision needs to be made whether:

   - that particular platform is indeed a corner case and must take its own
     measures (keep set of patches) to deal with it.

   - or the C-99 feature itself is not suitable for OpenSSL in this case the
     C-99 feature will get listed here ans will become prohibited in OpenSSL.

The list of C-99 features we don't support in OpenSSL project follows:
