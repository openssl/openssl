OpenSSL User Support resources
==============================

_Under Construction; not more than a collection of text fragments yet._

See the OpenSSL website www.openssl.org for details on how to obtain
commercial technical support. Free community support is available through the
openssl-users email list (see
<https://www.openssl.org/community/mailinglists.html for> further details).

If you have any problems with OpenSSL then please take the following steps
first:

 - Download the latest version from the repository
   to see if the problem has already been addressed
 - Configure with no-asm
 - Remove compiler optimization flags

If you wish to report a bug then please include the following information
and create an issue on GitHub:

 - OpenSSL version: output of 'openssl version -a'
 - Configuration data: output of 'perl configdata.pm ==dump'
 - OS Name, Version, Hardware platform
 - Compiler Details (name, version)
 - Application Details (name, version)
 - Problem Description (steps that will reproduce the problem, if known)
 - Stack Traceback (if the application dumps core)

Just because something doesn't work the way you expect does not mean it
is necessarily a bug in OpenSSL. Use the openssl-users email list for this type
of query.

For *questions* on how to use OpenSSL or what went wrong when you
tried something, our primary resource is the mailing list
openssl-users@openssl.org, where you can get help from others in the
OpenSSL community (which includes the developers as time permits).

Only subscribers can post to openssl-users@openssl.org (although the
archives are public).
For more information, see <https://www.openssl.org/community/mailinglists.html>

You have general questions about using OpenSSL
----------------------------------------------

In this case the [openssl-users][] mailing list is the right place for you.
The list is not only watched by the OpenSSL team members, but also by many
other OpenSSL users. Here you will most likely get the answer to your questions.
An overview over the [mailing lists](#mailing-lists) can be found below.

You found a Bug
---------------

If you have any problems with OpenSSL then please take the following steps first:

- Search the mailing lists and/or the GitHub issues to find out whether
  the problem has already been reported.
- Download the latest version from the repository to see if the problem
  has already been addressed.
- Configure without assembler support (`no-asm`) and check whether the
  problem persists.
- Remove compiler optimization flags.

Please keep in mind: Just because something doesn't work the way you expect
does not mean it is necessarily a bug in OpenSSL. If you are not sure,
consider searching the mail archives and posting a question to the
[openssl-users][] mailing list first.

### Open an Issue

If you wish to report a bug, please open an [issue][github-issues] on GitHub
and include the following information:

- OpenSSL version: output of `openssl version -a`
- Configuration data: output of `perl configdata.pm --dump`
- OS Name, Version, Hardware platform
- Compiler Details (name, version)
- Application Details (name, version)
- Problem Description (steps that will reproduce the problem, if known)
- Stack Traceback (if the application dumps core)

Not only errors in the software, also errors in the documentation, in
particular the manual pages, can be reported as issues.

### Submit a Pull Request

The fastest way to get a bug fixed is to fix it yourself ;-). If you are
experienced in programming and know how to fix the bug, you can open a
pull request. The details are covered in the [Contributing](#contributing) section.

Don't hesitate to open a pull request, even if it's only a small change
like a grammatical or typographical error in the documentation.

Mailing Lists
=============

The OpenSSL maintains a number of [mailing lists][] for various purposes.
The most important lists are:

- [openssl-users][] for general questions about using the OpenSSL software
                    and discussions between OpenSSL users.

- [openssl-announce][] for official announcements to the OpenSSL community.

- [openssl-project][]  for discussion about the development roadmap
                       and governance.

- [openssl-dev][]      for discussion about development of OpenSSL.

The openssl-dev list has been discontinued since development is now taking
place in form of GitHub pull requests. Although not active anymore, the
searchable archive may still contain useful information.

<!-- Links -->

[mailing lists]:     https://www.openssl.org/community/mailinglists.html
[openssl-users]:     https://mta.openssl.org/mailman/listinfo/openssl-users
[openssl-announce]:  https://mta.openssl.org/mailman/listinfo/openssl-announce
[openssl-project]:   https://mta.openssl.org/mailman/listinfo/openssl-project
[openssl-dev]:       https://mta.openssl.org/mailman/listinfo/openssl-dev
