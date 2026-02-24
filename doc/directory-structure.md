OpenSSL Repository Structure
===========================

This document provides an overview of the OpenSSL repository's directory
structure, explaining what the major directories and files are, their purpose,
and how they relate to each other.

This documentation is available in multiple locations:

* As a man page when OpenSSL is installed on your system
* As a web page on OpenSSL's official website (www.openssl.org)
* In the source distribution of OpenSSL in the `doc` directory
* In a Git checkout at `doc/directory-structure.md`

If you're reading this in a checkout of the OpenSSL source code, you're viewing
the document in its original location.

Repository Tree Overview
-----------------------

Here's a high-level view of the repository structure:

```bash
openssl/
├── .ctags.d/     # ctags configuration for code navigation
├── .github/      # GitHub-specific files and workflows
├── apps/         # OpenSSL command line applications
├── Configurations/ # Build configuration for different platforms
├── crypto/       # Core cryptographic implementations
├── demos/        # Example code demonstrating OpenSSL usage
├── dev/          # Development utilities and scripts
├── doc/          # Documentation
├── engines/      # Legacy engine implementations
├── exporters/    # Build system export utilities
├── external/     # External dependencies
├── fuzz/         # Fuzzing tools and configuration
├── include/      # Header files
├── ms/           # Microsoft Windows specific files
├── os-dep/       # Operating system dependent code
├── providers/    # Provider implementations (FIPS, etc.)
├── ssl/          # SSL/TLS implementation
├── test/         # Test suite
├── tools/        # Various utility tools
├── util/         # Build-related utilities
└── VMS/          # OpenVMS specific files
```

Root-Level Files
---------------

The repository root contains many important files:

* `README.md` - The main README with project overview and links to documentation
* `INSTALL.md` - Detailed installation instructions for all platforms
* `Configure` - The main build configuration script
* `config` - A wrapper around Configure for Unix platforms
* `LICENSE.txt` - The Apache 2.0 license that applies to OpenSSL 3.0+
* `CHANGES.md` - A comprehensive changelog
* `NEWS.md` - A curated list of major changes in each release
* `VERSION.dat` - Contains the current version information
* `configdata.pm.in` - Template used during build configuration

Various platform-specific notes are also at the root level:

* `NOTES-*.md` - Platform-specific information (UNIX, WINDOWS, etc.)
* `README-*.md` - Additional READMEs for specific components (ENGINES, FIPS,
  etc.)

Major Directories
---------------

### apps/

Contains the OpenSSL command-line application source code. This is what you're
using when you run the `openssl` command.

Notable components:

* The `openssl s_client` tool supports SSL/TLS, DTLS and QUIC via the `-quic`
  flag (since version 3.2.0)
* The `openssl s_server` tool supports SSL/TLS, DTLS but does NOT support QUIC

### crypto/

The heart of OpenSSL containing implementations of cryptographic algorithms.
Inside you'll find subdirectories for different cryptographic functions as well
as other supporting code.
This is the code that ends up in `libcrypto`. For example:

* `crypto/aes/` - AES encryption implementation
* `crypto/bn/` - Big Number arithmetic library
* `crypto/evp/` - High-level cryptographic API
* `crypto/rsa/`, `crypto/ec/`, etc. - Various algorithm implementations

### demos/

Example code demonstrating how to use OpenSSL APIs. Here are some notable
examples (not an exhaustive list):

* `demos/quic/` - QUIC protocol examples
* `demos/http3/` - HTTP/3 client example using the nghttp3 library
* `demos/guide/` - Code samples referenced in the OpenSSL Guide

### doc/

Documentation organized in multiple formats:

* `doc/man1/` - Manual pages for command-line tools
* `doc/man3/` - Manual pages for API functions
* `doc/man5/` - Manual pages for file formats
* `doc/man7/` - Manual pages for overviews and concepts
* `doc/internal/` - Developer documentation

### include/

Header files for OpenSSL:

* `include/openssl/` - Public API headers that get installed with OpenSSL
* `include/crypto/` - Internal headers for cryptographic implementations
  (not installed)
* `include/internal/` - Other internal headers (not installed)

### providers/

The provider architecture (new in OpenSSL 3.0) implementations:

* `providers/common/` - Common provider code
* `providers/implementations/` - Algorithm implementations for various providers
* `providers/fips/` - FIPS provider implementation

### ssl/

Implementation of SSL, TLS, DTLS, and QUIC protocols.
This is the code that ends up in `libssl`.

* `ssl/record/` - SSL/TLS record layer
* `ssl/statem/` - SSL/TLS state machine
* `ssl/quic/` - QUIC protocol implementation (available since version 3.2.0)

### test/

Comprehensive test suite, organized by component and feature.

* `test/recipes/` - Test recipes that are invoked when running `make test`
* `test/certs/` - Test certificates and keys used in tests
* Various test executables for different components

Build System Files
----------------

* `Configurations/` - Platform-specific build configurations
* `exporters/` - Utilities for exporting OpenSSL build information to various
  build systems
* `os-dep/` - Operating system dependent code and platform-specific
  implementations
* `util/` - Build scripts and utilities

External Modules
--------------

OpenSSL includes several external modules as Git submodules, mainly used for
testing, including:

* `oqs-provider/` - Post-quantum cryptography provider
* `krb5/` - Kerberos support
* `cloudflare-quiche/` - QUIC implementation from Cloudflare (used as a
  reference for OpenSSL's own QUIC implementation)

Development and Contributor Files
-------------------------------

* `.ctags.d/` - Configuration for ctags, enabling better code navigation and
  indexing for developers
* `.github/` - GitHub-specific files (workflows, issue templates)
* `CONTRIBUTING.md` - Guidelines for contributing to OpenSSL
* `HACKING.md` - Information on adding custom modifications to OpenSSL source
* `dev/` - Development utilities, helper scripts, and tools used during OpenSSL
  development

Stability Information
------------------

The API provided in the public headers (`include/openssl/`) is considered stable
within major versions. Internal headers (in `include/crypto/` and
`include/internal/`) may change even between patch releases and are not part of
the public API. The provider interface is also considered stable.

Components currently experiencing significant development:

* The QUIC implementation is still evolving
* The provider architecture was introduced in 3.0 and continues to mature

Long-standing stable components:

* Core cryptographic algorithms in `crypto/`
* The SSL/TLS protocol implementation (excluding QUIC)

File Organization Patterns
------------------------

OpenSSL follows consistent naming patterns:

* `.c` files contain implementations
* `.h` files are headers
* `.pod` files are documentation sources
* `*_local.h` files are for internal use within a component
* `build.info` files (found in many directories) describe what to build in that
  directory
* Test filenames typically include the name of what they're testing

This overview should help new contributors better understand the repository
structure and navigate the codebase more effectively.
