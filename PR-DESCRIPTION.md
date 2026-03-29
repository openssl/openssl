Pull Request: Add public API for IPAddrBlocks (RFC 3779)
========================================================

Fixes #18528

---

Problem
-------

OpenSSL had no public API to create, free, or encode/decode `IPAddrBlocks` (RFC 3779 IP address extension) structures. The type and related logic existed internally in `crypto/x509/v3_addr.c`, but only `ASIdentifiers` had the usual ASN.1 helper API (`ASIdentifiers_new`, `ASIdentifiers_free`, `d2i_ASIdentifiers`, `i2d_ASIdentifiers`, `ASIdentifiers_it`). Applications that need to build or parse IP address blocks (e.g. for RPKI Signed Checklist or other RFC 3779 use cases) could not do so without using internal or undocumented interfaces.

Solution
--------

Add a public API for `IPAddrBlocks` that mirrors the existing `ASIdentifiers` API:

- **Allocation/free:** `IPAddrBlocks_new()`, `IPAddrBlocks_free()`
- **Encode/decode:** `d2i_IPAddrBlocks()`, `i2d_IPAddrBlocks()`
- **ASN.1 item:** Export `IPAddrBlocks_it` for use in custom ASN.1 templates (e.g. RPKI Signed Checklist)

### Implementation details

- **`crypto/x509/v3_addr.c`**  
  - Switched from `IMPLEMENT_ASN1_FUNCTIONS(IPAddrBlocks)` to `IMPLEMENT_ASN1_FUNCTIONS_fname(IPAddrBlocks, IPAddrBlocks, IPAddrBlocks)` so the generated functions use the `IPAddrBlocks` name (matching the type) and are part of the public API.  
  - Exported the `IPAddrBlocks` ASN.1 item as `IPAddrBlocks_it` for use in external ASN.1 templates.

- **`include/openssl/x509v3.h.in`**  
  - Added `DECLARE_ASN1_FUNCTIONS(IPAddrBlocks)` so the new functions and `IPAddrBlocks_it` are declared in the public headers.

- **`util/libcrypto.num`**  
  - Registered the new symbols with the `RFC3779` tag: `d2i_IPAddrBlocks`, `i2d_IPAddrBlocks`, `IPAddrBlocks_free`, `IPAddrBlocks_new`, `IPAddrBlocks_it`.

- **`util/missingcrypto.txt`** and **`util/missingcrypto111.txt`**  
  - Updated to include `IPAddrBlocks_it` in the list of documented/managed symbols.

Existing helpers such as `X509v3_addr_add_range`, `X509v3_addr_add_prefix`, `X509v3_addr_canonize`, and `X509v3_addr_is_canonical` already take `IPAddrBlocks *`; they now work with `IPAddrBlocks` instances created via `IPAddrBlocks_new()` and decoded via `d2i_IPAddrBlocks()`.

---

Tests
-----

- **`test/v3ext.c`**  
  - Added `test_ipaddrblocks_api()` (under `#ifndef OPENSSL_NO_RFC3779`), which:
    - Round-trips an empty `IPAddrBlocks` with `IPAddrBlocks_new` → `i2d_IPAddrBlocks` → `d2i_IPAddrBlocks` → `IPAddrBlocks_free`, and checks that the decoded stack has zero elements.
    - Builds a non-empty `IPAddrBlocks` with `X509v3_addr_add_range`, round-trips it with `i2d_IPAddrBlocks` / `d2i_IPAddrBlocks`, and verifies the decoded structure via the existing `check_addr()` helper.
  - The test is registered in `setup_tests()` and is run with the existing v3ext tests (e.g. when running the x509 recipe that invokes the v3ext binary with `test/certs/pathlen.pem`).

**Optional checks (run before opening the PR):**

- Run the v3ext tests, e.g.  
  `DYLD_LIBRARY_PATH=. ./test/v3ext test/certs/pathlen.pem`  
  (or the equivalent with `LD_LIBRARY_PATH` on Linux). All 7 tests, including `test_ipaddrblocks_api`, should pass.
- Run `make doc-nits` to ensure documentation and symbol lists are consistent.

---

Documentation
-------------

- **`doc/man3/X509_dup.pod`**  
  - Added `IPAddrBlocks_free`, `IPAddrBlocks_it`, and `IPAddrBlocks_new` to the NAME section so the new API and the exported ASN.1 item are documented with the other type-based ASN.1 functions. The `IPAddrBlocks_it` entry documents the exported ASN.1 item (used in custom templates) alongside other `_it` symbols such as `ISSUER_SIGN_TOOL_it`.

- **`doc/man3/d2i_X509.pod`**  
  - Added `d2i_IPAddrBlocks` and `i2d_IPAddrBlocks` to the NAME section so the decode/encode functions are listed with the other d2i/i2d helpers.

- **`CHANGES.md`**  
  - Under “Changes between 4.0 and 4.1”, added an entry describing the new IPAddrBlocks API and that it fixes issue #18528.

---

Summary of changed files
------------------------

| Area           | File(s) |
|----------------|---------|
| Implementation | `crypto/x509/v3_addr.c` |
| Public API     | `include/openssl/x509v3.h.in` |
| Symbols        | `util/libcrypto.num`, `util/missingcrypto.txt`, `util/missingcrypto111.txt` |
| Tests          | `test/v3ext.c` |
| Documentation  | `doc/man3/X509_dup.pod`, `doc/man3/d2i_X509.pod`, `CHANGES.md` |
