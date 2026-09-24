# SpacemiT RISC-V build

This downstream branch contains AES, Camellia, MD5, Poly1305, SHA-256/SHA-512
and short-message ChaCha20 optimizations for SpacemiT Linux systems. SM2 uses
the upstream implementation; the downstream RISC-V SM2 field backend has
been reverted.

## Supported target

- RV64 Linux with the `lp64d` ABI, the base RV64GC extensions, and both Zba
  and Zbb. MD5 assembly requires Zbb; Camellia assembly requires Zba and Zbb.
- SpacemiT vector-crypto targets with **VLEN=256 bits**. The optimized AES
  and SHA kernels use register group sizes selected for these targets.
  VLEN=128 vector-crypto execution is outside this branch's supported scope.
- The relevant vector-crypto extensions must be present for accelerated
  AES/SHA dispatch: V, Zvkned for AES, and Zvkb with Zvknha/Zvknhb for SHA.

The scalar assembly requirements are build-time requirements. Setting
`OPENSSL_riscvcap=0` clears runtime capability selection but does not remove
Zba/Zbb instructions from the library. This build is not a plain RV64GC
binary for CPUs lacking those extensions.

## Cross-build

Put the SpacemiT cross-toolchain `bin` directory on `PATH`. The validated
compiler is `riscv64-unknown-linux-gnu-gcc` 15.2.0 (`gf3b8c022145`), from the
SpacemiT `be1132811e8f` toolchain bundle.

From an unconfigured source checkout:

```sh
mkdir build-spacemit
cd build-spacemit
perl ../Configure linux64-riscv64 \
    --cross-compile-prefix=riscv64-unknown-linux-gnu- \
    -O3 -g -march=rv64gc_zba_zbb -mabi=lp64d -mtune=spacemit-x100
make -j24
```

`-march=rv64gc_zba_zbb -mabi=lp64d` states the scalar ISA and ABI explicitly,
instead of relying on a compiler's defaults. `-mtune=spacemit-x100` is an
optional scheduling choice for a compiler that supports it; it does not
enable ISA extensions. `-g` retains debug information for validation.

The build includes separately dispatched vector-crypto assembly. Leave
`OPENSSL_riscvcap` unset for normal hardware detection. Any explicit override
must describe extensions actually supported by the target CPU.

## Run on the target board

Run the cross-built binaries on a supported RISC-V board. From the build
directory, point the loader and provider search path at the matching build:

```sh
LD_LIBRARY_PATH="$PWD" OPENSSL_MODULES="$PWD/providers" ./apps/openssl version -a
```

Keep the source and build directories in the same relative layout when
copying them to the board. Relevant recipes can then be run with the board's
Perl, from the build directory:

```sh
SRCTOP=.. BLDTOP=. perl ../test/run_tests.pl \
    test_internal_sm2 test_internal_ec test_ec test_ecdsa \
    test_internal_chacha test_internal_poly1305 test_sha test_evp
```

For comparable performance results, use the same toolchain and flags for
upstream and downstream builds, pin both to the same core, record the core
frequency and capability setting, warm up both binaries, and alternate their
order across repeated measurements.
