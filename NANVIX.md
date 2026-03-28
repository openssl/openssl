# OpenSSL Port for Nanvix

> **TL;DR:** This is a port of the OpenSSL cryptographic library for the Nanvix operating system. Jump to [Quick Start](#quick-start) to get started immediately.

---

## Overview

This document describes the port of [OpenSSL](https://www.openssl.org/) cryptographic library for the [Nanvix](https://github.com/nanvix/nanvix) operating system. This port enables OpenSSL to run on Nanvix, a POSIX-compatible educational operating system.

| Property | Value |
|----------|-------|
| **Base Version** | OpenSSL 3.5.0 |
| **Target Platform** | Nanvix (i686) |
| **Build System** | GNU Make (wrapping OpenSSL Configure) |

**What's included:**
- ✅ Cross-compilation support for Nanvix
- ✅ Static library builds (`libcrypto.a`, `libssl.a`)
- ✅ Build helper scripts
- ✅ CI/CD integration
- ✅ Test executables (`openssl_nanvix_test.elf`)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Building](#building)
4. [Testing](#testing)
5. [Changes Summary](#changes-summary)
6. [Known Limitations](#known-limitations)
7. [CI/CD](#cicd)

---

## Quick Start

For experienced users who want to build quickly:

```bash
# 1. Install nanvix-zutil (requires gh CLI: https://cli.github.com)
#    Using a venv is recommended on modern Linux distros (PEP 668).
python3 -m venv .venv && source .venv/bin/activate
WHEEL_URL=$(gh api repos/nanvix/zutils/releases/latest \
  --jq '.assets[] | select(.name | endswith(".whl")) | .browser_download_url')
pip install "$WHEEL_URL"

# 2. Setup (downloads Nanvix sysroot automatically)
./z setup

# 3. Build
./z build

# 4. Run tests
./z test
```

Or build directly with Make (advanced):

```bash
# 1. Pull the Docker image
docker pull nanvix/toolchain:latest-minimal

# 2. Download Nanvix sysroot
curl -fsSL https://raw.githubusercontent.com/nanvix/nanvix/refs/heads/dev/scripts/get-nanvix.sh | bash -s -- nanvix-artifacts
tar -xjf nanvix-artifacts/*microvm*single*.tar.bz2 -C nanvix-artifacts
export NANVIX_HOME=$(find nanvix-artifacts -maxdepth 2 -type d -name "bin" -exec dirname {} \; | head -1)

# 3. Build (Docker is used automatically if native toolchain is not found)
make -f Makefile.nanvix CONFIG_NANVIX=y NANVIX_HOME="$NANVIX_HOME"

# 4. Run tests
make -f Makefile.nanvix CONFIG_NANVIX=y NANVIX_HOME="$NANVIX_HOME" test
```

Continue reading for detailed instructions.

---

## Prerequisites

You need the following to build OpenSSL for Nanvix:

| Component | Description | Install |
|-----------|-------------|---------|
| **nanvix-zutil** | Build orchestration CLI | `pip install` from [GitHub Releases](https://github.com/nanvix/zutils/releases) |
| **Nanvix Toolchain** | i686-nanvix cross-compiler | Docker image or native install |
| **Nanvix Sysroot** | System libraries and linker script | `nanvix-zutil setup` |

### Available Platform Configurations

| Platform | Process Mode | Artifact Pattern |
|----------|--------------|------------------|
| hyperlight | multi-process | `hyperlight.*multi-process` |
| hyperlight | single-process | `hyperlight.*single-process` |
| hyperlight | standalone | `hyperlight.*standalone` |
| microvm | single-process | `microvm.*single-process` |
| microvm | multi-process | `microvm.*multi-process` |
| microvm | standalone | `microvm.*standalone` |

### Downloading Nanvix

```bash
curl -fsSL https://raw.githubusercontent.com/nanvix/nanvix/refs/heads/dev/scripts/get-nanvix.sh | bash -s -- nanvix-artifacts
```

The script downloads all release artifacts. Extract the one matching your target platform (see [Quick Start](#quick-start) for a complete example).

---

## Building

### Using nanvix-zutil (Recommended)

```bash
# Install nanvix-zutil (use a venv on modern Linux distros)
python3 -m venv .venv && source .venv/bin/activate
WHEEL_URL=$(gh api repos/nanvix/zutils/releases/latest \
  --jq '.assets[] | select(.name | endswith(".whl")) | .browser_download_url')
pip install "$WHEEL_URL"

# Setup sysroot and build
./z setup
./z build
```

### Using Docker (Direct Make)

The Makefile supports automatic Docker fallback when the native toolchain is not available:

```bash
# Pull the Nanvix toolchain Docker image
docker pull nanvix/toolchain:latest-minimal

# Build (Docker is used automatically if native toolchain is not found)
make -f Makefile.nanvix CONFIG_NANVIX=y NANVIX_HOME=/path/to/nanvix/sysroot-debug
```

> **Note:** The sysroot (`NANVIX_HOME`) must contain `lib/libposix.a` and `lib/user.ld` from a Nanvix build.

**Docker Fallback Behavior:**
- If `NANVIX_TOOLCHAIN` points to a valid toolchain, it uses the native compiler
- If the native toolchain is not found, it automatically uses Docker if available
- Use `CONFIG_NANVIX_DOCKER=y` to force Docker usage even when native toolchain exists
- Use `NANVIX_DOCKER_IMAGE` to specify a custom Docker image (default: `nanvix/toolchain:latest-minimal`)

### Using Native Toolchain

```bash
export NANVIX_TOOLCHAIN=/path/to/toolchain  # Contains: bin/i686-nanvix-gcc
export NANVIX_HOME=/path/to/nanvix          # Contains: lib/user.ld, lib/libposix.a
make -f Makefile.nanvix CONFIG_NANVIX=y all
```

### Build Outputs

After a successful build, you will have:

| File | Description |
|------|-------------|
| `libcrypto.a` | OpenSSL cryptography static library |
| `libssl.a` | OpenSSL SSL/TLS static library |
| `providers/libcommon.a` | Common provider library |
| `providers/libdefault.a` | Default provider library |
| `providers/liblegacy.a` | Legacy provider library |

---

## Testing

> **Important:** OpenSSL is built without command-line applications (`no-apps`), so testing focuses on verifying the static libraries are correctly built and can be linked.

### Running the Test Suite

```bash
# Run all tests
./z test

# Or run specific test targets
./z test -- test-smoke test-integration
```

Alternatively, invoke Make directly:

```bash
make -f Makefile.nanvix CONFIG_NANVIX=y NANVIX_HOME=/path/to/nanvix test
```

### Test Coverage

The test target verifies:
- Static libraries (`libcrypto.a`, `libssl.a`) exist
- Libraries are valid archives with correct symbols
- Libraries can be inspected with cross-toolchain `ar`

---

## Changes Summary

The following changes were made to support Nanvix.

### Build System Changes

| Change | Description |
|--------|-------------|
| New Makefile | Added `Makefile.nanvix` for Nanvix cross-compilation |
| Cross-compilation | Uses `CONFIG_NANVIX=y` option to enable Nanvix build |
| Docker support | Automatic Docker fallback when native toolchain not available |
| Configure wrapper | Wraps `./Configure` with Nanvix cross-compilation settings |
| Shared libraries | Disabled (`no-shared`) |
| Applications | Disabled (`no-apps`) for library-only build |

### Platform Configuration

A Nanvix platform target is defined in `Configurations/10-main.conf`:

```perl
"nanvix" => {
    inherit_from     => [ "BASE_unix" ],
    asm_arch         => 'x86',
    perlasm_scheme   => "elf",
    cppflags         => add(threads("-D_REENTRANT")),
    thread_scheme    => "pthreads",
},
```

### Configure Options

| Option | Description |
|--------|-------------|
| `no-shared` | Build static libraries only |
| `threads` | Enable threading support |
| `no-dso` | Disable dynamic shared objects |
| `no-apps` | Don't build command-line applications |
| `no-docs` | Don't build documentation |
| `no-rdrand` | Disable RDRAND instruction (not available on Nanvix) |
| `no-posix-io` | Disable POSIX I/O operations |
| `no-asm` | Disable assembly optimizations |
| `no-ui-console` | Disable console UI |

### New Files

| File | Purpose |
|------|---------|
| `Makefile.nanvix` | Standalone Makefile for Nanvix cross-compilation |
| `NANVIX.md` | This documentation file |
| `z` | Unified entry point (delegates to `z.sh` or `z.ps1`) |
| `z.sh` | Bash wrapper that delegates to `nanvix-zutil` CLI |
| `z.ps1` | PowerShell wrapper that delegates to `nanvix-zutil` CLI |
| `.nanvix/z.py` | Build script (extends `nanvix-zutil` `ZScript`) |
| `.nanvix/nanvix.toml` | Package manifest for dependency resolution |
| `.github/workflows/nanvix-ci.yml` | CI workflow for automated builds |

### Legacy Build Script

The `z` script delegates to `nanvix-zutil`, which orchestrates the entire build lifecycle (setup, build, test, release, clean). Users should prefer `./z` over raw `make -f Makefile.nanvix` invocations for consistency with other Nanvix ports.

---

## Known Limitations

| Limitation | Impact |
|------------|--------|
| **No shared libraries** | Only static libraries (`libcrypto.a`, `libssl.a`) are built |
| **No command-line tools** | `openssl` CLI not available (`no-apps`) |
| **No assembly optimizations** | Pure C implementation (`no-asm`) |
| **No RDRAND** | Hardware random number generator not available |
| **No POSIX I/O** | File operations limited |
| **Static linking only** | All applications using OpenSSL must be statically linked |

---

## CI/CD

The GitHub Actions workflow at `.github/workflows/nanvix-ci.yml` automates building and testing on every change. It uses the `nanvix-zutil` CLI (installed from the wheel in GitHub Releases) for all build orchestration.

### Workflow Structure

| Job | Description |
|-----|-------------|
| `ci` | Calls the shared Nanvix reusable workflow that builds, tests, and packages this port |

The `ci` job delegates to a central reusable workflow, which defines internal jobs such as
`get-nanvix-info`, `build`, `release`, and `report-failure` to handle manifest resolution,
cross-compilation, release creation, and failure reporting. These internal jobs live in the
shared CI configuration and are not defined directly in this repository's workflow file.

### Trigger Events

| Event | Description |
|-------|-------------|
| Push to `nanvix/**` | Any push to Nanvix branches |
| PR to `nanvix/**` | Pull requests targeting Nanvix branches |
| Daily schedule | Runs at midnight UTC |
| Manual dispatch | Can be triggered manually |
| Repository dispatch | Triggered by `nanvix-release` events |

### Build Matrix

The CI runs on 6 different platform/process-mode configurations:

| Platform | Process Mode |
|----------|--------------|
| hyperlight | multi-process |
| hyperlight | single-process |
| hyperlight | standalone |
| microvm | multi-process |
| microvm | single-process |
| microvm | standalone |

All configurations run in parallel with `fail-fast: false`, ensuring that all platforms are tested even if one fails.

---
