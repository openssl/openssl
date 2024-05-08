# Building OpenSSL

You want to check out Discord Messenger?  Well you're probably going to want to compile OpenSSL,
so I've provided some shell scripts to make it easier to build.

The main command to run is:
```
./buildit
```

Note: You will need Mingw-w64, and specifically the mingw32 shell.  You'll also need to follow
the [notes on Windows](NOTES-WINDOWS.md) regarding the packages to install.

### Configure

The script configures OpenSSL to:
- compile with MinGW
- not include any assembly blobs (makes it not use advanced instruction sets such as SSE2)
- defines `WINVER` and `_WIN32_WINNT` as `0x0501` (to avoid OpenSSL targeting Vista+ APIs)
- defines `OPENSSL_THREADS` to allow OpenSSL to use threads
- defines `OPENSSL_NO_ASYNC` and `OPENSSL_USE_NODELETE` to avoid OpenSSL importing certain Vista+
  APIs

### Build

Then, it runs `make -j$(nproc)`. It takes the number of logical processors in your system, and
runs a make job for each.  This allows a faster build while not totally blowing up your computer
(as `make -j` would do - unboundedly spawn jobs)

### Patch to remove a single XP+ import

Finally, it runs `./patchlibcrypto`, which compiles a single C file, `./patchlibcrypto.c` to a temp
file, runs it, and deletes it.  `patchlibcrypto.c` patches libcrypto-3.dll to change imports to
`_strtoi64` and `_strtoui64` to `iswxdigit` and `isleadbyte` (functions likely to return zero given
the parameters, and have the same length, and are also exported by msvcrt.dll), by doing a dumb
binary search.

Note: Ideally I'd remove all uses of \*scanf, though not totally sure that'll remove the import
patch requirement.

Note: This patch step is optional if you don't intend to run Discord Messenger on Windows 2000 or
older.

-iProgramInCpp
