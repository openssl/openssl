# I Can Haz Proof?

Note: so far only tested on MacOS.

First of all, you need an old version of clang: 3.6.x, 3.7.x or
3.8.x. At the time of writing, MacPorts clang-3.6 does not work
completely.

You can find it [here](http://llvm.org/releases/download.html).

Then you need [SAW](http://saw.galois.com/builds/nightly/) (I used the
12/12/16 version) and [Z3](https://github.com/Z3Prover/z3/releases).

Now, configure and build OpenSSL in a form useful to SAW:

    $ CC=<path to clang> ./config enable-saw
    $ make build_libs

Unfortunately, OpenSSL's build system is not currently flexible enough
to manage the next steps, so this may not work on all platforms
(patches welcome):

    $ cd proof
    $ SAW=<path to SAW binaries> Z3=<path to Z3 binaries> LLVM=<path to clang 3.x binaries> LINK=<path to llvm-link> make
