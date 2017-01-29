# I Can Haz Proof?

Note: so far only tested on MacOS and Ubuntu.

First of all, you need an old version of clang: 3.6.x, 3.7.x or
3.8.x. At the time of writing, MacPorts clang-3.6 does not work
completely and the default Ubuntu clang is 3.8.

You can find it [here](http://llvm.org/releases/download.html). Or you can use MacPorts. Or ```apt```.

Then you need [SAW](http://saw.galois.com/builds/nightly/) (I used the
12/12/16 version) and [Z3](https://github.com/Z3Prover/z3/releases on MacOS).

Now, configure and build OpenSSL in a form useful to SAW:

    $ CC=<path to clang> ./config enable-saw
    $ cd proof
    $ make openssl

Unfortunately, OpenSSL's build system is not currently flexible enough
to manage the next steps, so this may not work on all platforms
(patches welcome):

    $ SAW=<path to SAW binaries> Z3=<path to Z3 binaries> CLANG=<path to clang> LINK=<path to llvm-link> make
