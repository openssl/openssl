# I Can Haz Fuzz?

Or, how to fuzz OpenSSL with libfuzzer.

Starting from a vanilla+OpenSSH server Ubuntu install.

Use Chrome's handy recent build of clang. Older versions may also work.

    $ sudo apt-get install git
    $ mkdir git-work
    $ git clone https://chromium.googlesource.com/chromium/src/tools/clang
    $ clang/scripts/update.py

You may want to git pull and re-run the update from time to time.

Update your path:

    $ PATH=~/third_party/llvm-build/Release+Asserts/bin/:$PATH

Get and build libFuzzer (there is a git mirror at
https://github.com/llvm-mirror/llvm/tree/master/lib/Fuzzer if you prefer):

    $ cd
    $ sudo apt-get install subversion
    $ mkdir svn-work
    $ cd svn-work
    $ svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
    $ cd Fuzzer
    $ clang++ -c -g -O2 -std=c++11 *.cpp
    $ ar r libFuzzer.a *.o
    $ ranlib libFuzzer.a

Configure for fuzzing:

    $ CC=clang ./config enable-fuzz enable-asan enable-ubsan no-shared
    $ sudo apt-get install make
    $ LDCMD=clang++ make -j
    $ fuzz/helper.py <fuzzer> <arguments>

Where `<fuzzer>` is one of the executables in `fuzz/`. Most fuzzers do not
need any command line arguments, but, for example, `asn1` needs the name of a
data type.

If you get a crash, you should find a corresponding input file in
`fuzz/corpora/<fuzzer>-crash/`. You can reproduce the crash with

    $ fuzz/<fuzzer> <crashfile>
