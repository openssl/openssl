Running with Valgrind
=====================

OpenSSL 4.0 no longer arms `OPENSSL_cleanup()` function as an `atexit(3)`
handler. So unless the application explicitly calls `OPENSSL_cleanup()` valgrind and
similar memory leak detectors may report `still reachable` memory blocks
as memory leaks. An example of a valgrind report reads as follows:

```output
# valgrind ./pkeyread -f pem -k dh 8
==280439== Memcheck, a memory error detector
==280439== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==280439== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==280439== Command: ./pkeyread -f pem -k dh 8
==280439==
Average time per pem(dh) call: 506329.113924us
==280439==
==280439== HEAP SUMMARY:
==280439==     in use at exit: 239,521 bytes in 4,137 blocks
==280439==   total heap usage: 21,841 allocs, 17,704 frees, 4,089,104 bytes allocated
==280439==
==280439== LEAK SUMMARY:
==280439==    definitely lost: 0 bytes in 0 blocks
==280439==    indirectly lost: 0 bytes in 0 blocks
==280439==      possibly lost: 0 bytes in 0 blocks
==280439==    still reachable: 239,521 bytes in 4,137 blocks
==280439==         suppressed: 0 bytes in 0 blocks
==280439== Rerun with --leak-check=full to see details of leaked memory
==280439==
==280439== For lists of detected and suppressed errors, rerun with: -s
==280439== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

The valgrind output above reports there are 239,521 of reachable memory
when process exits. The memory is accounted to missing call
to`OPENSSL_cleanup()`before process exits. Indeed adding a call to
`OPENSSL_cleanup()` just before `main()` exits makes valgrind happy:

```output
# valgrind ./pkeyread -f pem -k dh 8
==280595== Memcheck, a memory error detector
==280595== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==280595== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==280595== Command: ./pkeyread -f pem -k dh 8
==280595==
Average time per pem(dh) call: 493827.160494us
==280595==
==280595== HEAP SUMMARY:
==280595==     in use at exit: 0 bytes in 0 blocks
==280595==   total heap usage: 22,239 allocs, 22,239 frees, 4,185,044 bytes allocated
==280595==
==280595== All heap blocks were freed -- no leaks are possible
==280595==
==280595== For lists of detected and suppressed errors, rerun with: -s
==280595== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```

It is matter of opinion whether a missing call to `OPENSSL_cleanup()` is
is an error or not. For example not calling `OPENSSL_cleanup()` can be
considered as optimization to save CPU cycles, because the OS is going
to reclaim memory way faster when the application exits than making the
application call `OPENSSL_cleanup()` directly.

The only remaining concern is the valgrind report itself, because it may
cause disruption in environments where test automation is deployed.
If changing application source code is not an option, then you need
to use a valgrind suppression file [1]. The suppression file for
openssl is shipped with OpenSSL sources. It is found at
`$OPENSSL_SRCS/util/valgrind.suppressions`. To use it just add
`--suppression` option to the valgrind command:
`valgrind --suppressions=`OPENSSL_SRCS/util/valgrind.suppression ...`
For `pkeyread` the command and output reads as follows:

```output
# valgrind --suppressions=$OPENSSL_SRCS/util/valgrind.suppression  ./pkeyread -f pem -k dh 8
==280896== Memcheck, a memory error detector
==280896== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==280896== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==280896== Command: ./pkeyread -f pem -k dh 8
==280896==
Average time per pem(dh) call: 476190.476190us
==280896==
==280896== HEAP SUMMARY:
==280896==     in use at exit: 239,521 bytes in 4,137 blocks
==280896==   total heap usage: 22,816 allocs, 18,679 frees, 4,325,714 bytes allocated
==280896==
==280896== LEAK SUMMARY:
==280896==    definitely lost: 0 bytes in 0 blocks
==280896==    indirectly lost: 0 bytes in 0 blocks
==280896==      possibly lost: 0 bytes in 0 blocks
==280896==    still reachable: 0 bytes in 0 blocks
==280896==         suppressed: 239,521 bytes in 4,137 blocks
==280896==
==280896== For lists of detected and suppressed errors, rerun with: -s
==280896== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

[1] <https://valgrind.org/docs/manual/manual-core.html#manual-core.suppress>
