#!/bin/bash

REGEX=' T [_]?(OQS|ntru|picnic|Keccak|.*SIKEp503|.*SIDHp503|.*SIKEp751|.*SIDHp751|.*shake128|.*shake256|rand_bytes|cpu_supports|uint64_from_char_array|uint64_to_char_array|print_hex|ntt_double|rec|aligned_alloc|aligned_free)'

if [[ $(nm -g liboqs.a | grep ' T ' | grep -E -v -i "$REGEX") ]];
then
    tput setaf 1;
    echo "Code contains the following non-namespaced global symbols; see https://github.com/open-quantum-safe/liboqs/wiki/Coding-conventions for function naming conventions.";
    tput sgr 0
    nm -g liboqs.a | grep ' T ' | grep -E -v -i "$REGEX"
    exit 1;
else
    tput setaf 2;
    echo "Code adheres to the project standards (global namespace).";
    tput sgr 0
    exit 0;
fi;
