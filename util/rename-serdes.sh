#! /bin/bash

# Move directories and adjust the parent build.info
git mv crypto/serializer crypto/encode_decode
git mv providers/implementations/serializers \
    providers/implementations/encode_decode
sed -i \
    -e 's|serializers|encode_decode|' \
    -e 's|serializer|encode_decode|' \
    crypto/build.info providers/implementations/build.info

# Rename files and adjust build.info in the same directory
git ls-files \
    crypto/encode_decode \
    include/crypto/serializer.h \
    include/openssl/{de,}serializer* \
    providers/implementations/encode_decode \
    providers \
    doc/man3 \
    doc/man7 \
    test \
    | while read filename; do
    new_filename=$(echo "$filename" \
                       | sed -e 's/OSSL_DESERIALIZE/OSSL_DECODE/g' \
                             -e 's/deserialize/decode/g' \
                             -e 's/OSSL_SERIALIZE/OSSL_ENCODE/g' \
                             -e 's/serialize/encode/g' \
                             -e 's/serdes/endecode/g' )
    [ "$filename" = "$new_filename" ] || git mv "$filename" "$new_filename"
done
sed -i \
    -e 's/DESERIALIZE/DECODE/g' \
    -e 's/deserialize/decode/g' \
    -e 's/SERIALIZE/ENCODE/g' \
    -e 's/serialize/encode/g' \
    -e 's/serdes/endecode/g' \
    crypto/encode_decode/build.info \
    providers/implementations/encode_decode/build.info \
    test/build.info \
    test/recipes/04-test_encoder_decoder.t
git add -u

# Big source rename
# (additional files in sed command aren't caught by the big grep)
git grep -l -E 'OSSL_(OP_|FUNC_)?(DE)?SERIALIZER' \
    | xargs perl -p -i \
            -e 's/DESERIALIZE/DECODE/g;' \
            -e 's/Deserialize/Decode/g;' \
            -e 's/deserialize/decode/g;' \
            -e 's/Deserializing/Decoding/g;' \
            -e 's/deserializing/decoding/g;' \
            -e 's/Deserialization/Decoding/g;' \
            -e 's/deserialization/decoding/g;' \
            -e 's/\bDESER(_|\b)/DECODER$1/g;' \
            -e 's/\bdeser(_|\b)/decoder$1/g;' \
            -e 's/SERIALIZE/ENCODE/g;' \
            -e 's/Serialize/Encode/g;' \
            -e 's/serialize/encode/g;' \
            -e 's/Serializing/Encoding/g;' \
            -e 's/serializing/encoding/g;' \
            -e 's/Serialization/Encoding/g;' \
            -e 's/serialization/encoding/g;' \
            -e 's/\bSER(_|\b)/ENCODER$1/g;' \
            -e 's/\bser(_|\b)/encoder$1/g;' \
            -e 's/\bserprop\b/encprop/g;' \
            -e 's/\bsctx\b/ectx/g;' \
            crypto/property/property_parse.c \
            doc/man1/openssl-list.pod.in \
            doc/man7/OSSL_PROVIDER-FIPS.pod \
            doc/man7/provider*.pod \
            include/internal/cryptlib.h \
            providers/*.inc \
            providers/implementations/encode_decode/*.[ch] \
            providers/implementations/include/prov/implementations.h

# Remove unnecessary inclusions (if they were necessary, the Big API rename
# would have renamed them properly
git grep -l -E '<openssl/(de)?serializer\.h>' \
    | xargs sed -E -i \
            -e '/<openssl\/(de)?serializer\.h>/d'

# Adjust a few files that have columns
cat crypto/err/openssl.ec | while read line; do
    (
        set -- $line
        if [ "$1" = "L" ]; then
            printf "L %-13s %-31s %s\n" $2 $3 $4
        else
            echo "$line"
        fi
    )
done > crypto/err/openssl.ec.new
mv crypto/err/openssl.ec.new crypto/err/openssl.ec

cat util/libcrypto.num | while read sym num version info; do
    printf '%-39s %s\t%s\t%s\n' "$sym" "$num" "$version" "$info"
done > util/libcrypto.num.new
mv util/libcrypto.num.new util/libcrypto.num

cat util/other.syms | while read sym rest; do
    if [ "$sym" = "#" ]; then
        if [ -n "$rest" ]; then
            echo "$sym $rest"
        else
            echo "$sym"
        fi
    else
        printf '%-39s %s\n' "$sym" "$rest"
    fi
done > util/other.syms.new
mv util/other.syms.new util/other.syms

git add -u
