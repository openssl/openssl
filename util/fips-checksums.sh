#! /bin/sh

HERE=`dirname $0`

for f in "$@"; do
    case "$f" in
        *.c | *.h )
            cat "$f" \
                | $HERE/lang-compress.pl 'C' \
                | unifdef -DFIPS_MODE=1 \
                | openssl sha256 -r \
                | sed -e "s| \\*stdin| *$f|"
            ;;
        *.pl ) 
            cat "$f" \
                | $HERE/lang-compress.pl 'perl' \
                | openssl sha256 -r \
                | sed -e "s| \\*stdin| *$f|"
            ;;
        *.S ) 
            cat "$f" \
                | $HERE/lang-compress.pl 'S' \
                | openssl sha256 -r \
                | sed -e "s| \\*stdin| *$f|"
            ;;
    esac
done
