#!/bin/sh
# Run the pq perf tests under massif for each (impl, N) and emit a
# gnuplot data table of peak heap bytes vs N.
#
# Output:
#   pq_new_mem.dat
#   pq_old_mem.dat
#
# Columns: N peak_heap_bytes
#
# valgrind options:
#   --tool=massif       heap profiler
#   --time-unit=B       snapshots indexed by bytes allocated, so the
#                       peak snapshot lands exactly where heap is max
#   --pages-as-heap=no  count only malloc/free, not page mappings
#   --detailed-freq=1   every snapshot is detailed (we only need peak)
#   --threshold=0.0     don't fold small alloc trees away

set -eu

NEW_BIN=${NEW_BIN:-test/pq_new_test}
OLD_BIN=${OLD_BIN:-test/pq_old_test}
SIZES="${SIZES:-64 256 1024 4096 16384 65536 262144 1048576}"

[ -x "$NEW_BIN" ] || { echo "no $NEW_BIN -- build it first" >&2; exit 1; }
[ -x "$OLD_BIN" ] || { echo "no $OLD_BIN -- build it first" >&2; exit 1; }
command -v valgrind >/dev/null || { echo "valgrind missing" >&2; exit 1; }

extract_peak() {
    # Find max mem_heap_B across all snapshots in a massif .ms file.
    awk -F= '/^mem_heap_B=/ { if ($2 > m) m = $2 } END { print m+0 }' "$1"
}

for impl in new old; do
    case "$impl" in
    new) bin=$NEW_BIN ;;
    old) bin=$OLD_BIN ;;
    esac
    out="pq_${impl}_mem.dat"
    {
        echo "# valgrind massif peak heap (bytes) -- $impl"
        echo "# N           peak_heap_B"
        for n in $SIZES; do
            ms=$(mktemp)
            valgrind --tool=massif --time-unit=B --pages-as-heap=no \
                     --detailed-freq=1 --threshold=0.0 \
                     --trace-children=yes \
                     --massif-out-file="$ms" \
                     "$bin" "$n" >/dev/null 2>&1
            peak=$(extract_peak "$ms")
            rm -f "$ms"
            printf "%-12d %d\n" "$n" "$peak"
        done
    } | tee "$out"
done
