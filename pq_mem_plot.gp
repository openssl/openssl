# gnuplot: plot peak heap (bytes) vs N for the new and old pq impls.
#
# Inputs (produced by pq_mem_collect.sh):
#   pq_new_mem.dat
#   pq_old_mem.dat
#
# Outputs:
#   pq_mem_peak.svg       absolute peak heap vs N
#   pq_mem_per_elem.svg   bytes/element vs N (factors out the
#                         constant library-overhead baseline)
#
# Requires gnuplot >= 5.0.

set terminal svg size 900,600 noenhanced font 'Helvetica,11' background rgb 'white'
set logscale x 2
set logscale y 10
set xlabel 'N (elements)'
set grid
set key top left box
set style line 1 lc rgb '#1f77b4' lw 2 pt 7 ps 1.3
set style line 2 lc rgb '#d62728' lw 2 pt 9 ps 1.3

set output 'pq_mem_peak.svg'
set title 'Peak heap (valgrind massif) -- lower is better'
set ylabel 'peak heap (bytes)'
plot 'pq_new_mem.dat' using 1:2 with linespoints ls 1 title 'pq.c (intrusive)', \
     'pq_old_mem.dat' using 1:2 with linespoints ls 2 title 'priority_queue.c'

# Bytes per element factors out the constant library overhead and gives
# the per-item storage cost: the asymptote tells you the queue's true
# memory density (element struct + queue's per-slot overhead).
set output 'pq_mem_per_elem.svg'
unset logscale y
set title 'Peak heap per element -- lower is better'
set ylabel 'bytes / element'
plot 'pq_new_mem.dat' using 1:($2/$1) with linespoints ls 1 title 'pq.c (intrusive)', \
     'pq_old_mem.dat' using 1:($2/$1) with linespoints ls 2 title 'priority_queue.c'
