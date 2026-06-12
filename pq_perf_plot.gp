# gnuplot script: one SVG per benchmark column, overlaying new vs old.
#
# Inputs (produced by the perf binaries, with framework noise stripped):
#   pq_new.dat
#   pq_old.dat
#
# Typical pipeline:
#   util/wrap.pl test/pq_new_test | grep -E '^(#|[0-9]+[[:space:]])' > pq_new.dat
#   util/wrap.pl test/pq_old_test | grep -E '^(#|[0-9]+[[:space:]])' > pq_old.dat
#   gnuplot pq_perf_plot.gp
#
# Outputs (one file per benchmark, written to the current directory):
#   pq_push_grow.svg        pq_push_reserved.svg    pq_pop_drain.svg
#   pq_remove_random.svg    pq_steady_push_pop.svg  pq_churn_rm_push.svg
#   pq_perf_summary.svg     (2x3 multiplot summary)
#
# Data columns in each .dat file:
#   1=N  2=push_grow  3=push_reserved  4=pop_drain
#   5=remove_random  6=steady_push_pop  7=churn_rm_push
#
# Requires gnuplot >= 5.0 (for array support).

set terminal svg size 900,600 noenhanced font 'Helvetica,11' background rgb 'white'
set logscale x 2
set xlabel 'N (elements)'
set ylabel 'ns / op'
set grid
set key top left box
set style line 1 lc rgb '#1f77b4' lw 2 pt 7  ps 1.3
set style line 2 lc rgb '#d62728' lw 2 pt 9  ps 1.3

array slug[6]    = ["push_grow",      "push_reserved",  "pop_drain",     "remove_random",  "steady_push_pop", "churn_rm_push"]
array pretty[6]  = ["push (grow)",    "push (reserved)","pop (drain)",   "remove (random)","steady push+pop", "churn rm+push"]

do for [i=1:6] {
    col = i + 1
    set output sprintf('pq_%s.svg', slug[i])
    set title sprintf('pq perf: %s   (lower is better)', pretty[i])
    plot 'pq_new.dat' using 1:col with linespoints ls 1 title 'pq.c (intrusive)', \
         'pq_old.dat' using 1:col with linespoints ls 2 title 'priority_queue.c'
}

# Bonus: a single 2x3 multiplot summary for at-a-glance review.
set terminal svg size 1600,1000 noenhanced font 'Helvetica,10' background rgb 'white'
set output 'pq_perf_summary.svg'
set multiplot layout 2,3 title "pq.c vs priority_queue.c -- ns/op (lower is better)"
unset key
do for [i=1:6] {
    col = i + 1
    set title pretty[i]
    # show the key only on the first panel so the legend is readable
    if (i == 1) { set key top left box } else { unset key }
    plot 'pq_new.dat' using 1:col with linespoints ls 1 title 'pq.c (intrusive)', \
         'pq_old.dat' using 1:col with linespoints ls 2 title 'priority_queue.c'
}
unset multiplot
