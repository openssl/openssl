#!/usr/local/bin/perl
# I have this in perl so I can use more usefull register names and then convert
# them into alpha registers.
#

push(@INC,"perlasm","../../perlasm");
require "alpha.pl";
require "alpha/mul_add.pl";
require "alpha/mul.pl";
require "alpha/sqr.pl";
require "alpha/add.pl";
require "alpha/sub.pl";
require "alpha/mul_c8.pl";
require "alpha/mul_c4.pl";
require "alpha/sqr_c4.pl";
require "alpha/sqr_c8.pl";
require "alpha/div.pl";

&asm_init($ARGV[0],$0);

&bn_mul_words("bn_mul_words");
&bn_sqr_words("bn_sqr_words");
&bn_mul_add_words("bn_mul_add_words");
&bn_add_words("bn_add_words");
&bn_sub_words("bn_sub_words");
&bn_div_words("bn_div_words");
&bn_mul_comba8("bn_mul_comba8");
&bn_mul_comba4("bn_mul_comba4");
&bn_sqr_comba4("bn_sqr_comba4");
&bn_sqr_comba8("bn_sqr_comba8");

&asm_finish();

