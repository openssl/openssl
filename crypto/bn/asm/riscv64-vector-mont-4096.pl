#! /usr/bin/env perl
use POSIX;
use warnings;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
#$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code = "";

################################################################################
# Constants
################################################################################

my $xl = 64; # XLEN
my $vl = 128; # VLEN should be at least $vl
my $el = 32; # ELEN should be at least $el
# we only support LMUL = 1
my $lmul = 1;

my $bn = 4096; # bits of Big Number
my $word = 16; # number of bits in one SEW
my $R = $bn + $word; # log(montgomery radix R). 
# e.g. when bn = 256, word = 16, then R = log(2 ** (256 + 16)) = 272
# the result of this mmm is A*B*2^{-R} mod P

my $sew = $word * 2; # SEW
if ($sew > $el) {
    die "SEW must not be greater than ELEN! params: vl $vl, el $el, word $word, sew $sew";
}

my $way = $vl / $sew; # simd way
my $niter = $bn / $word; # number of iterations
my $ntotalreg = $niter / $way + 1; # number of vreg for one bn
my $nreg = $ntotalreg;
my $nelement = $ntotalreg * $way; # number of elements should be in A, B, P and AB
# e.g, when BN = 4096, VLEN = 128 and SEW = 32
# ntotalreg is 65 instead of 64, then nelement is 260 instead of 256

# we use vlseg to load data
# max nreg = 8 as restraint by seg8
# for nreg > 8, we can split them into groups
my $ngroup = 1;
my $lastgroup = 0;
if ($nreg > 8) {
    $lastgroup = $nreg % 8;
    $ngroup = ($nreg - $lastgroup) / 8;
    if ($lastgroup != 0) {
        $ngroup = $ngroup + 1;
    } else {
        # if last group is 0, then last group is 8
        $lastgroup = 8;
    }
    $nreg = 8;
} else {
    $lastgroup = $nreg;
}
# e.g, when BN = 4096, VLEN = 128 and SEW = 32
# ngroup is 9 and last group is 1

################################################################################
# Register assignment
################################################################################

my ($AB, $A, $B, $P, $MU) = ("a0", "a1", "a2", "a3", "a4");

# happy that they are caller-saved
my ($T0, $STRIDE, $T2, $T3, $LOOP, $LOOP2) = ("t0", "t1", "t2", "t3", "t4", "t5");

my ($PVN, $AVN, $ABVN) = (0, 10, 20);
my ($PV, $AV, $ABV) = ("v$PVN", "v$AVN", "v$ABVN");

# temporary reg
my $TV = "v30";
my $TV2 = "v31";

################################################################################
# utility
################################################################################

sub propagate {
    my $j = shift;
    my $ngroupreg = shift;
    my $j1 = $j + 1; # no warry on overflow: see j != nreg - 1 below
    my $ABVJ = "v@{[$ABVN + $j]}";
    my $ABVJ1 = "v@{[$ABVN + $j1]}";
    # use carry TV from the $nreg - 1 of the previous group
    if ($j == 0) {
        $code .= <<___;
    vadd.vv $ABVJ, $ABVJ, $TV
___
    }
    $code .= <<___;
    # save carry in TV
    vsrl.vi $TV, $ABVJ, $word
    # mod 2 ** $word
    vand.vv $ABVJ, $ABVJ, $TV2
___
    if ($j != $ngroupreg - 1) {
        $code .= <<___;
    vadd.vv $ABVJ1, $ABVJ1, $TV
___
    }
}

sub propagate_niter {
# propagate carry for the whole bn
# in total ntotalreg*way times
$code .= <<___;
    # start loop of niter + 1 times
    # use T2 as outer loop index
    li  $T2,0
9:
    # mask
    # set TV2 for every propagate()
    # set TV2 every time (see slide1up below)
    li  $T0,@{[2 ** $word - 1]}
    vmv.v.x $TV2,$T0

    # carry for ABV_0
    vmv.v.i $TV,0

    # loop variable
    li  $LOOP2,0
___
# start loop of ngroup - 1 times
if ($ngroup != 1) {
    $code .= <<___;
10:
    # load one group of values from arg
    # offset of one group
    # !!! important: assume nreg = 8 and sew = 32
    # log(8) + log(32/8) = 5
    slli $T3,$LOOP2,5
    add  $T3,$T3,$AB
    vlsseg${nreg}e$sew.v $ABV, ($T3), $STRIDE
___

    # propagate carry for nreg round
    # the carry for $nreg - 1 is propagated to TV
    # then added in the next group
    for (my $j = 0; $j != $nreg; $j++) {
        propagate($j, $nreg);
    }

$code .= <<___;
    # store one group of AB
    vssseg${nreg}e$sew.v $ABV, ($T3), $STRIDE

    addi $LOOP2,$LOOP2,1
    li  $T0,@{[$ngroup - 1]}
    bne $LOOP2,$T0,10b
___
}
# special treatment on last group
$code .= <<___;
    # load last group of values from arg
    # offset of last group
    # !!! important: assume nreg = 8 and sew = 32
    # log(8) + log(32/8) = 5
    # LOOP2 is now ngroup - 1
    slli $T3,$LOOP2,5
    add  $T3,$T3,$AB
    vlsseg${lastgroup}e$sew.v $ABV, ($T3), $STRIDE
___
# propagate carry for lastgroup round
# the carry for $lastgroup - 1 is propagated to TV
# then added in the next group (now AB_0)
for (my $j = 0; $j != $lastgroup; $j++) {
    propagate($j, $lastgroup);
}
$code .= <<___;
    # store last group of AB
    vssseg${lastgroup}e$sew.v $ABV, ($T3), $STRIDE

    # update carry of AB_{ntotalreg - 1} to AB_0
    vlsseg1e$sew.v $ABV, ($AB), $STRIDE
    vslide1up.vx $TV2, $TV, zero
    vadd.vv $ABV, $ABV, $TV2
    vssseg1e$sew.v $ABV, ($AB), $STRIDE
___

# outer loop
$code .= <<___;
    addi  $T2,$T2,1
    li    $T0,$way
    bne   $T2,$T0,9b
___
}

sub move {
# move AB_1 to AB_0, AB_2 to AB_1, ... , AB_0 (in TV now) to AB_{ntotalreg-1}
$code .= <<___;
    # loop variable
    li  $LOOP2,0
___
if ($ngroup != 1) {
    $code .= <<___;
2:
    # load one offseted group of values from arg
    # offset of one group
    # !!! important: assume nreg = 8 and sew = 32
    # log(8) + log(32/8) = 5
    slli $T2,$LOOP2,5

    # then offset by 1 element
    addi $T2,$T2,@{[$sew / 8]}
    add  $T3,$T2,$AB
    vlsseg${nreg}e$sew.v $ABV, ($T3), $STRIDE

    # back to original offset
    addi $T3,$T3,@{[-$sew / 8]}
    vssseg${nreg}e$sew.v $ABV, ($T3), $STRIDE

    addi $LOOP2,$LOOP2,1
    li  $T2,@{[$ngroup - 1]}
    bne $LOOP2,$T2,2b
___
}
# special treatment on last group
$code .= <<___;
    # load last group of values from arg
    # offset of last group
    # !!! important: assume nreg = 8 and sew = 32
    # log(8) + log(32/8) = 5
    # LOOP2 is now ngroup - 1
    slli $T2,$LOOP2,5
    # then offset by 1 element
    addi $T2,$T2,@{[$sew / 8]}
    add  $T3,$T2,$AB
___
if ($lastgroup != 1) {
    $code .= <<___;
    vlsseg@{[$lastgroup - 1]}e$sew.v $ABV, ($T3), $STRIDE
___
}

$code .= <<___;
    # move AB_0 to AB_{ntotalreg-1}
    vmv.v.v v@{[$ABVN + $lastgroup - 1]}, $TV

    # back to original offset
    addi $T3,$T3,@{[-$sew / 8]}
    vssseg${lastgroup}e$sew.v $ABV, ($T3), $STRIDE
___
}

# consumes LOOP2, T0, AB, STRIDE from env, use T2, T3 as tmp var
sub macc {
    my $V = shift;
    my $VV = shift;
    my $VVN = shift;
    my $ngroupreg = shift;
    $code .= <<___;
    # load one group of values from arg
    # offset of one group
    # !!! important: assume nreg = 8 and sew = 32
    # log(8) + log(32/8) = 5
    slli $T2,$LOOP2,5
    add  $T3,$T2,$V
    vlsseg${ngroupreg}e$sew.v $VV, ($T3), $STRIDE
    add  $T3,$T2,$AB
    vlsseg${ngroupreg}e$sew.v $ABV, ($T3), $STRIDE
___

    for (my $j = 0; $j != $ngroupreg; $j++) {
        my $ABVJ = "v@{[$ABVN + $j]}";
        my $VVJ = "v@{[$VVN + $j]}";
        $code .= <<___;
        vmacc.vx $ABVJ, $T0, $VVJ
___
    }

    $code .= <<___;
    # store one group of AB
    vssseg${ngroupreg}e$sew.v $ABV, ($T3), $STRIDE
___
}

################################################################################
# function
################################################################################
$code .= <<___;
.text
.balign 16
.globl bn_mul_mont_rv${xl}imv_zvl${vl}b_sew${el}_bn${bn}_nelement${nelement}
.type bn_mul_mont_rv${xl}imv_zvl${vl}b_sew${el}_bn${bn}_nelement${nelement},\@function
# assume VLEN >= $vl, BN = $bn, SEW = $word * 2 = $sew
# we only support LMUL = 1 for now
# P, A, B, AB should have $nelement elements
bn_mul_mont_rv${xl}imv_zvl${vl}b_sew${el}_bn${bn}_nelement${nelement}:
    # quite SIMD
    li  $T0, $way # in case way > 31
    vsetvli zero, $T0, e$sew, m$lmul, ta, ma
    # stride
    li  $STRIDE, @{[$ntotalreg * $sew / 8]}
___

$code .= <<___;
    # start loop of niter + 1 times
    li  $LOOP,0
1:
    # AB = B_i*A + AB
    # !!!!!! important: lw here assumes SEW = 32
    # T0 is used in vmacc, do not use for temp now!
    lw  $T0, 0($B)
    addi $B, $B, 4 # advance B by a SEW

    # carry for ABV_0
    vmv.v.i $TV,0 
    # loop variable
    li  $LOOP2,0
___
# start loop of ngroup - 1 times
if ($ngroup != 1) {
    $code .= <<___;
2:
___
    macc($A, $AV, $AVN, $nreg);

    $code .= <<___;
    addi $LOOP2,$LOOP2,1
    # reuse T0 for special treatment
    li  $T2,@{[$ngroup - 1]}
    bne $LOOP2,$T2,2b
___
}
# special treatment on last group
macc($A, $AV, $AVN, $lastgroup);

## NOT TRUE: propagate carry for nreg round
# fully propagte
propagate_niter();

# AB = q*P + AB
$code .= <<___;
    # !!!!!! important: lw here assumes SEW = 32
    # T0 is used in vmacc, do not use for temp now!
    lw      $T0, 0($AB)
    mul     $T0, $T0, $MU
    # mod 2 ** $word
    # !!!! important: here we assume SEW = 32 and XLEN = 64
    sllw    $T0, $T0, $word
    srlw    $T0, $T0, $word

    # loop variable
    li  $LOOP2,0
___

# start loop of ngroup - 1 times
if ($ngroup != 1) {
    $code .= <<___;
2:
___
    macc($P, $PV, $PVN, $nreg);

$code .= <<___;
    addi $LOOP2,$LOOP2,1
    # reuse T0 for special treatment
    li  $T2,@{[$ngroup - 1]}
    bne $LOOP2,$T2,2b
___
}
# special treatment on last group
macc($P, $PV, $PVN, $lastgroup);

## NOT TRUE: propagate carry for nreg round
# fully propagte
propagate_niter();

$code .= <<___;
    # update carry of AB_{ntotalreg - 1} to AB_0
    # since we need to substract AB_0
    vlsseg1e$sew.v $ABV, ($AB), $STRIDE
    # AB / word
    vslide1down.vx $TV, $ABV, zero
    # do not need vssseg1e now
    # just store it in TV for move
___

move();

# outer loop
$code .= <<___;
    addi  $LOOP,$LOOP,1
    li    $T0,@{[$niter + 1]}
    bne   $LOOP,$T0,1b

    ret
___

# vlsseg1e32 is a pseudo-op of vlse32
# vssseg1e32 is a pseudo-op of vsse32
$code =~ s/seg1//g;

print $code;
close STDOUT or die "error closing STDOUT: $!";
