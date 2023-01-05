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

my $bn = 256; # bits of Big Number
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
my $nreg = $niter / $way + 1; # number of vreg for one bn
# max nreg = 8 as restraint by seg8
# thus max possible value for bn is 8 * (VLEN / 2) - word >= 496, suitable for most ECC (not P521, though)
# of couse with greater VLEN=2048 we can compute RSA 4096 here
if ($nreg > 8) {
    die "nreg must not be greater than 8! params: vl $vl, sew $sew, bn $bn, word $word, nreg $nreg";
}
my $nelement = $nreg * $way; # number of elements should be in A, B, P and AB
# actual bits used for one bn: $nreg * $vl
# we use vlseg to load data
# e.g, when BN = 256, VLEN = 128 and SEW = 32
# nreg is 5 instead of 4, thus nelement is 20 instead of 16

################################################################################
# Register assignment
################################################################################

my ($AB, $A, $B, $P, $MU) = ("a0", "a1", "a2", "a3", "a4");

my ($T0, $LOOP, $LOOP2) = ("t0", "t1", "t2"); # happy that it is caller-saved

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
    my $f = shift;
    my $j1 = ($j + 1) % $nreg;
    my $ABVJ = "v@{[$ABVN + $j]}";
    my $ABVJ1 = "v@{[$ABVN + $j1]}";
    $code .= <<___;
    # save carry in TV
    vsrl.vi $TV, $ABVJ, $word
    # mod 2 ** $word
    # TV2 the mask until after j == nreg - 1
    vand.vv $ABVJ, $ABVJ, $TV2
___
    if ($j == $nreg - 1) {
    # carry of AB_s-1 does not add to AB_0
        $code .= <<___;
    # changed TV2 here! re-init TV2 when the loop start again
    vslide1up.vx $TV2, $TV, zero
    vadd.vv $ABVJ1, $ABVJ1, $TV2
___
    } else {
        $code .= <<___;
    vadd.vv $ABVJ1, $ABVJ1, $TV
___
    }
}

sub move {
    $code .= <<___;
    vslide1down.vx $TV2, $ABV, zero
___
# move AB_1 to AB_0, AB_0 (now AB_s in TV2) to AB_s-1
    for (my $k = 0; $k != $nreg - 1; $k++) {
        my $ABVK = "v@{[$ABVN + $k]}";
        my $ABVK1 = "v@{[$ABVN + $k + 1]}";
        $code .= <<___;
    vmv.v.v        $ABVK, $ABVK1
___
    }
    my $ABVF = "v@{[$ABVN + $nreg - 1]}";
    $code .= <<___;
    vmv.v.v        $ABVF, $TV2
___
}

sub propagate_niter {
# propagate carry for nreg*way (bigger than niter) round
# original algorithm propagates for niter round
$code .= <<___;
    # start loop of niter + 1 times
    li  $LOOP2,0
10:
    # mask
    # T0 reused at the end
    # set TV2 for every loop
    li  $T0,@{[2 ** $word - 1]}
    vmv.v.x $TV2,$T0
___
# propagate carry for nreg round
for (my $j = 0; $j != $nreg; $j++) {
    propagate($j);
}
$code .= <<___;
    addi  $LOOP2,$LOOP2,1
    li    $T0,$way
    bne   $LOOP2,$T0,10b
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

    # load values from arg
    vlseg${nreg}e$sew.v $PV, ($P)
    vlseg${nreg}e$sew.v $AV, ($A)
___

    # set ABV to 0
for (my $j = 0; $j != $nreg; $j++) {
    my $ABVJ = "v@{[$ABVN + $j]}";
    $code .= <<___;
    vmv.v.i            $ABVJ, 0
___
}

$code .= <<___;
    # start loop of niter + 1 times
    li  $LOOP,0
1:
    # AB = B_i*A + AB
    # !!!!!! important: lw here assumes SEW = 32
    lw $T0, 0($B)
    addi $B, $B, 4 # advance B by a SEW
___

for (my $j = 0; $j != $nreg; $j++) {
    my $ABVJ = "v@{[$ABVN + $j]}";
    my $AVJ = "v@{[$AVN + $j]}";
    $code .= <<___;
    vmacc.vx $ABVJ, $T0, $AVJ
___
}

## NOT TRUE: propagate carry for nreg round
# nreg round is not enough, should do it for n
#for (my $j = 0; $j != $nreg; $j++) {
#    propagate($j, 0);
#}
# fully propagte
propagate_niter();

# AB = q*P + AB
$code .= <<___;
    vmv.x.s $T0, $ABV
    mul     $T0, $T0, $MU
    # mod 2 ** $word
    # !!!! important: here we assume SEW = 32 and XLEN = 64
    sllw    $T0, $T0, $word
    srlw    $T0, $T0, $word
___
for (my $j = 0; $j != $nreg; $j++) {
    my $ABVJ = "v@{[$ABVN + $j]}";
    my $PVJ = "v@{[$PVN + $j]}";
    $code .= <<___;
    vmacc.vx $ABVJ, $T0, $PVJ
___
    }

## NOT TRUE: propagate carry for nreg round
#for (my $j = 0; $j != $nreg - 1; $j++) {
#    propagate($j, 0);
#}
## propagate final round and move
#propagate($nreg - 1, 1);
propagate_niter();
move();

$code .= <<___;
    addi  $LOOP,$LOOP,1
    li    $T0,@{[$niter + 1]}
    bne   $LOOP,$T0,1b

    vsseg${nreg}e$sew.v $ABV, ($AB)
    ret
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
