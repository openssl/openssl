#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

################################################################################
# Utility functions to help with keeping track of which registers to stack/
# unstack when entering / exiting routines.
################################################################################
{
    # Callee-saved registers
    my @callee_saved = map("x$_",(2,8,9,18..27)); 
    # Caller-saved registers
    my @caller_saved = map("x$_",(1,5..7,10..17,28..31));
    my @must_save; 
    sub use_reg {
        my $reg = shift;
        if (grep(/^$reg$/, @callee_saved)) {
            push(@must_save, $reg);
        } elsif (!grep(/^$reg$/, @caller_saved)) {
            # Register is not usable!
            die("Unusable register ".$reg);
        }
        return $reg;
    }
    sub use_regs {
        return map(use_reg("x$_"), @_);
    }
    sub save_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * 8; 
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) { 
            $stack_reservation += 8;
        }
        $ret.="    addi    sp,sp,-$stack_reservation\n";
        foreach (@must_save) {
            $stack_offset -= 8;
            $ret.="    sd      $_,$stack_offset(sp)\n";
        }
	    return $ret;
    }
    sub load_regs {
        my $ret = '';
        my $stack_reservation = ($#must_save + 1) * 8;
        my $stack_offset = $stack_reservation;
        if ($stack_reservation % 16) {
            $stack_reservation += 8;
        }
        foreach (@must_save) {
            $stack_offset -= 8;
            $ret.="    ld      $_,$stack_offset(sp)\n";
        }
	    $ret.="    addi    sp,sp,$stack_reservation\n";
        return $ret;
    }
    sub clear_regs {
        @must_save = ();
    }
}

################################################################################
# Register assignment
################################################################################

# Function arguments 
#      RISC-V    ABI
# $rp	x10	     a0  # BN_ULONG *rp
# $ap	x11	     a1  # const BN_ULONG *ap
# $bp	x12	     a2  # const BN_ULONG *bp
# $np	x13	     a3  # const BN_ULONG *np
# $n0	x14      a4  # const BN_ULONG *n0
# $num	x15      a5  # int num
my ($rp,$ap,$bp,$np,$n0,$num) = use_regs(10, 11, 12, 13, 14, 15);

# Return address and Frame pointer
#      RISC-V    ABI
# $ra   x1       ra
# $fp   x8       s0
my ($ra,$fp) = use_regs(1,8); 

# Temporary variable allocation
#      RISC-V    ABI
# $lo0	x5	     t0
# $hi0	x6	     t1  
# $aj	x7	     t2
# $m0	x28	     t3
# $alo	x29	     t4
# $ahi	x30      t5
# $lo1	x31	     t6
# $hi1	x18	     s2
# $nj	x19	     s3
# $m1	x20	     s4
# $nlo	x21	     s5
# $nhi	x22	     s6
# $ovf	x23	     s7 
# $i	x24	     s8
# $j	x25	     s9
# $tp	x26	     s10
# $tj	x27	     s11
# $temp x9       s1
my ($lo0, $hi0, $aj, $m0, $alo, $ahi,$lo1, $hi1, $nj, $m1, $nlo, $nhi, $ovf, $i, $j, $tp, $tj, $temp) = use_regs(5..7, 28..31, 18..27, 9);

# Carry variable
# $carry1 x16      a6
# $carry2 x17      a7
my ($carry1,$carry2) = use_regs(16,17); 

my $code .= <<___;
.text
.balign 32
.globl bn_mul_mont
.type   bn_mul_mont,\@function
bn_mul_mont:
___

$code .= save_regs();

$code .= <<___;

    mv s0, sp
___

$code .= <<___;

.Lmul_mont:		
    ld      $m0, 0($bp)         
    addi    $bp, $bp, 8         
    slli    $temp, $num, 3         
    sub     $tp, sp, $temp         
    ld      $hi0, 0($ap)        
    ld      $aj, 8($ap)         
    addi    $ap, $ap, 16        
    slli    $num, $num, 3       
    ld      $n0, 0($n0)           
    andi    $tp, $tp, -16       
    ld      $hi1, 0($np)        
    ld      $nj, 8($np)         
    addi    $np, $np, 16        

    mul     $lo0, $hi0, $m0         
    addi    $j, $num, -16        
    mulhu   $hi0, $hi0, $m0      
    mul     $alo, $aj, $m0      
    mulhu   $ahi, $aj, $m0       

    mul     $m1, $lo0, $n0        
    mv      sp, $tp               

    mulhu   $hi1, $hi1, $m1       
    mul     $nlo, $nj, $m1        

    snez    $carry1,$lo0
    mulhu   $nhi, $nj, $m1       
    add     $hi1, $hi1, $carry1      
    beqz    $j, .L1st_skip            
.L1st:
    ld      $aj, 0($ap)          
    addi    $ap, $ap, 8          
    add $lo0, $alo, $hi0             
    sltu $carry1,$lo0,$alo    
    addi    $j, $j, -8           
    add     $hi0,$ahi,$carry1        
    
    ld      $nj, 0($np)          
    addi    $np, $np, 8          
    add $lo1, $nlo, $hi1        
    sltu $carry1,$lo1,$nlo   
    mul $alo, $aj, $m0       
    add $hi1, $nhi, $carry1      
    mulhu $ahi, $aj, $m0    
    

    add $temp, $lo1, $lo0      
    sltu $carry1,$temp,$lo1  
    mv $lo1, $temp             
     
    mul $nlo,$nj,$m1    
    add $hi1, $hi1, $carry1 
    mulhu $nhi, $nj, $m1        
    sd $lo1, 0($tp)                   
    addi    $tp, $tp, 8             
    bnez    $j, .L1st           

.L1st_skip:
    add     $lo0,$alo,$hi0        
    sltu    $carry1, $lo0, $alo      
    sub     $ap,$ap,$num        
    add     $hi0,$ahi,$carry1       

    add     $lo1,$nlo,$hi1        
    sltu    $carry1, $lo1,$nlo       
    sub     $np,$np,$num         
    add     $hi1,$nhi,$carry1       
    
    add     $lo1, $lo1,$lo0                
    sltu    $carry1, $lo1, $lo0         
    addi    $i,$num, -8         

    add   $temp, $hi1, $hi0    
    sltu  $carry2, $temp, $hi1      
    add   $hi1, $temp, $carry1   
    sltu  $ovf, $hi1, $temp      
    or    $carry1,$carry2,$ovf   
    
    mv   $ovf, $carry1

    sd      $lo1, 0($tp)          
    sd      $hi1, 8($tp)         

.Louter:
    ld      $m0, 0($bp)          
    addi    $bp, $bp, 8          
    ld      $hi0, 0($ap)         
    ld      $aj, 8($ap)          
    addi    $ap, $ap, 16         
    ld      $tj, 0(sp)          
    addi    $tp, sp, 8         
    
    mul     $lo0,$hi0,$m0         
    addi    $j,$num,-16        

    mulhu   $hi0,$hi0,$m0       
    ld      $hi1, 0($np)        
    ld      $nj, 8($np)          
    addi    $np, $np, 16        
    mul  $alo,$aj,$m0         
    add     $lo0,$lo0,$tj         
    sltu    $carry1, $lo0,$tj    
    mulhu   $ahi, $aj, $m0        
    add     $hi0, $hi0, $carry1     
    
    mul     $m1,$lo0, $n0        
    addi    $i, $i, -8         
    
 
    mulhu   $hi1, $hi1, $m1         
    mul     $nlo,$nj,$m1        
    
    snez $carry1, $lo0    
    mulhu   $nhi,$nj,$m1         
    beqz    $j, .Linner_skip  

.Linner:
    ld      $aj, 0($ap)         
    addi    $ap, $ap, 8          
    add     $hi1, $hi1, $carry1      

    ld      $tj, 0($tp)         
    addi    $tp, $tp, 8          
    add     $lo0, $alo, $hi0        
    sltu    $carry1, $lo0, $alo        
    addi    $j, $j, -8         

    add     $hi0, $ahi, $carry1       
    
    add     $lo1, $nlo,$hi1      
    sltu    $carry1, $lo1, $nlo       

    ld      $nj, 0($np)          
    addi    $np, $np, 8         

    add     $hi1,$nhi,$carry1       
    
    mul     $alo, $aj, $m0        

    add     $lo0, $lo0, $tj      
    sltu    $carry1, $lo0, $tj       

    mulhu   $ahi, $aj,$m0      

    add     $hi0, $hi0, $carry1       
    
    mul $nlo,$nj,$m1     

    add     $lo1, $lo1, $lo0        
    sltu    $carry1, $lo1, $lo0       

    mulhu   $nhi,$nj,$m1       
    sd      $lo1, -16($tp)    
    bnez    $j, .Linner       

.Linner_skip:
    ld      $tj, 0($tp)         
    addi    $tp, $tp, 8          

    add     $hi1, $hi1, $carry1       
 
    add  $lo0, $alo, $hi0    
    sltu $carry1, $lo0, $alo  

    sub     $ap,$ap,$num  
    add     $hi0,$ahi,$carry1
      
    add     $lo1,$nlo,$hi1
    sltu    $carry1, $lo1, $nlo

    sub	$np,$np,$num    

    add     $temp, $nhi, $ovf
    sltu    $carry2, $temp, $nhi       
    add     $hi1, $temp, $carry1       
    sltu    $ovf, $hi1, $temp         
    or      $carry1, $carry2, $ovf
           
    mv      $ovf, $carry1  

    add     $lo0,$lo0,$tj
    sltu    $carry1, $lo0, $tj
    add     $hi0, $hi0, $carry1  

    add     $lo1,$lo1,$lo0
    sltu    $carry1, $lo1,$lo0

    add     $temp, $hi1, $hi0  
    sltu    $carry2, $temp, $hi1
    add     $hi1, $temp, $carry1
    sltu    $carry1, $hi1, $temp
    or      $carry1, $carry2, $carry1

    add     $ovf,$ovf,$carry1

    sd      $lo1, -16($tp) 
    sd      $hi1, -8($tp)

    bnez    $i, .Louter

    ld  $tj,0(sp)

    addi    $tp, sp, 8

    ld      $nj, 0($np)
    addi    $np, $np, 8

    addi $j,$num,-8
    sltu $carry1,$num,8
    xori $carry1,$carry1,1 

    mv      $ap,$rp
.Lsub:
    xori $carry1,$carry1,1 
    sub $temp,$tj,$nj
    sltu $carry2,$tj,$temp 
    sub $aj,$temp,$carry1 
    sltu $carry1,$temp,$aj 
    or $carry1,$carry2,$carry1 
    xori $carry1,$carry1,1 

    ld      $tj, 0($tp)          
    addi    s10, s10, 8

    addi    $j,$j,-8

    ld      $nj, 0($np)
    addi    $np, $np, 8

    sd      $aj, 0($ap)
    addi    $ap, $ap, 8

    bnez    $j, .Lsub

    xori $carry1,$carry1,1
    sub $temp,$tj,$nj
    sltu $carry2,$tj,$temp
    sub $aj,$temp,$carry1
    sltu $carry1,$temp,$aj
    or $carry1,$carry2,$carry1
    xori $carry1,$carry1,1
    
    xori $carry1,$carry1,1
    sub $temp,$ovf,zero
    sltu $carry2,$ovf,$temp
    sub $ovf,$temp,$carry1
    sltu $carry1,$temp,$ovf
    or $carry1,$carry2,$carry1
    xori $carry1,$carry1,1

    sd      $aj, 0($ap)
    addi    $ap, $ap, 8
    ld      $tj, 0(sp)
    addi    $tp, sp, 8
    ld      $aj, 0($rp)
    addi    $rp, $rp, 8
    addi    $num,$num,-8
    nop
.Lcond_copy:
    addi    $num,$num, -8         
    bnez $carry1,.set_aj1 
    mv   $nj,$tj
    j    .end1
.set_aj1:
    mv   $nj,$aj         
.end1:
    ld      $tj, 0($tp)
    addi    $tp, $tp, 8
    ld      $aj, 0($rp)
    addi    $rp, $rp, 8
    sd      zero, -16($tp)
    sd      $nj, -16($rp) 
    bnez    $num, .Lcond_copy

    bnez $carry1,.set_aj2 
    mv   $nj,$tj          
    j    .end2
.set_aj2:
    mv   $nj,$aj        
.end2:
    sd      zero, -8($tp)
    sd      $nj, -8($rp)
___

$code .= <<___;

    mv sp,s0
    li a0,1
___


$code .= load_regs();

$code .= <<___;
    ret
.size	bn_mul_mont,.-bn_mul_mont
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
