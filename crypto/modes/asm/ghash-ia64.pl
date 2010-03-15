#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# March 2010
#
# The module implements "4-bit" Galois field multiplication and
# streamed GHASH function. "4-bit" means that it uses 256 bytes
# per-key table [+128 bytes shared table]. Streamed GHASH performance
# was measured to be 6.35 cycles per processed byte on Itanium 2,
# which is >90% better than Microsoft compiler generated code. Well,
# the number should have been ~6.5. The deviation has everything to do
# with the way performance is measured, as difference between GCM and
# straightforward 128-bit counter mode. To anchor to something else
# sha1-ia64.pl module processes one byte in 6.0 cycles. On Itanium
# GHASH should run at ~8.5 cycles per byte.

$output=shift and (open STDOUT,">$output" or die "can't open $output: $!");

if ($^O eq "hpux") {
    $ADDP="addp4";
    for (@ARGV) { $ADDP="add" if (/[\+DD|\-mlp]64/); }
} else { $ADDP="add"; }
for (@ARGV)  {  $big_endian=1 if (/\-DB_ENDIAN/);
                $big_endian=0 if (/\-DL_ENDIAN/);  }
if (!defined($big_endian))
             {  $big_endian=(unpack('L',pack('N',1))==1);  }

sub loop() {
my $label=shift;
my ($p16,$p17)=(shift)?("p63","p63"):("p16","p17"); # mask references to inp

# Loop is scheduled for 6 ticks on Itanium 2 and 8 on Itanium, i.e.
# in scalable manner;-) Naturally assuming data in L1 cache...
# Special note about 'dep' instruction, which is used to construct
# &rem_4bit[Zlo&0xf]. It works, because rem_4bit is aligned at 128
# bytes boundary and lower 7 bits of its address are guaranteed to
# be zero.
$code.=<<___;
$label:
{ .mfi;	(p18)	ld8	Hlo=[Hi[1]],-8
	(p19)	dep	rem=Zlo,rem_4bitp,3,4	}
{ .mfi;	(p19)	xor	Zhi=Zhi,Hhi
	($p17)	xor	xi[1]=xi[1],in[1]	};;
{ .mfi;	(p18)	ld8	Hhi=[Hi[1]]
	(p19)	shrp	Zlo=Zhi,Zlo,4		}
{ .mfi;	(p19)	ld8	rem=[rem]
	(p18)	and	Hi[1]=mask0xf0,xi[2]	};;
{ .mmi;	($p16)	ld1	in[0]=[inp],-1
	(p18)	xor	Zlo=Zlo,Hlo
	(p19)	shr.u	Zhi=Zhi,4		}
{ .mib;	(p19)	xor	Hhi=Hhi,rem
	(p18)	add	Hi[1]=Htbl,Hi[1]	};;

{ .mfi;	(p18)	ld8	Hlo=[Hi[1]],-8
	(p18)	dep	rem=Zlo,rem_4bitp,3,4	}
{ .mfi;	(p17)	shladd	Hi[0]=xi[1],4,r0
	(p18)	xor	Zhi=Zhi,Hhi		};;
{ .mfi;	(p18)	ld8	Hhi=[Hi[1]]
	(p18)	shrp	Zlo=Zhi,Zlo,4		}
{ .mfi;	(p18)	ld8	rem=[rem]
	(p17)	and	Hi[0]=mask0xf0,Hi[0]	};;
{ .mmi;	(p16)	ld1	xi[0]=[Xi],-1
	(p18)	xor	Zlo=Zlo,Hlo
	(p18)	shr.u	Zhi=Zhi,4		}
{ .mib;	(p18)	xor	Hhi=Hhi,rem
	(p17)	add	Hi[0]=Htbl,Hi[0]
	br.ctop.sptk	$label			};;
___
}

$code=<<___;
.explicit
.text

prevfs=r2;	prevlc=r3;	prevpr=r8;
mask0xf0=r21;
rem=r22;	rem_4bitp=r23;
Xi=r24;		Htbl=r25;
inp=r26;	end=r27;
Hhi=r28;	Hlo=r29;
Zhi=r30;	Zlo=r31;

.global	gcm_gmult_4bit#
.proc	gcm_gmult_4bit#
.align	128
.skip	16;;					// aligns loop body
gcm_gmult_4bit:
	.prologue
{ .mmi;	.save	ar.pfs,prevfs
	alloc	prevfs=ar.pfs,2,6,0,8
	$ADDP	Xi=15,in0			// &Xi[15]
	mov	rem_4bitp=ip		}
{ .mii;	$ADDP	Htbl=8,in1			// &Htbl[0].lo
	.save	ar.lc,prevlc
	mov	prevlc=ar.lc
	.save	pr,prevpr
	mov	prevpr=pr		};;

	.body
	.rotr	in[3],xi[3],Hi[2]

{ .mib;	ld1	xi[2]=[Xi],-1			// Xi[15]
	mov	mask0xf0=0xf0
	brp.loop.imp	.Loop1,.Lend1-16};;
{ .mmi;	ld1	xi[1]=[Xi],-1			// Xi[14]
					};;
{ .mii;	shladd	Hi[1]=xi[2],4,r0
	mov	pr.rot=0x7<<16
	mov	ar.lc=13		};;
{ .mii;	and	Hi[1]=mask0xf0,Hi[1]
	mov	ar.ec=3
	xor	Zlo=Zlo,Zlo		};;
{ .mii;	add	Hi[1]=Htbl,Hi[1]		// &Htbl[nlo].lo
	add	rem_4bitp=rem_4bit#-gcm_gmult_4bit#,rem_4bitp
	xor	Zhi=Zhi,Zhi		};;
___
	&loop	(".Loop1",1);
$code.=<<___;
.Lend1:
{ .mib;	xor	Zhi=Zhi,Hhi		};;	// modulo-scheduling artefact
{ .mib;	mux1	Zlo=Zlo,\@rev		};;
{ .mib;	mux1	Zhi=Zhi,\@rev		};;
{ .mmi;	add	Hlo=9,Xi;;			// ;; is here to prevent
	add	Hhi=1,Xi		};;	// pipeline flush on Itanium
{ .mib;	st8	[Hlo]=Zlo
	mov	pr=prevpr,-2		};;
{ .mib;	st8	[Hhi]=Zhi
	mov	ar.lc=prevlc
	br.ret.sptk.many	b0	};;
.endp	gcm_gmult_4bit#

.global	gcm_ghash_4bit#
.proc	gcm_ghash_4bit#
.align	32;;
gcm_ghash_4bit:
	.prologue
{ .mmi;	.save	ar.pfs,prevfs
	alloc	prevfs=ar.pfs,4,4,0,8
	$ADDP	inp=15,in0			// &inp[15]
	mov	rem_4bitp=ip		}
{ .mmi;	$ADDP	end=in1,in0			// &inp[len]
	$ADDP	Xi=15,in2			// &Xi[15]
	.save	ar.lc,prevlc
	mov	prevlc=ar.lc		};;
{ .mmi;	$ADDP	Htbl=8,in3			// &Htbl[0].lo
	mov	mask0xf0=0xf0
	.save	pr,prevpr
	mov	prevpr=pr		}

	.body
	.rotr	in[3],xi[3],Hi[2]

{ .mmi;	ld1	in[2]=[inp],-1			// inp[15]
	ld1	xi[2]=[Xi],-1			// Xi[15]
	add	end=-17,end		};;
{ .mmi;	ld1	in[1]=[inp],-1			// inp[14]
	ld1	xi[1]=[Xi],-1			// Xi[14]
	xor	xi[2]=xi[2],in[2]	};;
{ .mii;	shladd	Hi[1]=xi[2],4,r0
	mov	pr.rot=0x7<<16
	mov	ar.lc=13		};;
{ .mii;	and	Hi[1]=mask0xf0,Hi[1]
	mov	ar.ec=3
	xor	Zlo=Zlo,Zlo		};;
{ .mii;	add	Hi[1]=Htbl,Hi[1]		// &Htbl[nlo].lo
	add	rem_4bitp=rem_4bit#-gcm_ghash_4bit#,rem_4bitp
	xor	Zhi=Zhi,Zhi		};;
___
	&loop	(".LoopN");
$code.=<<___;
{ .mib;	xor	Zhi=Zhi,Hhi			// modulo-scheduling artefact
	extr.u	xi[2]=Zlo,0,8		}	// Xi[15]
{ .mib;	cmp.ltu	p6,p0=inp,end			// are we done?
	add	inp=32,inp			// advance inp
	clrrrb.pr			};;
{ .mii;
(p6)	ld1	in[2]=[inp],-1			// inp[15]
(p6)	extr.u	xi[1]=Zlo,8,8			// Xi[14]
(p6)	mov	ar.lc=13		};;
{ .mii;
(p6)	ld1	in[1]=[inp],-1			// inp[14]
(p6)	mov	ar.ec=3
	mux1	Zlo=Zlo,\@rev		};;
{ .mii;
(p6)	xor	xi[2]=xi[2],in[2]
	mux1	Zhi=Zhi,\@rev		};;
{ .mii;
(p6)	shladd	Hi[1]=xi[2],4,r0
	add	Hlo=9,Xi			// Xi is &Xi[-1]
	add	Hhi=1,Xi		};;
{ .mii;
(p6)	and	Hi[1]=mask0xf0,Hi[1]
(p6)	add	Xi=14,Xi			// &Xi[13]
(p6)	mov	pr.rot=0x7<<16		};;

{ .mii; st8	[Hlo]=Zlo
(p6)	xor	Zlo=Zlo,Zlo
(p6)	add	Hi[1]=Htbl,Hi[1]	};;
{ .mib;	st8	[Hhi]=Zhi
(p6)	xor	Zhi=Zhi,Zhi
(p6)	br.cond.dptk.many	.LoopN	};;

{ .mib;	mov	pr=prevpr,-2		}
{ .mib;	mov	ar.lc=prevlc
	br.ret.sptk.many	b0	};;
.endp	gcm_ghash_4bit#

.align	128;;
.type	rem_4bit#,\@object
rem_4bit:
        data8	0x0000<<48, 0x1C20<<48, 0x3840<<48, 0x2460<<48
        data8	0x7080<<48, 0x6CA0<<48, 0x48C0<<48, 0x54E0<<48
        data8	0xE100<<48, 0xFD20<<48, 0xD940<<48, 0xC560<<48
        data8	0x9180<<48, 0x8DA0<<48, 0xA9C0<<48, 0xB5E0<<48
.size	rem_4bit#,128
stringz	"GHASH for IA64, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/mux1(\s+)\S+\@rev/nop.i$1 0x0/gm      if ($big_endian);

print $code;
close STDOUT;
