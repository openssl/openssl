	.file	"bn_mulw.c"
gcc2_compiled.:
.section	".text"
	.align 4
	.global bn_mul_add_word
	.type	 bn_mul_add_word,#function
	.proc	016
bn_mul_add_word:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%o0
	mov %i1,%o2
	mov %i2,%g1
	mov %i3,%o1
	mov 0,%i4
	add %o0,12,%g4
	add %o2,12,%o7
.LL2:
	mov %i4,%i3
	mov 0,%i2
	ld [%o0],%g2
	mov %g2,%i1
	ld [%o2],%g2
	mov 0,%i0
	umul %o1,%g2,%g3
	rd %y,%g2
	addcc %g3,%i1,%g3
	addx %g2,%i0,%g2
	addcc %g3,%i3,%g3
	addx %g2,%i2,%g2
	st %g3,[%o0]
	mov %g2,%i5
	mov 0,%i4
	addcc %g1,-1,%g1
	be .LL3
	mov %i5,%i4
	mov %i4,%i3
	mov 0,%i2
	ld [%g4-8],%g2
	mov %g2,%i1
	ld [%o7-8],%g2
	mov 0,%i0
	umul %o1,%g2,%g3
	rd %y,%g2
	addcc %g3,%i1,%g3
	addx %g2,%i0,%g2
	addcc %g3,%i3,%g3
	addx %g2,%i2,%g2
	st %g3,[%g4-8]
	mov %g2,%i5
	mov 0,%i4
	addcc %g1,-1,%g1
	be .LL3
	mov %i5,%i4
	mov %i4,%i3
	mov 0,%i2
	ld [%g4-4],%g2
	mov %g2,%i1
	ld [%o7-4],%g2
	mov 0,%i0
	umul %o1,%g2,%g3
	rd %y,%g2
	addcc %g3,%i1,%g3
	addx %g2,%i0,%g2
	addcc %g3,%i3,%g3
	addx %g2,%i2,%g2
	st %g3,[%g4-4]
	mov %g2,%i5
	mov 0,%i4
	addcc %g1,-1,%g1
	be .LL3
	mov %i5,%i4
	mov %i4,%i3
	mov 0,%i2
	ld [%g4],%g2
	mov %g2,%i1
	ld [%o7],%g2
	mov 0,%i0
	umul %o1,%g2,%g3
	rd %y,%g2
	addcc %g3,%i1,%g3
	addx %g2,%i0,%g2
	addcc %g3,%i3,%g3
	addx %g2,%i2,%g2
	st %g3,[%g4]
	mov %g2,%i5
	mov 0,%i4
	addcc %g1,-1,%g1
	be .LL3
	mov %i5,%i4
	add %o7,16,%o7
	add %o2,16,%o2
	add %g4,16,%g4
	b .LL2
	add %o0,16,%o0
.LL3:
	ret
	restore %g0,%i4,%o0
.LLfe1:
	.size	 bn_mul_add_word,.LLfe1-bn_mul_add_word
	.align 4
	.global bn_mul_word
	.type	 bn_mul_word,#function
	.proc	016
bn_mul_word:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%o7
	mov %i1,%o0
	mov %i2,%i4
	mov %i3,%g4
	mov 0,%i0
	add %o7,12,%g1
	add %o0,12,%i5
.LL18:
	mov %i0,%g3
	mov 0,%g2
	ld [%o0],%i2
	umul %g4,%i2,%i3
	rd %y,%i2
	addcc %i3,%g3,%i3
	addx %i2,%g2,%i2
	st %i3,[%o7]
	mov %i2,%i1
	mov 0,%i0
	addcc %i4,-1,%i4
	be .LL19
	mov %i1,%i0
	mov %i0,%g3
	mov 0,%g2
	ld [%i5-8],%i2
	umul %g4,%i2,%i3
	rd %y,%i2
	addcc %i3,%g3,%i3
	addx %i2,%g2,%i2
	st %i3,[%g1-8]
	mov %i2,%i1
	mov 0,%i0
	addcc %i4,-1,%i4
	be .LL19
	mov %i1,%i0
	mov %i0,%g3
	mov 0,%g2
	ld [%i5-4],%i2
	umul %g4,%i2,%i3
	rd %y,%i2
	addcc %i3,%g3,%i3
	addx %i2,%g2,%i2
	st %i3,[%g1-4]
	mov %i2,%i1
	mov 0,%i0
	addcc %i4,-1,%i4
	be .LL19
	mov %i1,%i0
	mov %i0,%g3
	mov 0,%g2
	ld [%i5],%i2
	umul %g4,%i2,%i3
	rd %y,%i2
	addcc %i3,%g3,%i3
	addx %i2,%g2,%i2
	st %i3,[%g1]
	mov %i2,%i1
	mov 0,%i0
	addcc %i4,-1,%i4
	be .LL19
	mov %i1,%i0
	add %i5,16,%i5
	add %o0,16,%o0
	add %g1,16,%g1
	b .LL18
	add %o7,16,%o7
.LL19:
	ret
	restore
.LLfe2:
	.size	 bn_mul_word,.LLfe2-bn_mul_word
	.align 4
	.global bn_sqr_words
	.type	 bn_sqr_words,#function
	.proc	020
bn_sqr_words:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov %o0,%g4
	add %g4,28,%o3
	add %o1,12,%g1
.LL34:
	ld [%o1],%o0
	addcc %o2,-1,%o2
	umul %o0,%o0,%o5
	rd %y,%o4
	st %o5,[%g4]
	mov %o4,%g3
	mov 0,%g2
	be .LL35
	st %g3,[%o3-24]
	ld [%g1-8],%o0
	addcc %o2,-1,%o2
	umul %o0,%o0,%o5
	rd %y,%o4
	st %o5,[%o3-20]
	mov %o4,%g3
	mov 0,%g2
	be .LL35
	st %g3,[%o3-16]
	ld [%g1-4],%o0
	addcc %o2,-1,%o2
	umul %o0,%o0,%o5
	rd %y,%o4
	st %o5,[%o3-12]
	mov %o4,%g3
	mov 0,%g2
	be .LL35
	st %g3,[%o3-8]
	ld [%g1],%o0
	addcc %o2,-1,%o2
	umul %o0,%o0,%o5
	rd %y,%o4
	st %o5,[%o3-4]
	mov %o4,%g3
	mov 0,%g2
	be .LL35
	st %g3,[%o3]
	add %g1,16,%g1
	add %o1,16,%o1
	add %o3,32,%o3
	b .LL34
	add %g4,32,%g4
.LL35:
	retl
	nop
.LLfe3:
	.size	 bn_sqr_words,.LLfe3-bn_sqr_words
.section	".rodata"
	.align 8
.LLC0:
	.asciz	"Division would overflow\n"
.section	".text"
	.align 4
	.global bn_div64
	.type	 bn_div64,#function
	.proc	016
bn_div64:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov 0,%l1
	cmp %i2,0
	bne .LL42
	mov 2,%l0
	b .LL59
	mov -1,%i0
.LL42:
	call BN_num_bits_word,0
	mov %i2,%o0
	mov %o0,%o2
	cmp %o2,32
	be .LL43
	mov 1,%o0
	sll %o0,%o2,%o0
	cmp %i0,%o0
	bleu .LL60
	mov 32,%o0
	sethi %hi(__iob+32),%o0
	or %o0,%lo(__iob+32),%o0
	sethi %hi(.LLC0),%o1
	call fprintf,0
	or %o1,%lo(.LLC0),%o1
	call abort,0
	nop
.LL43:
	mov 32,%o0
.LL60:
	cmp %i0,%i2
	blu .LL44
	sub %o0,%o2,%o2
	sub %i0,%i2,%i0
.LL44:
	cmp %o2,0
	be .LL45
	sethi %hi(-65536),%o7
	sll %i2,%o2,%i2
	sll %i0,%o2,%o1
	sub %o0,%o2,%o0
	srl %i1,%o0,%o0
	or %o1,%o0,%i0
	sll %i1,%o2,%i1
.LL45:
	srl %i2,16,%g2
	sethi %hi(65535),%o0
	or %o0,%lo(65535),%o1
	and %i2,%o1,%g3
	mov %o0,%g4
	mov %o1,%g1
.LL46:
	srl %i0,16,%o0
	cmp %o0,%g2
	be .LL50
	or %g4,%lo(65535),%o3
	wr %g0,%g0,%y
	nop
	nop
	nop
	udiv %i0,%g2,%o3
.LL50:
	and %i1,%o7,%o0
	srl %o0,16,%o5
	smul %o3,%g3,%o4
	smul %o3,%g2,%o2
.LL51:
	sub %i0,%o2,%o1
	andcc %o1,%o7,%g0
	bne .LL52
	sll %o1,16,%o0
	add %o0,%o5,%o0
	cmp %o4,%o0
	bleu .LL52
	sub %o4,%g3,%o4
	sub %o2,%g2,%o2
	b .LL51
	add %o3,-1,%o3
.LL52:
	smul %o3,%g2,%o2
	smul %o3,%g3,%o0
	srl %o0,16,%o1
	sll %o0,16,%o0
	and %o0,%o7,%o0
	cmp %i1,%o0
	bgeu .LL56
	add %o2,%o1,%o2
	add %o2,1,%o2
.LL56:
	cmp %i0,%o2
	bgeu .LL57
	sub %i1,%o0,%i1
	add %i0,%i2,%i0
	add %o3,-1,%o3
.LL57:
	addcc %l0,-1,%l0
	be .LL47
	sub %i0,%o2,%i0
	sll %o3,16,%l1
	sll %i0,16,%o0
	srl %i1,16,%o1
	or %o0,%o1,%i0
	and %i1,%g1,%o0
	b .LL46
	sll %o0,16,%i1
.LL47:
	or %l1,%o3,%i0
.LL59:
	ret
	restore
.LLfe4:
	.size	 bn_div64,.LLfe4-bn_div64
	.ident	"GCC: (GNU) 2.7.0"
