	.file	"bn_mulw.c"
	.version	"01.01"
gcc2_compiled.:
.text
	.align 4
.globl _bn_mul_add_word
_bn_mul_add_word:
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %ebx

	# ax		L(t)
	# dx		H(t)
	# bx		a
	# cx		w
	# di		r
	# si		c
	# bp		num
	xorl %esi,%esi		# c=0
	movl 20(%esp),%edi	# r => edi
	movl 24(%esp),%ebx	# a => exb
	movl 32(%esp),%ecx	# w => ecx
	movl 28(%esp),%ebp	# num => ebp

	shrl $2,%ebp		# num/4
	je .L910

#	.align 4
.L110:
	# Round 1
	movl %ecx,%eax		# w => eax
	mull (%ebx)		# w * *a 
	addl (%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+= carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)

	# Round 2
	movl %ecx,%eax		# w => eax
	mull 4(%ebx)		# w * *a 
	addl 4(%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+= carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,4(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)

	# Round 3
	movl %ecx,%eax		# w => eax
	mull 8(%ebx)		# w * *a 
	addl 8(%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+=carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,8(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)

	# Round 4
	movl %ecx,%eax		# w => eax
	mull 12(%ebx)		# w * *a 
	addl 12(%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+=carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,12(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)

	addl $16,%ebx		# a+=4 (4 words)
	addl $16,%edi		# r+=4 (4 words)

	decl %ebp		# --num
	je .L910
	jmp .L110
#	.align 4
.L910:
	movl 28(%esp),%ebp	# num => ebp
	andl $3,%ebp
	je .L111

	# Round 1
	movl %ecx,%eax		# w => eax
	mull (%ebx)		# w * *a 
	addl (%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+=carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L111

	# Round 2
	movl %ecx,%eax		# w => eax
	mull 4(%ebx)		# w * *a 
	addl 4(%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+=carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,4(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L111

	# Round 3
	movl %ecx,%eax		# w => eax
	mull 8(%ebx)		# w * *a 
	addl 8(%edi),%eax	# *r+=L(t)
	adcl $0,%edx		# H(t)+=carry
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,8(%edi)	# *r+=L(t)
	movl %edx,%esi		# c=H(t)

#	.align 4
.L111:
	movl %esi,%eax		# return(c)
	popl %ebx
	popl %esi
	popl %edi
	popl %ebp
	ret
.Lfe1:
	.align 4
.globl _bn_mul_word
_bn_mul_word:
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %ebx

	# ax		L(t)
	# dx		H(t)
	# bx		a
	# cx		w
	# di		r
	# num		bp
	# si		c
	xorl %esi,%esi		# c=0
	movl 20(%esp),%edi	# r => edi
	movl 24(%esp),%ebx	# a => exb
	movl 28(%esp),%ebp	# num => bp
	movl 32(%esp),%ecx	# w => ecx

#	.align 4
.L210:
	movl %ecx,%eax		# w => eax
	mull (%ebx)		# w * *a 
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,(%edi)	# *r=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L211

	movl %ecx,%eax		# w => eax
	mull 4(%ebx)		# w * *a 
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,4(%edi)	# *r=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L211

	movl %ecx,%eax		# w => eax
	mull 8(%ebx)		# w * *a 
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,8(%edi)	# *r=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L211

	movl %ecx,%eax		# w => eax
	mull 12(%ebx)		# w * *a 
	addl %esi,%eax		# L(t)+=c
	adcl $0,%edx		# H(t)+=carry
	movl %eax,12(%edi)	# *r=L(t)
	movl %edx,%esi		# c=H(t)
	decl %ebp		# --num
	je .L211

	addl $16,%ebx		# a+=4 (4 words)
	addl $16,%edi		# r+=4 (4 words)

	jmp .L210
#	.align 4
.L211:
	movl %esi,%eax		# return(c)
	popl %ebx
	popl %esi
	popl %edi
	popl %ebp
	ret
.Lfe2:
	.align 4
.globl _bn_sqr_words
_bn_sqr_words:
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 16(%esp),%esi	# r
	movl 20(%esp),%edi	# a
	movl 24(%esp),%ebx	# n
#	.align 4
	shrl $2,%ebx
	jz .L99
.L28:
	movl (%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,(%esi)	# put low into return addr
	movl %edx,4(%esi)	# put high into return addr

	movl 4(%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,8(%esi)	# put low into return addr
	movl %edx,12(%esi)	# put high into return addr

	movl 8(%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,16(%esi)	# put low into return addr
	movl %edx,20(%esi)	# put high into return addr

	movl 12(%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,24(%esi)	# put low into return addr
	movl %edx,28(%esi)	# put high into return addr

	addl $16,%edi
	addl $32,%esi
	decl %ebx		# n-=4;
	jz .L99
	jmp .L28
#	.align 4
.L99:
	movl 24(%esp),%ebx	# n
	andl $3,%ebx
	jz .L29
	movl (%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,(%esi)	# put low into return addr
	movl %edx,4(%esi)	# put high into return addr
	decl %ebx		# n--;
	jz .L29
	movl 4(%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,8(%esi)	# put low into return addr
	movl %edx,12(%esi)	# put high into return addr
	decl %ebx		# n--;
	jz .L29
	movl 8(%edi),%eax	# get a
	mull %eax		# a*a
	movl %eax,16(%esi)	# put low into return addr
	movl %edx,20(%esi)	# put high into return addr

.L29:
	popl %ebx
	popl %esi
	popl %edi
	ret
.Lfe3:
	.align 4
.globl _bn_div64
_bn_div64:
	movl 4(%esp),%edx	# a
	movl 8(%esp),%eax	# b
	divl 12(%esp)		# ab/c
	ret
.Lfe4:
	.ident	"GCC: (GNU) 2.6.3"
