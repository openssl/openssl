	.file	"bn_mulw.c"
	.version	"01.01"
gcc2_compiled.:
.text
	.align 16
.globl bn_mul_add_word
	.type	 bn_mul_add_word,@function
bn_mul_add_word:
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %ebx

	/ ax		L(t)
	/ dx		H(t)
	/ bx		a
	/ cx		w
	/ di		r
	/ si		c
	/ bp		num
	xorl %esi,%esi		/ c=0
	movl 20(%esp),%edi	/ r => edi
	movl 24(%esp),%ebx	/ a => exb
	movl 28(%esp),%ebp	/ num => ebp
	movl 32(%esp),%ecx	/ w => ecx

	.align 4
.L110:
	movl %ecx,%eax		/ w => eax
	mull (%ebx)		/ w * *a 
	addl (%edi),%eax	/ L(t)+= *r
	adcl $0,%edx		/ H(t)+= carry
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L111

	movl %ecx,%eax		/ w => eax
	mull 4(%ebx)		/ w * *a 
	addl 4(%edi),%eax	/ L(t)+= *r
	adcl $0,%edx		/ H(t)+= carry
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,4(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L111

	movl %ecx,%eax		/ w => eax
	mull 8(%ebx)		/ w * *a 
	addl 8(%edi),%eax	/ L(t)+= *r
	adcl $0,%edx		/ H(t)+= carry
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,8(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L111

	movl %ecx,%eax		/ w => eax
	mull 12(%ebx)		/ w * *a 
	addl 12(%edi),%eax	/ L(t)+= *r
	adcl $0,%edx		/ H(t)+= carry
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,12(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L111

	addl $16,%ebx		/ a+=4 (4 words)
	addl $16,%edi		/ r+=4 (4 words)

	jmp .L110
	.align 16
.L111:
	movl %esi,%eax		/ return(c)
	popl %ebx
	popl %esi
	popl %edi
	popl %ebp
	ret
.Lfe1:
	.size	 bn_mul_add_word,.Lfe1-bn_mul_add_word
	.align 16
.globl bn_mul_word
	.type	 bn_mul_word,@function
bn_mul_word:
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %ebx

	/ ax		L(t)
	/ dx		H(t)
	/ bx		a
	/ cx		w
	/ di		r
	/ num		bp
	/ si		c
	xorl %esi,%esi		/ c=0
	movl 20(%esp),%edi	/ r => edi
	movl 24(%esp),%ebx	/ a => exb
	movl 28(%esp),%ebp	/ num => ebp
	movl 32(%esp),%ecx	/ w => ecx

	.align 4
.L210:
	movl %ecx,%eax		/ w => eax
	mull (%ebx)		/ w * *a 
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L211

	movl %ecx,%eax		/ w => eax
	mull 4(%ebx)		/ w * *a 
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,4(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L211

	movl %ecx,%eax		/ w => eax
	mull 8(%ebx)		/ w * *a 
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,8(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L211

	movl %ecx,%eax		/ w => eax
	mull 12(%ebx)		/ w * *a 
	addl %esi,%eax		/ L(t)+=c
	adcl $0,%edx		/ H(t)+=carry
	movl %eax,12(%edi)	/ *r=L(t)
	movl %edx,%esi		/ c=H(t)
	decl %ebp		/ --num
	je .L211

	addl $16,%ebx		/ a+=4 (4 words)
	addl $16,%edi		/ r+=4 (4 words)

	jmp .L210
	.align 16
.L211:
	movl %esi,%eax		/ return(c)
	popl %ebx
	popl %esi
	popl %edi
	popl %ebp
	ret
.Lfe2:
	.size	 bn_mul_word,.Lfe2-bn_mul_word

	.align 16
.globl bn_sqr_words
	.type	 bn_sqr_words,@function
bn_sqr_words:
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 16(%esp),%esi	/ r
	movl 20(%esp),%edi	/ a
	movl 24(%esp),%ebx	/ n
	.align 4
.L28:
	movl (%edi),%eax	/ get a
	mull %eax		/ a*a
	movl %eax,(%esi)	/ put low into return addr
	movl %edx,4(%esi)	/ put high into return addr
	decl %ebx		/ n--;
	je .L29

	movl 4(%edi),%eax	/ get a
	mull %eax		/ a*a
	movl %eax,8(%esi)	/ put low into return addr
	movl %edx,12(%esi)	/ put high into return addr
	decl %ebx		/ n--;
	je .L29

	movl 8(%edi),%eax	/ get a
	mull %eax		/ a*a
	movl %eax,16(%esi)	/ put low into return addr
	movl %edx,20(%esi)	/ put high into return addr
	decl %ebx		/ n--;
	je .L29

	movl 12(%edi),%eax	/ get a
	mull %eax		/ a*a
	movl %eax,24(%esi)	/ put low into return addr
	movl %edx,28(%esi)	/ put high into return addr
	decl %ebx		/ n--;
	je .L29

	addl $16,%edi
	addl $32,%esi
	jmp .L28
	.align 16
.L29:
	popl %ebx
	popl %esi
	popl %edi
	ret
.Lfe3:
	.size	 bn_sqr_words,.Lfe3-bn_sqr_words

	.align 16
.globl bn_div64
	.type	 bn_div64,@function
bn_div64:
	movl 4(%esp),%edx	/ a
	movl 8(%esp),%eax	/ b
	divl 12(%esp)		/ ab/c
	ret
.Lfe4:
	.size	 bn_div64,.Lfe4-bn_div64
	.ident	"GCC: (GNU) 2.6.3"
