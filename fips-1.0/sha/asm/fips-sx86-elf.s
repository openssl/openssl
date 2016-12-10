





	.file	"sha1-586.s"
	.version	"01.01"
gcc2_compiled.:
.text
	.align 16
.globl sha1_block_asm_data_order
	.type	sha1_block_asm_data_order,@function
sha1_block_asm_data_order:
	movl	12(%esp),	%ecx
	pushl	%esi
	sall	$6,		%ecx
	movl	12(%esp),	%esi
	pushl	%ebp
	addl	%esi,		%ecx
	pushl	%ebx
	movl	16(%esp),	%ebp
	pushl	%edi
	movl	12(%ebp),	%edx
	subl	$108,		%esp
	movl	16(%ebp),	%edi
	movl	8(%ebp),	%ebx
	movl	%ecx,		68(%esp)

.L000start:

	movl	(%esi),		%eax
	movl	4(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		(%esp)
	movl	%ecx,		4(%esp)
	movl	8(%esi),	%eax
	movl	12(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		8(%esp)
	movl	%ecx,		12(%esp)
	movl	16(%esi),	%eax
	movl	20(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		16(%esp)
	movl	%ecx,		20(%esp)
	movl	24(%esi),	%eax
	movl	28(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		24(%esp)
	movl	%ecx,		28(%esp)
	movl	32(%esi),	%eax
	movl	36(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		32(%esp)
	movl	%ecx,		36(%esp)
	movl	40(%esi),	%eax
	movl	44(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		40(%esp)
	movl	%ecx,		44(%esp)
	movl	48(%esi),	%eax
	movl	52(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		48(%esp)
	movl	%ecx,		52(%esp)
	movl	56(%esi),	%eax
	movl	60(%esi),	%ecx

	xchgb	%al,		%ah
	rorl	$16,		%eax
	xchgb	%al,		%ah

	xchgb	%cl,		%ch
	rorl	$16,		%ecx
	xchgb	%cl,		%ch
	movl	%eax,		56(%esp)
	movl	%ecx,		60(%esp)


	movl	%esi,		132(%esp)
.L001shortcut:


	movl	(%ebp),		%eax
	movl	4(%ebp),	%ecx

	movl	%eax,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%ebp
	xorl	%edx,		%esi
	andl	%ecx,		%esi
	rorl	$2,		%ecx
	addl	%edi,		%ebp
	movl	(%esp),		%edi
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	addl	%ebp,		%esi

	movl	%esi,		%ebp
	movl	%ecx,		%edi
	roll	$5,		%ebp
	xorl	%ebx,		%edi
	andl	%eax,		%edi
	rorl	$2,		%eax
	addl	%edx,		%ebp
	movl	4(%esp),	%edx
	xorl	%ebx,		%edi
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi

	movl	%edi,		%ebp
	movl	%eax,		%edx
	roll	$5,		%ebp
	xorl	%ecx,		%edx
	andl	%esi,		%edx
	rorl	$2,		%esi
	addl	%ebx,		%ebp
	movl	8(%esp),	%ebx
	xorl	%ecx,		%edx
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%edx

	movl	%edx,		%ebp
	movl	%esi,		%ebx
	roll	$5,		%ebp
	xorl	%eax,		%ebx
	andl	%edi,		%ebx
	rorl	$2,		%edi
	addl	%ecx,		%ebp
	movl	12(%esp),	%ecx
	xorl	%eax,		%ebx
	leal	1518500249(%ebp,%ecx,1),%ebp
	addl	%ebp,		%ebx

	movl	%ebx,		%ebp
	movl	%edi,		%ecx
	roll	$5,		%ebp
	xorl	%esi,		%ecx
	andl	%edx,		%ecx
	rorl	$2,		%edx
	addl	%eax,		%ebp
	movl	16(%esp),	%eax
	xorl	%esi,		%ecx
	leal	1518500249(%ebp,%eax,1),%ebp
	addl	%ebp,		%ecx

	movl	%ecx,		%ebp
	movl	%edx,		%eax
	roll	$5,		%ebp
	xorl	%edi,		%eax
	andl	%ebx,		%eax
	rorl	$2,		%ebx
	addl	%esi,		%ebp
	movl	20(%esp),	%esi
	xorl	%edi,		%eax
	leal	1518500249(%ebp,%esi,1),%ebp
	addl	%ebp,		%eax

	movl	%eax,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%ebp
	xorl	%edx,		%esi
	andl	%ecx,		%esi
	rorl	$2,		%ecx
	addl	%edi,		%ebp
	movl	24(%esp),	%edi
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	addl	%ebp,		%esi

	movl	%esi,		%ebp
	movl	%ecx,		%edi
	roll	$5,		%ebp
	xorl	%ebx,		%edi
	andl	%eax,		%edi
	rorl	$2,		%eax
	addl	%edx,		%ebp
	movl	28(%esp),	%edx
	xorl	%ebx,		%edi
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi

	movl	%edi,		%ebp
	movl	%eax,		%edx
	roll	$5,		%ebp
	xorl	%ecx,		%edx
	andl	%esi,		%edx
	rorl	$2,		%esi
	addl	%ebx,		%ebp
	movl	32(%esp),	%ebx
	xorl	%ecx,		%edx
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%edx

	movl	%edx,		%ebp
	movl	%esi,		%ebx
	roll	$5,		%ebp
	xorl	%eax,		%ebx
	andl	%edi,		%ebx
	rorl	$2,		%edi
	addl	%ecx,		%ebp
	movl	36(%esp),	%ecx
	xorl	%eax,		%ebx
	leal	1518500249(%ebp,%ecx,1),%ebp
	addl	%ebp,		%ebx

	movl	%ebx,		%ebp
	movl	%edi,		%ecx
	roll	$5,		%ebp
	xorl	%esi,		%ecx
	andl	%edx,		%ecx
	rorl	$2,		%edx
	addl	%eax,		%ebp
	movl	40(%esp),	%eax
	xorl	%esi,		%ecx
	leal	1518500249(%ebp,%eax,1),%ebp
	addl	%ebp,		%ecx

	movl	%ecx,		%ebp
	movl	%edx,		%eax
	roll	$5,		%ebp
	xorl	%edi,		%eax
	andl	%ebx,		%eax
	rorl	$2,		%ebx
	addl	%esi,		%ebp
	movl	44(%esp),	%esi
	xorl	%edi,		%eax
	leal	1518500249(%ebp,%esi,1),%ebp
	addl	%ebp,		%eax

	movl	%eax,		%ebp
	movl	%ebx,		%esi
	roll	$5,		%ebp
	xorl	%edx,		%esi
	andl	%ecx,		%esi
	rorl	$2,		%ecx
	addl	%edi,		%ebp
	movl	48(%esp),	%edi
	xorl	%edx,		%esi
	leal	1518500249(%ebp,%edi,1),%ebp
	addl	%ebp,		%esi

	movl	%esi,		%ebp
	movl	%ecx,		%edi
	roll	$5,		%ebp
	xorl	%ebx,		%edi
	andl	%eax,		%edi
	rorl	$2,		%eax
	addl	%edx,		%ebp
	movl	52(%esp),	%edx
	xorl	%ebx,		%edi
	leal	1518500249(%ebp,%edx,1),%ebp
	addl	%ebp,		%edi

	movl	%edi,		%ebp
	movl	%eax,		%edx
	roll	$5,		%ebp
	xorl	%ecx,		%edx
	andl	%esi,		%edx
	rorl	$2,		%esi
	addl	%ebx,		%ebp
	movl	56(%esp),	%ebx
	xorl	%ecx,		%edx
	leal	1518500249(%ebp,%ebx,1),%ebp
	addl	%ebp,		%edx

	movl	%edx,		%ebp
	movl	%esi,		%ebx
	roll	$5,		%ebp
	xorl	%eax,		%ebx
	andl	%edi,		%ebx
	rorl	$2,		%edi
	addl	%ecx,		%ebp
	movl	60(%esp),	%ecx
	xorl	%eax,		%ebx
	leal	1518500249(%ebp,%ecx,1),%ebp
	addl	%ebp,		%ebx

	movl	8(%esp),	%ecx
	movl	%edi,		%ebp
	xorl	(%esp),		%ecx
	xorl	%esi,		%ebp
	xorl	32(%esp),	%ecx
	andl	%edx,		%ebp
	xorl	52(%esp),	%ecx
	rorl	$2,		%edx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		(%esp)
	leal	1518500249(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	addl	%ebp,		%ecx
	roll	$5,		%eax
	addl	%eax,		%ecx

	movl	12(%esp),	%eax
	movl	%edx,		%ebp
	xorl	4(%esp),	%eax
	xorl	%edi,		%ebp
	xorl	36(%esp),	%eax
	andl	%ebx,		%ebp
	xorl	56(%esp),	%eax
	rorl	$2,		%ebx
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		4(%esp)
	leal	1518500249(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	addl	%ebp,		%eax
	roll	$5,		%esi
	addl	%esi,		%eax

	movl	16(%esp),	%esi
	movl	%ebx,		%ebp
	xorl	8(%esp),	%esi
	xorl	%edx,		%ebp
	xorl	40(%esp),	%esi
	andl	%ecx,		%ebp
	xorl	60(%esp),	%esi
	rorl	$2,		%ecx
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		8(%esp)
	leal	1518500249(%esi,%edi,1),%esi
	movl	%eax,		%edi
	addl	%ebp,		%esi
	roll	$5,		%edi
	addl	%edi,		%esi

	movl	20(%esp),	%edi
	movl	%ecx,		%ebp
	xorl	12(%esp),	%edi
	xorl	%ebx,		%ebp
	xorl	44(%esp),	%edi
	andl	%eax,		%ebp
	xorl	(%esp),		%edi
	rorl	$2,		%eax
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		12(%esp)
	leal	1518500249(%edi,%edx,1),%edi
	movl	%esi,		%edx
	addl	%ebp,		%edi
	roll	$5,		%edx
	addl	%edx,		%edi

	movl	16(%esp),	%edx
	movl	%esi,		%ebp
	xorl	24(%esp),	%edx
	rorl	$2,		%esi
	xorl	48(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	4(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		16(%esp)
	leal	1859775393(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	20(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	28(%esp),	%ebx
	rorl	$2,		%edi
	xorl	52(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	8(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		20(%esp)
	leal	1859775393(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	24(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	32(%esp),	%ecx
	rorl	$2,		%edx
	xorl	56(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	12(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		24(%esp)
	leal	1859775393(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	28(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	36(%esp),	%eax
	rorl	$2,		%ebx
	xorl	60(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	16(%esp),	%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		28(%esp)
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	32(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	40(%esp),	%esi
	rorl	$2,		%ecx
	xorl	(%esp),		%esi
	xorl	%ebx,		%ebp
	xorl	20(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		32(%esp)
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	36(%esp),	%edi
	movl	%eax,		%ebp
	xorl	44(%esp),	%edi
	rorl	$2,		%eax
	xorl	4(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	24(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		36(%esp)
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	40(%esp),	%edx
	movl	%esi,		%ebp
	xorl	48(%esp),	%edx
	rorl	$2,		%esi
	xorl	8(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	28(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		40(%esp)
	leal	1859775393(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	44(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	52(%esp),	%ebx
	rorl	$2,		%edi
	xorl	12(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	32(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		44(%esp)
	leal	1859775393(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	48(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	56(%esp),	%ecx
	rorl	$2,		%edx
	xorl	16(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	36(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		48(%esp)
	leal	1859775393(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	52(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	60(%esp),	%eax
	rorl	$2,		%ebx
	xorl	20(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	40(%esp),	%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		52(%esp)
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	56(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	(%esp),		%esi
	rorl	$2,		%ecx
	xorl	24(%esp),	%esi
	xorl	%ebx,		%ebp
	xorl	44(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		56(%esp)
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	60(%esp),	%edi
	movl	%eax,		%ebp
	xorl	4(%esp),	%edi
	rorl	$2,		%eax
	xorl	28(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	48(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		60(%esp)
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	(%esp),		%edx
	movl	%esi,		%ebp
	xorl	8(%esp),	%edx
	rorl	$2,		%esi
	xorl	32(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	52(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		(%esp)
	leal	1859775393(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	4(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	12(%esp),	%ebx
	rorl	$2,		%edi
	xorl	36(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	56(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		4(%esp)
	leal	1859775393(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	8(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	16(%esp),	%ecx
	rorl	$2,		%edx
	xorl	40(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	60(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		8(%esp)
	leal	1859775393(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	12(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	20(%esp),	%eax
	rorl	$2,		%ebx
	xorl	44(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	(%esp),		%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		12(%esp)
	leal	1859775393(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	16(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	24(%esp),	%esi
	rorl	$2,		%ecx
	xorl	48(%esp),	%esi
	xorl	%ebx,		%ebp
	xorl	4(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		16(%esp)
	leal	1859775393(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	20(%esp),	%edi
	movl	%eax,		%ebp
	xorl	28(%esp),	%edi
	rorl	$2,		%eax
	xorl	52(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	8(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		20(%esp)
	leal	1859775393(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	24(%esp),	%edx
	movl	%esi,		%ebp
	xorl	32(%esp),	%edx
	rorl	$2,		%esi
	xorl	56(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	12(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		24(%esp)
	leal	1859775393(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	28(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	36(%esp),	%ebx
	rorl	$2,		%edi
	xorl	60(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	16(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		28(%esp)
	leal	1859775393(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	32(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	40(%esp),	%ecx
	orl	%edi,		%ebp
	xorl	(%esp),		%ecx
	andl	%esi,		%ebp
	xorl	20(%esp),	%ecx
.byte 209
.byte 193	
	movl	%ecx,		32(%esp)
	leal	2400959708(%ecx,%eax,1),%ecx
	movl	%edx,		%eax
	rorl	$2,		%edx
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	addl	%ebp,		%ecx

	movl	36(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	44(%esp),	%eax
	orl	%edx,		%ebp
	xorl	4(%esp),	%eax
	andl	%edi,		%ebp
	xorl	24(%esp),	%eax
.byte 209
.byte 192	
	movl	%eax,		36(%esp)
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	rorl	$2,		%ebx
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%esi,		%ebp
	addl	%ebp,		%eax

	movl	40(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	48(%esp),	%esi
	orl	%ebx,		%ebp
	xorl	8(%esp),	%esi
	andl	%edx,		%ebp
	xorl	28(%esp),	%esi
.byte 209
.byte 198	
	movl	%esi,		40(%esp)
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ecx,		%edi
	rorl	$2,		%ecx
	andl	%ebx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	addl	%ebp,		%esi

	movl	44(%esp),	%edi
	movl	%eax,		%ebp
	xorl	52(%esp),	%edi
	orl	%ecx,		%ebp
	xorl	12(%esp),	%edi
	andl	%ebx,		%ebp
	xorl	32(%esp),	%edi
.byte 209
.byte 199	
	movl	%edi,		44(%esp)
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	rorl	$2,		%eax
	andl	%ecx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%edx,		%ebp
	addl	%ebp,		%edi

	movl	48(%esp),	%edx
	movl	%esi,		%ebp
	xorl	56(%esp),	%edx
	orl	%eax,		%ebp
	xorl	16(%esp),	%edx
	andl	%ecx,		%ebp
	xorl	36(%esp),	%edx
.byte 209
.byte 194	
	movl	%edx,		48(%esp)
	leal	2400959708(%edx,%ebx,1),%edx
	movl	%esi,		%ebx
	rorl	$2,		%esi
	andl	%eax,		%ebx
	orl	%ebx,		%ebp
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebx,		%ebp
	addl	%ebp,		%edx

	movl	52(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	60(%esp),	%ebx
	orl	%esi,		%ebp
	xorl	20(%esp),	%ebx
	andl	%eax,		%ebp
	xorl	40(%esp),	%ebx
.byte 209
.byte 195	
	movl	%ebx,		52(%esp)
	leal	2400959708(%ebx,%ecx,1),%ebx
	movl	%edi,		%ecx
	rorl	$2,		%edi
	andl	%esi,		%ecx
	orl	%ecx,		%ebp
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	addl	%ebp,		%ebx

	movl	56(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	(%esp),		%ecx
	orl	%edi,		%ebp
	xorl	24(%esp),	%ecx
	andl	%esi,		%ebp
	xorl	44(%esp),	%ecx
.byte 209
.byte 193	
	movl	%ecx,		56(%esp)
	leal	2400959708(%ecx,%eax,1),%ecx
	movl	%edx,		%eax
	rorl	$2,		%edx
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	addl	%ebp,		%ecx

	movl	60(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	4(%esp),	%eax
	orl	%edx,		%ebp
	xorl	28(%esp),	%eax
	andl	%edi,		%ebp
	xorl	48(%esp),	%eax
.byte 209
.byte 192	
	movl	%eax,		60(%esp)
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	rorl	$2,		%ebx
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%esi,		%ebp
	addl	%ebp,		%eax

	movl	(%esp),		%esi
	movl	%ecx,		%ebp
	xorl	8(%esp),	%esi
	orl	%ebx,		%ebp
	xorl	32(%esp),	%esi
	andl	%edx,		%ebp
	xorl	52(%esp),	%esi
.byte 209
.byte 198	
	movl	%esi,		(%esp)
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ecx,		%edi
	rorl	$2,		%ecx
	andl	%ebx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	addl	%ebp,		%esi

	movl	4(%esp),	%edi
	movl	%eax,		%ebp
	xorl	12(%esp),	%edi
	orl	%ecx,		%ebp
	xorl	36(%esp),	%edi
	andl	%ebx,		%ebp
	xorl	56(%esp),	%edi
.byte 209
.byte 199	
	movl	%edi,		4(%esp)
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	rorl	$2,		%eax
	andl	%ecx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%edx,		%ebp
	addl	%ebp,		%edi

	movl	8(%esp),	%edx
	movl	%esi,		%ebp
	xorl	16(%esp),	%edx
	orl	%eax,		%ebp
	xorl	40(%esp),	%edx
	andl	%ecx,		%ebp
	xorl	60(%esp),	%edx
.byte 209
.byte 194	
	movl	%edx,		8(%esp)
	leal	2400959708(%edx,%ebx,1),%edx
	movl	%esi,		%ebx
	rorl	$2,		%esi
	andl	%eax,		%ebx
	orl	%ebx,		%ebp
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebx,		%ebp
	addl	%ebp,		%edx

	movl	12(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	20(%esp),	%ebx
	orl	%esi,		%ebp
	xorl	44(%esp),	%ebx
	andl	%eax,		%ebp
	xorl	(%esp),		%ebx
.byte 209
.byte 195	
	movl	%ebx,		12(%esp)
	leal	2400959708(%ebx,%ecx,1),%ebx
	movl	%edi,		%ecx
	rorl	$2,		%edi
	andl	%esi,		%ecx
	orl	%ecx,		%ebp
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	addl	%ebp,		%ebx

	movl	16(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	24(%esp),	%ecx
	orl	%edi,		%ebp
	xorl	48(%esp),	%ecx
	andl	%esi,		%ebp
	xorl	4(%esp),	%ecx
.byte 209
.byte 193	
	movl	%ecx,		16(%esp)
	leal	2400959708(%ecx,%eax,1),%ecx
	movl	%edx,		%eax
	rorl	$2,		%edx
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	addl	%ebp,		%ecx

	movl	20(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	28(%esp),	%eax
	orl	%edx,		%ebp
	xorl	52(%esp),	%eax
	andl	%edi,		%ebp
	xorl	8(%esp),	%eax
.byte 209
.byte 192	
	movl	%eax,		20(%esp)
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	rorl	$2,		%ebx
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%esi,		%ebp
	addl	%ebp,		%eax

	movl	24(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	32(%esp),	%esi
	orl	%ebx,		%ebp
	xorl	56(%esp),	%esi
	andl	%edx,		%ebp
	xorl	12(%esp),	%esi
.byte 209
.byte 198	
	movl	%esi,		24(%esp)
	leal	2400959708(%esi,%edi,1),%esi
	movl	%ecx,		%edi
	rorl	$2,		%ecx
	andl	%ebx,		%edi
	orl	%edi,		%ebp
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%edi,		%ebp
	addl	%ebp,		%esi

	movl	28(%esp),	%edi
	movl	%eax,		%ebp
	xorl	36(%esp),	%edi
	orl	%ecx,		%ebp
	xorl	60(%esp),	%edi
	andl	%ebx,		%ebp
	xorl	16(%esp),	%edi
.byte 209
.byte 199	
	movl	%edi,		28(%esp)
	leal	2400959708(%edi,%edx,1),%edi
	movl	%eax,		%edx
	rorl	$2,		%eax
	andl	%ecx,		%edx
	orl	%edx,		%ebp
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%edx,		%ebp
	addl	%ebp,		%edi

	movl	32(%esp),	%edx
	movl	%esi,		%ebp
	xorl	40(%esp),	%edx
	orl	%eax,		%ebp
	xorl	(%esp),		%edx
	andl	%ecx,		%ebp
	xorl	20(%esp),	%edx
.byte 209
.byte 194	
	movl	%edx,		32(%esp)
	leal	2400959708(%edx,%ebx,1),%edx
	movl	%esi,		%ebx
	rorl	$2,		%esi
	andl	%eax,		%ebx
	orl	%ebx,		%ebp
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebx,		%ebp
	addl	%ebp,		%edx

	movl	36(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	44(%esp),	%ebx
	orl	%esi,		%ebp
	xorl	4(%esp),	%ebx
	andl	%eax,		%ebp
	xorl	24(%esp),	%ebx
.byte 209
.byte 195	
	movl	%ebx,		36(%esp)
	leal	2400959708(%ebx,%ecx,1),%ebx
	movl	%edi,		%ecx
	rorl	$2,		%edi
	andl	%esi,		%ecx
	orl	%ecx,		%ebp
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ecx,		%ebp
	addl	%ebp,		%ebx

	movl	40(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	48(%esp),	%ecx
	orl	%edi,		%ebp
	xorl	8(%esp),	%ecx
	andl	%esi,		%ebp
	xorl	28(%esp),	%ecx
.byte 209
.byte 193	
	movl	%ecx,		40(%esp)
	leal	2400959708(%ecx,%eax,1),%ecx
	movl	%edx,		%eax
	rorl	$2,		%edx
	andl	%edi,		%eax
	orl	%eax,		%ebp
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%eax,		%ebp
	addl	%ebp,		%ecx

	movl	44(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	52(%esp),	%eax
	orl	%edx,		%ebp
	xorl	12(%esp),	%eax
	andl	%edi,		%ebp
	xorl	32(%esp),	%eax
.byte 209
.byte 192	
	movl	%eax,		44(%esp)
	leal	2400959708(%eax,%esi,1),%eax
	movl	%ebx,		%esi
	rorl	$2,		%ebx
	andl	%edx,		%esi
	orl	%esi,		%ebp
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%esi,		%ebp
	addl	%ebp,		%eax

	movl	48(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	56(%esp),	%esi
	rorl	$2,		%ecx
	xorl	16(%esp),	%esi
	xorl	%ebx,		%ebp
	xorl	36(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		48(%esp)
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	52(%esp),	%edi
	movl	%eax,		%ebp
	xorl	60(%esp),	%edi
	rorl	$2,		%eax
	xorl	20(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	40(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		52(%esp)
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	56(%esp),	%edx
	movl	%esi,		%ebp
	xorl	(%esp),		%edx
	rorl	$2,		%esi
	xorl	24(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	44(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		56(%esp)
	leal	3395469782(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	60(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	4(%esp),	%ebx
	rorl	$2,		%edi
	xorl	28(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	48(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		60(%esp)
	leal	3395469782(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	(%esp),		%ecx
	movl	%edx,		%ebp
	xorl	8(%esp),	%ecx
	rorl	$2,		%edx
	xorl	32(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	52(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		(%esp)
	leal	3395469782(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	4(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	12(%esp),	%eax
	rorl	$2,		%ebx
	xorl	36(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	56(%esp),	%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		4(%esp)
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	8(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	16(%esp),	%esi
	rorl	$2,		%ecx
	xorl	40(%esp),	%esi
	xorl	%ebx,		%ebp
	xorl	60(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		8(%esp)
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	12(%esp),	%edi
	movl	%eax,		%ebp
	xorl	20(%esp),	%edi
	rorl	$2,		%eax
	xorl	44(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	(%esp),		%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		12(%esp)
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	16(%esp),	%edx
	movl	%esi,		%ebp
	xorl	24(%esp),	%edx
	rorl	$2,		%esi
	xorl	48(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	4(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		16(%esp)
	leal	3395469782(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	20(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	28(%esp),	%ebx
	rorl	$2,		%edi
	xorl	52(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	8(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		20(%esp)
	leal	3395469782(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	24(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	32(%esp),	%ecx
	rorl	$2,		%edx
	xorl	56(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	12(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		24(%esp)
	leal	3395469782(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	28(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	36(%esp),	%eax
	rorl	$2,		%ebx
	xorl	60(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	16(%esp),	%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		28(%esp)
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	32(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	40(%esp),	%esi
	rorl	$2,		%ecx
	xorl	(%esp),		%esi
	xorl	%ebx,		%ebp
	xorl	20(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		32(%esp)
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	36(%esp),	%edi
	movl	%eax,		%ebp
	xorl	44(%esp),	%edi
	rorl	$2,		%eax
	xorl	4(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	24(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		36(%esp)
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi

	movl	40(%esp),	%edx
	movl	%esi,		%ebp
	xorl	48(%esp),	%edx
	rorl	$2,		%esi
	xorl	8(%esp),	%edx
	xorl	%eax,		%ebp
	xorl	28(%esp),	%edx
	xorl	%ecx,		%ebp
.byte 209
.byte 194	
	movl	%edx,		40(%esp)
	leal	3395469782(%edx,%ebx,1),%edx
	movl	%edi,		%ebx
	roll	$5,		%ebx
	addl	%ebp,		%edx
	addl	%ebx,		%edx

	movl	44(%esp),	%ebx
	movl	%edi,		%ebp
	xorl	52(%esp),	%ebx
	rorl	$2,		%edi
	xorl	12(%esp),	%ebx
	xorl	%esi,		%ebp
	xorl	32(%esp),	%ebx
	xorl	%eax,		%ebp
.byte 209
.byte 195	
	movl	%ebx,		44(%esp)
	leal	3395469782(%ebx,%ecx,1),%ebx
	movl	%edx,		%ecx
	roll	$5,		%ecx
	addl	%ebp,		%ebx
	addl	%ecx,		%ebx

	movl	48(%esp),	%ecx
	movl	%edx,		%ebp
	xorl	56(%esp),	%ecx
	rorl	$2,		%edx
	xorl	16(%esp),	%ecx
	xorl	%edi,		%ebp
	xorl	36(%esp),	%ecx
	xorl	%esi,		%ebp
.byte 209
.byte 193	
	movl	%ecx,		48(%esp)
	leal	3395469782(%ecx,%eax,1),%ecx
	movl	%ebx,		%eax
	roll	$5,		%eax
	addl	%ebp,		%ecx
	addl	%eax,		%ecx

	movl	52(%esp),	%eax
	movl	%ebx,		%ebp
	xorl	60(%esp),	%eax
	rorl	$2,		%ebx
	xorl	20(%esp),	%eax
	xorl	%edx,		%ebp
	xorl	40(%esp),	%eax
	xorl	%edi,		%ebp
.byte 209
.byte 192	
	movl	%eax,		52(%esp)
	leal	3395469782(%eax,%esi,1),%eax
	movl	%ecx,		%esi
	roll	$5,		%esi
	addl	%ebp,		%eax
	addl	%esi,		%eax

	movl	56(%esp),	%esi
	movl	%ecx,		%ebp
	xorl	(%esp),		%esi
	rorl	$2,		%ecx
	xorl	24(%esp),	%esi
	xorl	%ebx,		%ebp
	xorl	44(%esp),	%esi
	xorl	%edx,		%ebp
.byte 209
.byte 198	
	movl	%esi,		56(%esp)
	leal	3395469782(%esi,%edi,1),%esi
	movl	%eax,		%edi
	roll	$5,		%edi
	addl	%ebp,		%esi
	addl	%edi,		%esi

	movl	60(%esp),	%edi
	movl	%eax,		%ebp
	xorl	4(%esp),	%edi
	rorl	$2,		%eax
	xorl	28(%esp),	%edi
	xorl	%ecx,		%ebp
	xorl	48(%esp),	%edi
	xorl	%ebx,		%ebp
.byte 209
.byte 199	
	movl	%edi,		60(%esp)
	leal	3395469782(%edi,%edx,1),%edi
	movl	%esi,		%edx
	roll	$5,		%edx
	addl	%ebp,		%edi
	addl	%edx,		%edi


	movl	128(%esp),	%ebp
	movl	12(%ebp),	%edx
	addl	%ecx,		%edx
	movl	4(%ebp),	%ecx
	addl	%esi,		%ecx
	movl	%eax,		%esi
	movl	(%ebp),		%eax
	movl	%edx,		12(%ebp)
	addl	%edi,		%eax
	movl	16(%ebp),	%edi
	addl	%ebx,		%edi
	movl	8(%ebp),	%ebx
	addl	%esi,		%ebx
	movl	%eax,		(%ebp)
	movl	132(%esp),	%esi
	movl	%ebx,		8(%ebp)
	addl	$64,		%esi
	movl	68(%esp),	%eax
	movl	%edi,		16(%ebp)
	cmpl	%eax,		%esi
	movl	%ecx,		4(%ebp)
	jb	.L000start
	addl	$108,		%esp
	popl	%edi
	popl	%ebx
	popl	%ebp
	popl	%esi
	ret
.L_sha1_block_asm_data_order_end:
	.size	sha1_block_asm_data_order,.L_sha1_block_asm_data_order_end-sha1_block_asm_data_order
.ident	"desasm.pl"
.text
	.align 16
.globl sha1_block_asm_host_order
	.type	sha1_block_asm_host_order,@function
sha1_block_asm_host_order:
	movl	12(%esp),	%ecx
	pushl	%esi
	sall	$6,		%ecx
	movl	12(%esp),	%esi
	pushl	%ebp
	addl	%esi,		%ecx
	pushl	%ebx
	movl	16(%esp),	%ebp
	pushl	%edi
	movl	12(%ebp),	%edx
	subl	$108,		%esp
	movl	16(%ebp),	%edi
	movl	8(%ebp),	%ebx
	movl	%ecx,		68(%esp)

	movl	(%esi),		%eax
	movl	4(%esi),	%ecx
	movl	%eax,		(%esp)
	movl	%ecx,		4(%esp)
	movl	8(%esi),	%eax
	movl	12(%esi),	%ecx
	movl	%eax,		8(%esp)
	movl	%ecx,		12(%esp)
	movl	16(%esi),	%eax
	movl	20(%esi),	%ecx
	movl	%eax,		16(%esp)
	movl	%ecx,		20(%esp)
	movl	24(%esi),	%eax
	movl	28(%esi),	%ecx
	movl	%eax,		24(%esp)
	movl	%ecx,		28(%esp)
	movl	32(%esi),	%eax
	movl	36(%esi),	%ecx
	movl	%eax,		32(%esp)
	movl	%ecx,		36(%esp)
	movl	40(%esi),	%eax
	movl	44(%esi),	%ecx
	movl	%eax,		40(%esp)
	movl	%ecx,		44(%esp)
	movl	48(%esi),	%eax
	movl	52(%esi),	%ecx
	movl	%eax,		48(%esp)
	movl	%ecx,		52(%esp)
	movl	56(%esi),	%eax
	movl	60(%esi),	%ecx
	movl	%eax,		56(%esp)
	movl	%ecx,		60(%esp)
	jmp	.L001shortcut
.L_sha1_block_asm_host_order_end:
	.size	sha1_block_asm_host_order,.L_sha1_block_asm_host_order_end-sha1_block_asm_host_order
.ident	"desasm.pl"
