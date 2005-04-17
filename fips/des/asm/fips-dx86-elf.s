





	.file	"des-586.s"
	.version	"01.01"
gcc2_compiled.:
.text
	.align 16
.globl DES_encrypt1
	.type	DES_encrypt1,@function
DES_encrypt1:
	pushl	%esi
	pushl	%edi


	movl	12(%esp),	%esi
	xorl	%ecx,		%ecx
	pushl	%ebx
	pushl	%ebp
	movl	(%esi),		%eax
	movl	28(%esp),	%ebx
	movl	4(%esi),	%edi


	roll	$4,		%eax
	movl	%eax,		%esi
	xorl	%edi,		%eax
	andl	$0xf0f0f0f0,	%eax
	xorl	%eax,		%esi
	xorl	%eax,		%edi

	roll	$20,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0xfff0000f,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$14,		%eax
	movl	%eax,		%edi
	xorl	%esi,		%eax
	andl	$0x33333333,	%eax
	xorl	%eax,		%edi
	xorl	%eax,		%esi

	roll	$22,		%esi
	movl	%esi,		%eax
	xorl	%edi,		%esi
	andl	$0x03fc03fc,	%esi
	xorl	%esi,		%eax
	xorl	%esi,		%edi

	roll	$9,		%eax
	movl	%eax,		%esi
	xorl	%edi,		%eax
	andl	$0xaaaaaaaa,	%eax
	xorl	%eax,		%esi
	xorl	%eax,		%edi

.byte 209
.byte 199	
	.align	8
	call	.L000PIC_me_up
.L000PIC_me_up:
	popl	%ebp
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L000PIC_me_up],%ebp
	movl	DES_SPtrans@GOT(%ebp),%ebp
	movl	24(%esp),	%ecx
	cmpl	$0,		%ebx
	je	.L001start_decrypt


	movl	(%ecx),		%eax
	xorl	%ebx,		%ebx
	movl	4(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	8(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	12(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	16(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	20(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	24(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	28(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	32(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	36(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	40(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	44(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	48(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	52(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	56(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	60(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	64(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	68(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	72(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	76(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	80(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	84(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	88(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	92(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	96(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	100(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	104(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	108(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	112(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	116(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	120(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	124(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi
	jmp	.L002end
.L001start_decrypt:


	movl	120(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	124(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	112(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	116(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	104(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	108(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	96(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	100(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	88(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	92(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	80(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	84(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	72(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	76(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	64(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	68(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	56(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	60(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	48(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	52(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	40(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	44(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	32(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	36(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	24(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	28(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	16(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	20(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	8(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	12(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	(%ecx),		%eax
	xorl	%ebx,		%ebx
	movl	4(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi
.L002end:


	movl	20(%esp),	%edx
.byte 209
.byte 206	
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0xaaaaaaaa,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$23,		%eax
	movl	%eax,		%edi
	xorl	%esi,		%eax
	andl	$0x03fc03fc,	%eax
	xorl	%eax,		%edi
	xorl	%eax,		%esi

	roll	$10,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0x33333333,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$18,		%esi
	movl	%esi,		%edi
	xorl	%eax,		%esi
	andl	$0xfff0000f,	%esi
	xorl	%esi,		%edi
	xorl	%esi,		%eax

	roll	$12,		%edi
	movl	%edi,		%esi
	xorl	%eax,		%edi
	andl	$0xf0f0f0f0,	%edi
	xorl	%edi,		%esi
	xorl	%edi,		%eax

	rorl	$4,		%eax
	movl	%eax,		(%edx)
	movl	%esi,		4(%edx)
	popl	%ebp
	popl	%ebx
	popl	%edi
	popl	%esi
	ret
.L_DES_encrypt1_end:
	.size	DES_encrypt1,.L_DES_encrypt1_end-DES_encrypt1
.ident	"desasm.pl"
.text
	.align 16
.globl DES_encrypt2
	.type	DES_encrypt2,@function
DES_encrypt2:
	pushl	%esi
	pushl	%edi


	movl	12(%esp),	%eax
	xorl	%ecx,		%ecx
	pushl	%ebx
	pushl	%ebp
	movl	(%eax),		%esi
	movl	28(%esp),	%ebx
	roll	$3,		%esi
	movl	4(%eax),	%edi
	roll	$3,		%edi
	.align	8
	call	.L003PIC_me_up
.L003PIC_me_up:
	popl	%ebp
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L003PIC_me_up],%ebp
	movl	DES_SPtrans@GOT(%ebp),%ebp
	movl	24(%esp),	%ecx
	cmpl	$0,		%ebx
	je	.L004start_decrypt


	movl	(%ecx),		%eax
	xorl	%ebx,		%ebx
	movl	4(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	8(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	12(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	16(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	20(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	24(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	28(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	32(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	36(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	40(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	44(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	48(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	52(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	56(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	60(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	64(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	68(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	72(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	76(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	80(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	84(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	88(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	92(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	96(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	100(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	104(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	108(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	112(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	116(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	120(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	124(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi
	jmp	.L005end
.L004start_decrypt:


	movl	120(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	124(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	112(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	116(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	104(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	108(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	96(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	100(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	88(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	92(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	80(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	84(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	72(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	76(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	64(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	68(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	56(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	60(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	48(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	52(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	40(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	44(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	32(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	36(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	24(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	28(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	16(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	20(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi


	movl	8(%ecx),	%eax
	xorl	%ebx,		%ebx
	movl	12(%ecx),	%edx
	xorl	%esi,		%eax
	xorl	%ecx,		%ecx
	xorl	%esi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%edi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%edi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%edi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%edi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%edi
	xorl	0x700(%ebp,%ecx),%edi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%edi
	xorl	0x500(%ebp,%edx),%edi


	movl	(%ecx),		%eax
	xorl	%ebx,		%ebx
	movl	4(%ecx),	%edx
	xorl	%edi,		%eax
	xorl	%ecx,		%ecx
	xorl	%edi,		%edx
	andl	$0xfcfcfcfc,	%eax
	andl	$0xcfcfcfcf,	%edx
	movb	%al,		%bl
	movb	%ah,		%cl
	rorl	$4,		%edx
	xorl	     (%ebp,%ebx),%esi
	movb	%dl,		%bl
	xorl	0x200(%ebp,%ecx),%esi
	movb	%dh,		%cl
	shrl	$16,		%eax
	xorl	0x100(%ebp,%ebx),%esi
	movb	%ah,		%bl
	shrl	$16,		%edx
	xorl	0x300(%ebp,%ecx),%esi
	movb	%dh,		%cl
	andl	$0xff,		%eax
	andl	$0xff,		%edx
	xorl	0x600(%ebp,%ebx),%esi
	xorl	0x700(%ebp,%ecx),%esi
	movl	24(%esp),	%ecx
	xorl	0x400(%ebp,%eax),%esi
	xorl	0x500(%ebp,%edx),%esi
.L005end:


	rorl	$3,		%edi
	movl	20(%esp),	%eax
	rorl	$3,		%esi
	movl	%edi,		(%eax)
	movl	%esi,		4(%eax)
	popl	%ebp
	popl	%ebx
	popl	%edi
	popl	%esi
	ret
.L_DES_encrypt2_end:
	.size	DES_encrypt2,.L_DES_encrypt2_end-DES_encrypt2
.ident	"desasm.pl"
.text
	.align 16
.globl DES_encrypt3
	.type	DES_encrypt3,@function
DES_encrypt3:
	pushl	%ebx
	movl	8(%esp),	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi


	movl	(%ebx),		%edi
	movl	4(%ebx),	%esi
	subl	$12,		%esp


	roll	$4,		%edi
	movl	%edi,		%edx
	xorl	%esi,		%edi
	andl	$0xf0f0f0f0,	%edi
	xorl	%edi,		%edx
	xorl	%edi,		%esi

	roll	$20,		%esi
	movl	%esi,		%edi
	xorl	%edx,		%esi
	andl	$0xfff0000f,	%esi
	xorl	%esi,		%edi
	xorl	%esi,		%edx

	roll	$14,		%edi
	movl	%edi,		%esi
	xorl	%edx,		%edi
	andl	$0x33333333,	%edi
	xorl	%edi,		%esi
	xorl	%edi,		%edx

	roll	$22,		%edx
	movl	%edx,		%edi
	xorl	%esi,		%edx
	andl	$0x03fc03fc,	%edx
	xorl	%edx,		%edi
	xorl	%edx,		%esi

	roll	$9,		%edi
	movl	%edi,		%edx
	xorl	%esi,		%edi
	andl	$0xaaaaaaaa,	%edi
	xorl	%edi,		%edx
	xorl	%edi,		%esi

	rorl	$3,		%edx
	rorl	$2,		%esi
	movl	%esi,		4(%ebx)
	movl	36(%esp),	%eax
	movl	%edx,		(%ebx)
	movl	40(%esp),	%edi
	movl	44(%esp),	%esi
	movl	$1,		8(%esp)
	movl	%eax,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	movl	$0,		8(%esp)
	movl	%edi,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	movl	$1,		8(%esp)
	movl	%esi,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	addl	$12,		%esp
	movl	(%ebx),		%edi
	movl	4(%ebx),	%esi


	roll	$2,		%esi
	roll	$3,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0xaaaaaaaa,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$23,		%eax
	movl	%eax,		%edi
	xorl	%esi,		%eax
	andl	$0x03fc03fc,	%eax
	xorl	%eax,		%edi
	xorl	%eax,		%esi

	roll	$10,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0x33333333,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$18,		%esi
	movl	%esi,		%edi
	xorl	%eax,		%esi
	andl	$0xfff0000f,	%esi
	xorl	%esi,		%edi
	xorl	%esi,		%eax

	roll	$12,		%edi
	movl	%edi,		%esi
	xorl	%eax,		%edi
	andl	$0xf0f0f0f0,	%edi
	xorl	%edi,		%esi
	xorl	%edi,		%eax

	rorl	$4,		%eax
	movl	%eax,		(%ebx)
	movl	%esi,		4(%ebx)
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.L_DES_encrypt3_end:
	.size	DES_encrypt3,.L_DES_encrypt3_end-DES_encrypt3
.ident	"desasm.pl"
.text
	.align 16
.globl DES_decrypt3
	.type	DES_decrypt3,@function
DES_decrypt3:
	pushl	%ebx
	movl	8(%esp),	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi


	movl	(%ebx),		%edi
	movl	4(%ebx),	%esi
	subl	$12,		%esp


	roll	$4,		%edi
	movl	%edi,		%edx
	xorl	%esi,		%edi
	andl	$0xf0f0f0f0,	%edi
	xorl	%edi,		%edx
	xorl	%edi,		%esi

	roll	$20,		%esi
	movl	%esi,		%edi
	xorl	%edx,		%esi
	andl	$0xfff0000f,	%esi
	xorl	%esi,		%edi
	xorl	%esi,		%edx

	roll	$14,		%edi
	movl	%edi,		%esi
	xorl	%edx,		%edi
	andl	$0x33333333,	%edi
	xorl	%edi,		%esi
	xorl	%edi,		%edx

	roll	$22,		%edx
	movl	%edx,		%edi
	xorl	%esi,		%edx
	andl	$0x03fc03fc,	%edx
	xorl	%edx,		%edi
	xorl	%edx,		%esi

	roll	$9,		%edi
	movl	%edi,		%edx
	xorl	%esi,		%edi
	andl	$0xaaaaaaaa,	%edi
	xorl	%edi,		%edx
	xorl	%edi,		%esi

	rorl	$3,		%edx
	rorl	$2,		%esi
	movl	%esi,		4(%ebx)
	movl	36(%esp),	%esi
	movl	%edx,		(%ebx)
	movl	40(%esp),	%edi
	movl	44(%esp),	%eax
	movl	$0,		8(%esp)
	movl	%eax,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	movl	$1,		8(%esp)
	movl	%edi,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	movl	$0,		8(%esp)
	movl	%esi,		4(%esp)
	movl	%ebx,		(%esp)
	call	DES_encrypt2
	addl	$12,		%esp
	movl	(%ebx),		%edi
	movl	4(%ebx),	%esi


	roll	$2,		%esi
	roll	$3,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0xaaaaaaaa,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$23,		%eax
	movl	%eax,		%edi
	xorl	%esi,		%eax
	andl	$0x03fc03fc,	%eax
	xorl	%eax,		%edi
	xorl	%eax,		%esi

	roll	$10,		%edi
	movl	%edi,		%eax
	xorl	%esi,		%edi
	andl	$0x33333333,	%edi
	xorl	%edi,		%eax
	xorl	%edi,		%esi

	roll	$18,		%esi
	movl	%esi,		%edi
	xorl	%eax,		%esi
	andl	$0xfff0000f,	%esi
	xorl	%esi,		%edi
	xorl	%esi,		%eax

	roll	$12,		%edi
	movl	%edi,		%esi
	xorl	%eax,		%edi
	andl	$0xf0f0f0f0,	%edi
	xorl	%edi,		%esi
	xorl	%edi,		%eax

	rorl	$4,		%eax
	movl	%eax,		(%ebx)
	movl	%esi,		4(%ebx)
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.L_DES_decrypt3_end:
	.size	DES_decrypt3,.L_DES_decrypt3_end-DES_decrypt3
.ident	"desasm.pl"
.text
	.align 16
.globl DES_ncbc_encrypt
	.type	DES_ncbc_encrypt,@function
DES_ncbc_encrypt:

	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	28(%esp),	%ebp

	movl	36(%esp),	%ebx
	movl	(%ebx),		%esi
	movl	4(%ebx),	%edi
	pushl	%edi
	pushl	%esi
	pushl	%edi
	pushl	%esi
	movl	%esp,		%ebx
	movl	36(%esp),	%esi
	movl	40(%esp),	%edi

	movl	56(%esp),	%ecx

	pushl	%ecx

	movl	52(%esp),	%eax
	pushl	%eax
	pushl	%ebx
	cmpl	$0,		%ecx
	jz	.L006decrypt
	andl	$4294967288,	%ebp
	movl	12(%esp),	%eax
	movl	16(%esp),	%ebx
	jz	.L007encrypt_finish
.L008encrypt_loop:
	movl	(%esi),		%ecx
	movl	4(%esi),	%edx
	xorl	%ecx,		%eax
	xorl	%edx,		%ebx
	movl	%eax,		12(%esp)
	movl	%ebx,		16(%esp)
	call	DES_encrypt1
	movl	12(%esp),	%eax
	movl	16(%esp),	%ebx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	addl	$8,		%esi
	addl	$8,		%edi
	subl	$8,		%ebp
	jnz	.L008encrypt_loop
.L007encrypt_finish:
	movl	56(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L009finish
	call	.L010PIC_point
.L010PIC_point:
	popl	%edx
	leal	.L011cbc_enc_jmp_table-.L010PIC_point(%edx),%ecx
	movl	(%ecx,%ebp,4),	%ebp
	addl	%edx,		%ebp
	xorl	%ecx,		%ecx
	xorl	%edx,		%edx
	jmp	*%ebp
.L012ej7:
	movb	6(%esi),	%dh
	sall	$8,		%edx
.L013ej6:
	movb	5(%esi),	%dh
.L014ej5:
	movb	4(%esi),	%dl
.L015ej4:
	movl	(%esi),		%ecx
	jmp	.L016ejend
.L017ej3:
	movb	2(%esi),	%ch
	sall	$8,		%ecx
.L018ej2:
	movb	1(%esi),	%ch
.L019ej1:
	movb	(%esi),		%cl
.L016ejend:
	xorl	%ecx,		%eax
	xorl	%edx,		%ebx
	movl	%eax,		12(%esp)
	movl	%ebx,		16(%esp)
	call	DES_encrypt1
	movl	12(%esp),	%eax
	movl	16(%esp),	%ebx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	jmp	.L009finish
.align 16
.L006decrypt:
	andl	$4294967288,	%ebp
	movl	20(%esp),	%eax
	movl	24(%esp),	%ebx
	jz	.L020decrypt_finish
.L021decrypt_loop:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%eax,		12(%esp)
	movl	%ebx,		16(%esp)
	call	DES_encrypt1
	movl	12(%esp),	%eax
	movl	16(%esp),	%ebx
	movl	20(%esp),	%ecx
	movl	24(%esp),	%edx
	xorl	%eax,		%ecx
	xorl	%ebx,		%edx
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%ecx,		(%edi)
	movl	%edx,		4(%edi)
	movl	%eax,		20(%esp)
	movl	%ebx,		24(%esp)
	addl	$8,		%esi
	addl	$8,		%edi
	subl	$8,		%ebp
	jnz	.L021decrypt_loop
.L020decrypt_finish:
	movl	56(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L009finish
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%eax,		12(%esp)
	movl	%ebx,		16(%esp)
	call	DES_encrypt1
	movl	12(%esp),	%eax
	movl	16(%esp),	%ebx
	movl	20(%esp),	%ecx
	movl	24(%esp),	%edx
	xorl	%eax,		%ecx
	xorl	%ebx,		%edx
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
.L022dj7:
	rorl	$16,		%edx
	movb	%dl,		6(%edi)
	shrl	$16,		%edx
.L023dj6:
	movb	%dh,		5(%edi)
.L024dj5:
	movb	%dl,		4(%edi)
.L025dj4:
	movl	%ecx,		(%edi)
	jmp	.L026djend
.L027dj3:
	rorl	$16,		%ecx
	movb	%cl,		2(%edi)
	sall	$16,		%ecx
.L028dj2:
	movb	%ch,		1(%esi)
.L029dj1:
	movb	%cl,		(%esi)
.L026djend:
	jmp	.L009finish
.align 16
.L009finish:
	movl	64(%esp),	%ecx
	addl	$28,		%esp
	movl	%eax,		(%ecx)
	movl	%ebx,		4(%ecx)
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.align 16
.L011cbc_enc_jmp_table:
	.long 0
	.long .L019ej1-.L010PIC_point
	.long .L018ej2-.L010PIC_point
	.long .L017ej3-.L010PIC_point
	.long .L015ej4-.L010PIC_point
	.long .L014ej5-.L010PIC_point
	.long .L013ej6-.L010PIC_point
	.long .L012ej7-.L010PIC_point
.L_DES_ncbc_encrypt_end:
	.size	DES_ncbc_encrypt,.L_DES_ncbc_encrypt_end-DES_ncbc_encrypt
.ident	"desasm.pl"
.text
	.align 16
.globl DES_ede3_cbc_encrypt
	.type	DES_ede3_cbc_encrypt,@function
DES_ede3_cbc_encrypt:

	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	28(%esp),	%ebp

	movl	44(%esp),	%ebx
	movl	(%ebx),		%esi
	movl	4(%ebx),	%edi
	pushl	%edi
	pushl	%esi
	pushl	%edi
	pushl	%esi
	movl	%esp,		%ebx
	movl	36(%esp),	%esi
	movl	40(%esp),	%edi

	movl	64(%esp),	%ecx

	movl	56(%esp),	%eax
	pushl	%eax

	movl	56(%esp),	%eax
	pushl	%eax

	movl	56(%esp),	%eax
	pushl	%eax
	pushl	%ebx
	cmpl	$0,		%ecx
	jz	.L030decrypt
	andl	$4294967288,	%ebp
	movl	16(%esp),	%eax
	movl	20(%esp),	%ebx
	jz	.L031encrypt_finish
.L032encrypt_loop:
	movl	(%esi),		%ecx
	movl	4(%esi),	%edx
	xorl	%ecx,		%eax
	xorl	%edx,		%ebx
	movl	%eax,		16(%esp)
	movl	%ebx,		20(%esp)
	call	DES_encrypt3
	movl	16(%esp),	%eax
	movl	20(%esp),	%ebx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	addl	$8,		%esi
	addl	$8,		%edi
	subl	$8,		%ebp
	jnz	.L032encrypt_loop
.L031encrypt_finish:
	movl	60(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L033finish
	call	.L034PIC_point
.L034PIC_point:
	popl	%edx
	leal	.L035cbc_enc_jmp_table-.L034PIC_point(%edx),%ecx
	movl	(%ecx,%ebp,4),	%ebp
	addl	%edx,		%ebp
	xorl	%ecx,		%ecx
	xorl	%edx,		%edx
	jmp	*%ebp
.L036ej7:
	movb	6(%esi),	%dh
	sall	$8,		%edx
.L037ej6:
	movb	5(%esi),	%dh
.L038ej5:
	movb	4(%esi),	%dl
.L039ej4:
	movl	(%esi),		%ecx
	jmp	.L040ejend
.L041ej3:
	movb	2(%esi),	%ch
	sall	$8,		%ecx
.L042ej2:
	movb	1(%esi),	%ch
.L043ej1:
	movb	(%esi),		%cl
.L040ejend:
	xorl	%ecx,		%eax
	xorl	%edx,		%ebx
	movl	%eax,		16(%esp)
	movl	%ebx,		20(%esp)
	call	DES_encrypt3
	movl	16(%esp),	%eax
	movl	20(%esp),	%ebx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	jmp	.L033finish
.align 16
.L030decrypt:
	andl	$4294967288,	%ebp
	movl	24(%esp),	%eax
	movl	28(%esp),	%ebx
	jz	.L044decrypt_finish
.L045decrypt_loop:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%eax,		16(%esp)
	movl	%ebx,		20(%esp)
	call	DES_decrypt3
	movl	16(%esp),	%eax
	movl	20(%esp),	%ebx
	movl	24(%esp),	%ecx
	movl	28(%esp),	%edx
	xorl	%eax,		%ecx
	xorl	%ebx,		%edx
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%ecx,		(%edi)
	movl	%edx,		4(%edi)
	movl	%eax,		24(%esp)
	movl	%ebx,		28(%esp)
	addl	$8,		%esi
	addl	$8,		%edi
	subl	$8,		%ebp
	jnz	.L045decrypt_loop
.L044decrypt_finish:
	movl	60(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L033finish
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	%eax,		16(%esp)
	movl	%ebx,		20(%esp)
	call	DES_decrypt3
	movl	16(%esp),	%eax
	movl	20(%esp),	%ebx
	movl	24(%esp),	%ecx
	movl	28(%esp),	%edx
	xorl	%eax,		%ecx
	xorl	%ebx,		%edx
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
.L046dj7:
	rorl	$16,		%edx
	movb	%dl,		6(%edi)
	shrl	$16,		%edx
.L047dj6:
	movb	%dh,		5(%edi)
.L048dj5:
	movb	%dl,		4(%edi)
.L049dj4:
	movl	%ecx,		(%edi)
	jmp	.L050djend
.L051dj3:
	rorl	$16,		%ecx
	movb	%cl,		2(%edi)
	sall	$16,		%ecx
.L052dj2:
	movb	%ch,		1(%esi)
.L053dj1:
	movb	%cl,		(%esi)
.L050djend:
	jmp	.L033finish
.align 16
.L033finish:
	movl	76(%esp),	%ecx
	addl	$32,		%esp
	movl	%eax,		(%ecx)
	movl	%ebx,		4(%ecx)
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.align 16
.L035cbc_enc_jmp_table:
	.long 0
	.long .L043ej1-.L034PIC_point
	.long .L042ej2-.L034PIC_point
	.long .L041ej3-.L034PIC_point
	.long .L039ej4-.L034PIC_point
	.long .L038ej5-.L034PIC_point
	.long .L037ej6-.L034PIC_point
	.long .L036ej7-.L034PIC_point
.L_DES_ede3_cbc_encrypt_end:
	.size	DES_ede3_cbc_encrypt,.L_DES_ede3_cbc_encrypt_end-DES_ede3_cbc_encrypt
.ident	"desasm.pl"
