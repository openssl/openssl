#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# September 2011
#
# Assembler helpers for Padlock engine. Compared to original engine
# version relying on inline assembler and compiled with gcc 3.4.6 it
# was measured to provide ~100% improvement on misaligned data in ECB
# mode and ~75% in CBC mode. For aligned data improvement can be
# observed for short inputs only, e.g. 45% for 64-byte messages in
# ECB mode, 20% in CBC. Difference in performance for aligned vs.
# misaligned data depends on misalignment and is either ~1.8x or 2.9x.
# These are approximately same factors as for hardware support, so
# there is little reason to rely on the latter. On the contrary, it
# might actually hurt performance in mixture of aligned and misaligned
# buffers, because a) if you choose to flip 'align' flag in control
# word on per-buffer basis, then you'd have to reload key context,
# which incurs penalty; b) if you choose to set 'align' flag
# permanently, it limits performance even for aligned data to ~1/2.
# All above mentioned results were collected on 1.5GHz C7. Nano on the
# other hand handles unaligned data more gracefully. Depending on
# algorithm and how unaligned data is, hardware can be up to 70% more
# efficient than below software alignment procedures, nor does 'align'
# flag have affect on aligned performance [if has any meaning at all].
# Therefore suggestion is to unconditionally set 'align' flag on Nano
# for optimal performance.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../crypto/perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

%PADLOCK_MARGIN=(ecb=>128, cbc=>64); # prefetch errata
$PADLOCK_CHUNK=512;	# Must be a power of 2 larger than 16

$ctx="edx";
$out="edi";
$inp="esi";
$len="ecx";
$chunk="ebx";

&function_begin_B("padlock_capability");
	&push	("ebx");
	&pushf	();
	&pop	("eax");
	&mov	("ecx","eax");
	&xor	("eax",1<<21);
	&push	("eax");
	&popf	();
	&pushf	();
	&pop	("eax");
	&xor	("ecx","eax");
	&xor	("eax","eax");
	&bt	("ecx",21);
	&jnc	(&label("noluck"));
	&cpuid	();
	&xor	("eax","eax");
	&cmp	("ebx","0x".unpack("H*",'tneC'));
	&jne	(&label("noluck"));
	&cmp	("edx","0x".unpack("H*",'Hrua'));
	&jne	(&label("noluck"));
	&cmp	("ecx","0x".unpack("H*",'slua'));
	&jne	(&label("noluck"));
	&mov	("eax",0xC0000000);
	&cpuid	();
	&mov	("edx","eax");
	&xor	("eax","eax");
	&cmp	("edx",0xC0000001);
	&jb	(&label("noluck"));
	&mov	("eax",1);
	&cpuid	();
	&or	("eax",0x0f);
	&xor	("ebx","ebx");
	&and	("eax",0x0fff);
	&cmp	("eax",0x06ff);		# check for Nano
	&sete	("bl");
	&mov	("eax",0xC0000001);
	&push	("ebx");
	&cpuid	();
	&pop	("ebx");
	&mov	("eax","edx");
	&shl	("ebx",4);		# bit#4 denotes Nano
	&and	("eax",0xffffffef);
	&or	("eax","ebx")
&set_label("noluck");
	&pop	("ebx");
	&ret	();
&function_end_B("padlock_capability")

&function_begin_B("padlock_key_bswap");
	&mov	("edx",&wparam(0));
	&mov	("ecx",&DWP(240,"edx"));
&set_label("bswap_loop");
	&mov	("eax",&DWP(0,"edx"));
	&bswap	("eax");
	&mov	(&DWP(0,"edx"),"eax");
	&lea	("edx",&DWP(4,"edx"));
	&sub	("ecx",1);
	&jnz	(&label("bswap_loop"));
	&ret	();
&function_end_B("padlock_key_bswap");

# This is heuristic key context tracing. At first one
# believes that one should use atomic swap instructions,
# but it's not actually necessary. Point is that if
# padlock_saved_context was changed by another thread
# after we've read it and before we compare it with ctx,
# our key *shall* be reloaded upon thread context switch
# and we are therefore set in either case...
&static_label("padlock_saved_context");

&function_begin_B("padlock_verify_context");
	&mov	($ctx,&wparam(0));
	&lea	("eax",($::win32 or $::coff) ? &DWP(&label("padlock_saved_context")) :
		       &DWP(&label("padlock_saved_context")."-".&label("verify_pic_point")));
	&pushf	();
	&call	("_padlock_verify_ctx");
&set_label("verify_pic_point");
	&lea	("esp",&DWP(4,"esp"));
	&ret	();
&function_end_B("padlock_verify_context");

&function_begin_B("_padlock_verify_ctx");
	&add	("eax",&DWP(0,"esp")) if(!($::win32 or $::coff));# &padlock_saved_context
	&bt	(&DWP(4,"esp"),30);		# eflags
	&jnc	(&label("verified"));
	&cmp	($ctx,&DWP(0,"eax"));
	&je	(&label("verified"));
	&pushf	();
	&popf	();
&set_label("verified");
	&mov	(&DWP(0,"eax"),$ctx);
	&ret	();
&function_end_B("_padlock_verify_ctx");

&function_begin_B("padlock_reload_key");
	&pushf	();
	&popf	();
	&ret	();
&function_end_B("padlock_reload_key");

&function_begin_B("padlock_aes_block");
	&push	("edi");
	&push	("esi");
	&push	("ebx");
	&mov	($out,&wparam(0));		# must be 16-byte aligned
	&mov	($inp,&wparam(1));		# must be 16-byte aligned
	&mov	($ctx,&wparam(2));
	&mov	($len,1);
	&lea	("ebx",&DWP(32,$ctx));		# key
	&lea	($ctx,&DWP(16,$ctx));		# control word
	&data_byte(0xf3,0x0f,0xa7,0xc8);	# rep xcryptecb
	&pop	("ebx");
	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_aes_block");

sub generate_mode {
my ($mode,$opcode) = @_;
# int padlock_$mode_encrypt(void *out, const void *inp,
#		struct padlock_cipher_data *ctx, size_t len);
&function_begin("padlock_${mode}_encrypt");
	&mov	($out,&wparam(0));
	&mov	($inp,&wparam(1));
	&mov	($ctx,&wparam(2));
	&mov	($len,&wparam(3));
	&test	($ctx,15);
	&jnz	(&label("${mode}_abort"));
	&test	($len,15);
	&jnz	(&label("${mode}_abort"));
	&lea	("eax",($::win32 or $::coff) ? &DWP(&label("padlock_saved_context")) :
		       &DWP(&label("padlock_saved_context")."-".&label("${mode}_pic_point")));
	&pushf	();
	&cld	();
	&call	("_padlock_verify_ctx");
&set_label("${mode}_pic_point");
	&lea	($ctx,&DWP(16,$ctx));	# control word
	&xor	("eax","eax");
					if ($mode eq "ctr32") {
	&movq	("mm0",&QWP(-16,$ctx));	# load [upper part of] counter
					} else {
	&xor	("ebx","ebx");
    if ($PADLOCK_MARGIN{$mode}) {
	&cmp	($len,$PADLOCK_MARGIN{$mode});
	&jbe	(&label("${mode}_short"));
    }
	&test	(&DWP(0,$ctx),1<<5);	# align bit in control word
	&jnz	(&label("${mode}_aligned"));
	&test	($out,0x0f);
	&setz	("al");			# !out_misaligned
	&test	($inp,0x0f);
	&setz	("bl");			# !inp_misaligned
	&test	("eax","ebx");
	&jnz	(&label("${mode}_aligned"));
	&neg	("eax");
					}
	&mov	($chunk,$PADLOCK_CHUNK);
	&not	("eax");		# out_misaligned?-1:0
	&lea	("ebp",&DWP(-24,"esp"));
	&cmp	($len,$chunk);
	&cmovc	($chunk,$len);		# chunk=len>PADLOCK_CHUNK?PADLOCK_CHUNK:len
	&and	("eax",$chunk);		# out_misaligned?chunk:0
	&mov	($chunk,$len);
	&neg	("eax");
	&and	($chunk,$PADLOCK_CHUNK-1);	# chunk=len%PADLOCK_CHUNK
	&lea	("esp",&DWP(0,"eax","ebp"));	# alloca
	&and	("esp",-16);
	&jmp	(&label("${mode}_loop"));

&set_label("${mode}_loop",16);
	&mov	(&DWP(0,"ebp"),$out);		# save parameters
	&mov	(&DWP(4,"ebp"),$inp);
	&mov	(&DWP(8,"ebp"),$len);
	&mov	($len,$chunk);
	&mov	(&DWP(12,"ebp"),$chunk);	# chunk
						if ($mode eq "ctr32") {
	&mov	("ecx",&DWP(-4,$ctx));
	&xor	($out,$out);
	&mov	("eax",&DWP(-8,$ctx));		# borrow $len
&set_label("${mode}_prepare");
	&mov	(&DWP(12,"esp",$out),"ecx");
	&bswap	("ecx");
	&movq	(&QWP(0,"esp",$out),"mm0");
	&inc	("ecx");
	&mov	(&DWP(8,"esp",$out),"eax");
	&bswap	("ecx");
	&lea	($out,&DWP(16,$out));
	&cmp	($out,$chunk);
	&jb	(&label("${mode}_prepare"));

	&mov	(&DWP(-4,$ctx),"ecx");
	&lea	($inp,&DWP(0,"esp"));
	&lea	($out,&DWP(0,"esp"));
	&mov	($len,$chunk);
						} else {
	&test	($out,0x0f);			# out_misaligned
	&cmovnz	($out,"esp");
	&test	($inp,0x0f);			# inp_misaligned
	&jz	(&label("${mode}_inp_aligned"));
	&shr	($len,2);
	&data_byte(0xf3,0xa5);			# rep movsl
	&sub	($out,$chunk);
	&mov	($len,$chunk);
	&mov	($inp,$out);
&set_label("${mode}_inp_aligned");
						}
	&lea	("eax",&DWP(-16,$ctx));		# ivp
	&lea	("ebx",&DWP(16,$ctx));		# key
	&shr	($len,4);			# len/=AES_BLOCK_SIZE
	&data_byte(0xf3,0x0f,0xa7,$opcode);	# rep xcrypt*
						if ($mode !~ /ecb|ctr/) {
	&movaps	("xmm0",&QWP(0,"eax"));
	&movaps	(&QWP(-16,$ctx),"xmm0");	# copy [or refresh] iv
						}
	&mov	($out,&DWP(0,"ebp"));		# restore parameters
	&mov	($chunk,&DWP(12,"ebp"));
						if ($mode eq "ctr32") {
	&mov	($inp,&DWP(4,"ebp"));
	&xor	($len,$len);
&set_label("${mode}_xor");
	&movups	("xmm1",&QWP(0,$inp,$len));
	&lea	($len,&DWP(16,$len));
	&pxor	("xmm1",&QWP(-16,"esp",$len));
	&movups	(&QWP(-16,$out,$len),"xmm1");
	&cmp	($len,$chunk);
	&jb	(&label("${mode}_xor"));
						} else {
	&test	($out,0x0f);
	&jz	(&label("${mode}_out_aligned"));
	&mov	($len,$chunk);
	&shr	($len,2);
	&lea	($inp,&DWP(0,"esp"));
	&data_byte(0xf3,0xa5);			# rep movsl
	&sub	($out,$chunk);
&set_label("${mode}_out_aligned");
	&mov	($inp,&DWP(4,"ebp"));
						}
	&mov	($len,&DWP(8,"ebp"));
	&add	($out,$chunk);
	&add	($inp,$chunk);
	&sub	($len,$chunk);
	&mov	($chunk,$PADLOCK_CHUNK);
	&jnz	(&label("${mode}_loop"));
						if ($mode ne "ctr32") {
	&cmp	("esp","ebp");
	&je	(&label("${mode}_done"));
						}
	&pxor	("xmm0","xmm0");
	&lea	("eax",&DWP(0,"esp"));
&set_label("${mode}_bzero");
	&movaps	(&QWP(0,"eax"),"xmm0");
	&lea	("eax",&DWP(16,"eax"));
	&cmp	("ebp","eax");
	&ja	(&label("${mode}_bzero"));

&set_label("${mode}_done");
	&lea	("esp",&DWP(24,"ebp"));
						if ($mode ne "ctr32") {
	&jmp	(&label("${mode}_exit"));

&set_label("${mode}_short",16);
	&xor	("eax","eax");
	&lea	("ebp",&DWP(-24,"esp"));
	&sub	("eax",$len);
	&lea	("esp",&DWP(0,"eax","ebp"));
	&and	("esp",-16);
	&xor	($chunk,$chunk);
&set_label("${mode}_short_copy");
	&movups	("xmm0",&QWP(0,$inp,$chunk));
	&lea	($chunk,&DWP(16,$chunk));
	&cmp	($len,$chunk);
	&movaps	(&QWP(-16,"esp",$chunk),"xmm0");
	&ja	(&label("${mode}_short_copy"));
	&mov	($inp,"esp");
	&mov	($chunk,$len);
	&jmp	(&label("${mode}_loop"));

&set_label("${mode}_aligned",16);
	&lea	("eax",&DWP(-16,$ctx));		# ivp
	&lea	("ebx",&DWP(16,$ctx));		# key
	&shr	($len,4);			# len/=AES_BLOCK_SIZE
	&data_byte(0xf3,0x0f,0xa7,$opcode);	# rep xcrypt*
						if ($mode ne "ecb") {
	&movaps	("xmm0",&QWP(0,"eax"));
	&movaps	(&QWP(-16,$ctx),"xmm0");	# copy [or refresh] iv
						}
&set_label("${mode}_exit");			}
	&mov	("eax",1);
	&lea	("esp",&DWP(4,"esp"));		# popf
	&emms	()				if ($mode eq "ctr32");
&set_label("${mode}_abort");
&function_end("padlock_${mode}_encrypt");
}

&generate_mode("ecb",0xc8);
&generate_mode("cbc",0xd0);
&generate_mode("cfb",0xe0);
&generate_mode("ofb",0xe8);
&generate_mode("ctr32",0xc8);	# yes, it implements own CTR with ECB opcode,
				# because hardware CTR was introduced later
				# and even has errata on certain C7 stepping.
				# own implementation *always* works, though
				# ~15% slower than dedicated hardware...

&function_begin_B("padlock_xstore");
	&push	("edi");
	&mov	("edi",&wparam(0));
	&mov	("edx",&wparam(1));
	&data_byte(0x0f,0xa7,0xc0);		# xstore
	&pop	("edi");
	&ret	();
&function_end_B("padlock_xstore");

&function_begin_B("_win32_segv_handler");
	&mov	("eax",1);			# ExceptionContinueSearch
	&mov	("edx",&wparam(0));		# *ExceptionRecord
	&mov	("ecx",&wparam(2));		# *ContextRecord
	&cmp	(&DWP(0,"edx"),0xC0000005)	# ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION
	&jne	(&label("ret"));
	&add	(&DWP(184,"ecx"),4);		# skip over rep sha*
	&mov	("eax",0);			# ExceptionContinueExecution
&set_label("ret");
	&ret	();
&function_end_B("_win32_segv_handler");
&safeseh("_win32_segv_handler")			if ($::win32);

&function_begin_B("padlock_sha1_oneshot");
	&push	("edi");
	&push	("esi");
	&xor	("eax","eax");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
    if ($::win32 or $::coff) {
    	&push	(&::islabel("_win32_segv_handler"));
	&data_byte(0x64,0xff,0x30);		# push	%fs:(%eax)
	&data_byte(0x64,0x89,0x20);		# mov	%esp,%fs:(%eax)
    }
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);			# 32 is enough but spec says 128
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&mov	("eax",&DWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&mov	(&DWP(16,"esp"),"eax");
	&xor	("eax","eax");
	&data_byte(0xf3,0x0f,0xa6,0xc8);	# rep xsha1
	&movaps	("xmm0",&QWP(0,"esp"));
	&mov	("eax",&DWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
    if ($::win32 or $::coff) {
	&data_byte(0x64,0x8f,0x05,0,0,0,0);	# pop	%fs:0
	&lea	("esp",&DWP(4,"esp"));
    }
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&mov	(&DWP(16,"edi"),"eax");
	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_sha1_oneshot");

&function_begin_B("padlock_sha1_blocks");
	&push	("edi");
	&push	("esi");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("edx","esp");			# put aside %esp
	&mov	("ecx",&wparam(2));
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&mov	("eax",&DWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&mov	(&DWP(16,"esp"),"eax");
	&mov	("eax",-1);
	&data_byte(0xf3,0x0f,0xa6,0xc8);	# rep xsha1
	&movaps	("xmm0",&QWP(0,"esp"));
	&mov	("eax",&DWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&mov	(&DWP(16,"edi"),"eax");
 	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_sha1_blocks");

&function_begin_B("padlock_sha256_oneshot");
	&push	("edi");
	&push	("esi");
	&xor	("eax","eax");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
    if ($::win32 or $::coff) {
    	&push	(&::islabel("_win32_segv_handler"));
	&data_byte(0x64,0xff,0x30);		# push	%fs:(%eax)
	&data_byte(0x64,0x89,0x20);		# mov	%esp,%fs:(%eax)
    }
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&movups	("xmm1",&QWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&movaps	(&QWP(16,"esp"),"xmm1");
	&xor	("eax","eax");
	&data_byte(0xf3,0x0f,0xa6,0xd0);	# rep xsha256
	&movaps	("xmm0",&QWP(0,"esp"));
	&movaps	("xmm1",&QWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
    if ($::win32 or $::coff) {
	&data_byte(0x64,0x8f,0x05,0,0,0,0);	# pop	%fs:0
	&lea	("esp",&DWP(4,"esp"));
    }
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&movups	(&QWP(16,"edi"),"xmm1");
	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_sha256_oneshot");

&function_begin_B("padlock_sha256_blocks");
	&push	("edi");
	&push	("esi");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&movups	("xmm1",&QWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&movaps	(&QWP(16,"esp"),"xmm1");
	&mov	("eax",-1);
	&data_byte(0xf3,0x0f,0xa6,0xd0);	# rep xsha256
	&movaps	("xmm0",&QWP(0,"esp"));
	&movaps	("xmm1",&QWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&movups	(&QWP(16,"edi"),"xmm1");
	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_sha256_blocks");

&function_begin_B("padlock_sha512_blocks");
	&push	("edi");
	&push	("esi");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&movups	("xmm1",&QWP(16,"edi"));
	&movups	("xmm2",&QWP(32,"edi"));
	&movups	("xmm3",&QWP(48,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&movaps	(&QWP(16,"esp"),"xmm1");
	&movaps	(&QWP(32,"esp"),"xmm2");
	&movaps	(&QWP(48,"esp"),"xmm3");
	&data_byte(0xf3,0x0f,0xa6,0xe0);	# rep xsha512
	&movaps	("xmm0",&QWP(0,"esp"));
	&movaps	("xmm1",&QWP(16,"esp"));
	&movaps	("xmm2",&QWP(32,"esp"));
	&movaps	("xmm3",&QWP(48,"esp"));
	&mov	("esp","edx");			# restore %esp
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&movups	(&QWP(16,"edi"),"xmm1");
	&movups	(&QWP(32,"edi"),"xmm2");
	&movups	(&QWP(48,"edi"),"xmm3");
	&pop	("esi");
	&pop	("edi");
	&ret	();
&function_end_B("padlock_sha512_blocks");

&asciz	("VIA Padlock x86 module, CRYPTOGAMS by <appro\@openssl.org>");
&align	(16);

&dataseg();
# Essentially this variable belongs in thread local storage.
# Having this variable global on the other hand can only cause
# few bogus key reloads [if any at all on signle-CPU system],
# so we accept the penalty...
&set_label("padlock_saved_context",4);
&data_word(0);

&asm_finish();
