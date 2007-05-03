#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# AES for s390x.

# April 2007.
#
# Software performance improvement over gcc-generated code is ~70% and
# in absolute terms is ~73 cycles per byte processed with 128-bit key.
# You're likely to exclaim "why so slow?" Keep in mind that z-CPUs are
# *strictly* in-order execution and issued instruction [in this case
# load value from memory is critical] has to complete before execution
# flow proceeds. S-boxes are compressed to 2KB.
#
# As for hardware acceleration support. It's basically a "teaser," as
# it can and should be improved in several ways. Most notably support
# for CBC is not utilized, nor multiple blocks are ever processed.
# Then software key schedule can be postponed till hardware support
# detection... Performance improvement over assembler is reportedly
# ~2.5x, but can reach >8x [naturally on larger chunks] if proper
# support is implemented.

$t1="%r0";
$t2="%r1";
$t3="%r2";	$inp="%r2";
$out="%r3";	$mask="%r3";
$key="%r4";
$i1="%r5";
$i2="%r6";
$i3="%r7";
$s0="%r8";
$s1="%r9";
$s2="%r10";
$s3="%r11";
$tbl="%r12";
$rounds="%r13";
$ra="%r14";
$sp="%r15";

sub _data_word()
{ my $i;
    while(defined($i=shift)) { $code.=sprintf".long\t0x%08x,0x%08x\n",$i,$i; }
}

$code=<<___;
.text

.type	AES_Te,\@object
.align	64
AES_Te:
___
&_data_word(
	0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
	0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
	0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
	0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
	0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87,
	0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
	0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea,
	0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
	0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a,
	0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
	0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108,
	0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
	0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e,
	0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
	0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d,
	0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
	0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e,
	0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
	0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce,
	0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
	0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c,
	0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
	0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b,
	0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
	0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16,
	0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
	0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81,
	0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
	0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a,
	0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
	0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163,
	0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
	0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f,
	0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
	0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47,
	0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
	0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f,
	0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
	0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c,
	0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
	0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e,
	0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
	0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6,
	0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
	0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7,
	0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
	0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25,
	0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
	0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72,
	0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
	0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21,
	0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
	0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa,
	0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
	0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0,
	0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
	0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133,
	0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
	0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920,
	0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
	0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17,
	0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
	0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11,
	0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a);
$code.=<<___;
.size	AES_Te,.-AES_Te

# void AES_encrypt(const unsigned char *in, unsigned char *out,
# 		 const AES_KEY *key) {
.globl	AES_encrypt
.type	AES_encrypt,\@function
AES_encrypt:
	lghi	%r0,10
	c	%r0,240($key)
	jne	.Lesoft
	lghi	%r0,0		# query capability vector
	la	%r1,16($sp)
	.long	0xb92e0042	# km %r4,%r2
	lg	%r0,16($sp)
	tmhl	%r0,`0x8000>>2`
	jz	.Lesoft
	lghi	%r0,`0x00|0x12`	# encrypt AES-128
	la	%r1,0($key)
	la	%r2,0($inp)
	la	%r4,0($out)
	lghi	%r3,16		# single block length
	.long	0xb92e0042	# km %r4,%r2
	bcr	8,%r14
.Lesoft:
	stmg	%r3,%r15,24($sp)

	bras	$tbl,.Lepic
.Lepic:	aghi	$tbl,AES_Te-.Lepic

	llgf	$s0,0($inp)
	llgf	$s1,4($inp)
	llgf	$s2,8($inp)
	llgf	$s3,12($inp)

	llill	$mask,`0xff<<3`
	bras	$ra,_s390x_AES_encrypt

	lg	$out,24($sp)
	st	$s0,0($out)
	st	$s1,4($out)
	st	$s2,8($out)
	st	$s3,12($out)

	lmg	%r6,%r15,48($sp)
	br	%r14
.size	AES_encrypt,.-AES_encrypt

.type   _s390x_AES_encrypt,\@function
.align	16
_s390x_AES_encrypt:
	x	$s0,0($key)
	x	$s1,4($key)
	x	$s2,8($key)
	x	$s3,12($key)
	l	$rounds,240($key)
	aghi	$rounds,-1

.Lenc_loop:
	sllg	$i1,$s0,`0+3`
	srlg	$i2,$s0,`8-3`
	srlg	$i3,$s0,`16-3`
	srl	$s0,`24-3`
	nr	$s0,$mask
	ngr	$i1,$mask
	nr	$i2,$mask
	nr	$i3,$mask
	l	$s0,0($s0,$tbl)	# Te0[s0>>24]
	l	$t1,1($i1,$tbl)	# Te3[s0>>0]
	l	$t2,2($i2,$tbl)	# Te2[s0>>8]
	l	$t3,3($i3,$tbl)	# Te1[s0>>16]

	srlg	$i1,$s1,`16-3`	# i0
	sllg	$i2,$s1,`0+3`
	srlg	$i3,$s1,`8-3`
	srl	$s1,`24-3`
	nr	$i1,$mask
	nr	$s1,$mask
	ngr	$i2,$mask
	nr	$i3,$mask
	x	$s0,3($i1,$tbl)	# Te1[s1>>16]
	l	$s1,0($s1,$tbl)	# Te0[s1>>24]
	x	$t2,1($i2,$tbl)	# Te3[s1>>0]
	x	$t3,2($i3,$tbl)	# Te2[s1>>8]
	xr	$s1,$t1

	srlg	$i1,$s2,`8-3`	# i0
	srlg	$i2,$s2,`16-3`	# i1
	sllg	$i3,$s2,`0+3`
	srl	$s2,`24-3`
	nr	$i1,$mask
	nr	$i2,$mask
	nr	$s2,$mask
	ngr	$i3,$mask
	x	$s0,2($i1,$tbl)	# Te2[s2>>8]
	x	$s1,3($i2,$tbl)	# Te1[s2>>16]
	l	$s2,0($s2,$tbl)	# Te0[s2>>24]
	x	$t3,1($i3,$tbl)	# Te3[s2>>0]
	xr	$s2,$t2

	sllg	$i1,$s3,`0+3`	# i0
	srlg	$i2,$s3,`8-3`	# i1
	srlg	$i3,$s3,`16-3`	# i2
	srl	$s3,`24-3`
	ngr	$i1,$mask
	nr	$i2,$mask
	nr	$i3,$mask
	nr	$s3,$mask
	x	$s0,1($i1,$tbl)	# Te3[s3>>0]
	x	$s1,2($i2,$tbl)	# Te2[s3>>8]
	x	$s2,3($i3,$tbl)	# Te1[s3>>16]
	l	$s3,0($s3,$tbl)	# Te0[s3>>24]
	xr	$s3,$t3

	la	$key,16($key)
	x	$s0,0($key)
	x	$s1,4($key)
	x	$s2,8($key)
	x	$s3,12($key)

	brct	$rounds,.Lenc_loop

	sllg	$i1,$s0,`0+3`
	srlg	$i2,$s0,`8-3`
	srlg	$i3,$s0,`16-3`
	srl	$s0,`24-3`
	nr	$s0,$mask
	ngr	$i1,$mask
	nr	$i2,$mask
	nr	$i3,$mask
	llgc	$s0,2($s0,$tbl)	# Te4[s0>>24]
	llgc	$t1,2($i1,$tbl)	# Te4[s0>>0]
	llgc	$t2,2($i2,$tbl)	# Te4[s0>>8]
	llgc	$t3,2($i3,$tbl)	# Te4[s0>>16]
	sll	$s0,24
	sll	$t2,8
	sll	$t3,16

	srlg	$i1,$s1,`16-3`	# i0
	sllg	$i2,$s1,`0+3`
	srlg	$i3,$s1,`8-3`
	srl	$s1,`24-3`
	nr	$i1,$mask
	nr	$s1,$mask
	ngr	$i2,$mask
	nr	$i3,$mask
	llgc	$i1,2($i1,$tbl)	# Te4[s1>>16]
	llgc	$s1,2($s1,$tbl)	# Te4[s1>>24]
	llgc	$i2,2($i2,$tbl)	# Te4[s1>>0]
	llgc	$i3,2($i3,$tbl)	# Te4[s1>>8]
	sll	$i1,16
	sll	$s1,24
	sll	$i3,8
	or	$s0,$i1
	or	$s1,$t1
	or	$t2,$i2
	or	$t3,$i3
	
	srlg	$i1,$s2,`8-3`	# i0
	srlg	$i2,$s2,`16-3`	# i1
	sllg	$i3,$s2,`0+3`
	srl	$s2,`24-3`
	nr	$i1,$mask
	nr	$i2,$mask
	nr	$s2,$mask
	ngr	$i3,$mask
	llgc	$i1,2($i1,$tbl)	# Te4[s2>>8]
	llgc	$i2,2($i2,$tbl)	# Te4[s2>>16]
	llgc	$s2,2($s2,$tbl)	# Te4[s2>>24]
	llgc	$i3,2($i3,$tbl)	# Te4[s2>>0]
	sll	$i1,8
	sll	$i2,16
	sll	$s2,24
	or	$s0,$i1
	or	$s1,$i2
	or	$s2,$t2
	or	$t3,$i3

	sllg	$i1,$s3,`0+3`	# i0
	srlg	$i2,$s3,`8-3`	# i1
	srlg	$i3,$s3,`16-3`	# i2
	srl	$s3,`24-3`
	ngr	$i1,$mask
	nr	$i2,$mask
	nr	$i3,$mask
	nr	$s3,$mask
	llgc	$i1,2($i1,$tbl)	# Te4[s3>>0]
	llgc	$i2,2($i2,$tbl)	# Te4[s3>>8]
	llgc	$i3,2($i3,$tbl)	# Te4[s3>>16]
	llgc	$s3,2($s3,$tbl)	# Te4[s3>>24]
	sll	$i2,8
	sll	$i3,16
	sll	$s3,24
	or	$s0,$i1
	or	$s1,$i2
	or	$s2,$i3
	or	$s3,$t3

	x	$s0,16($key)
	x	$s1,20($key)
	x	$s2,24($key)
	x	$s3,28($key)

	br	$ra	
.size	_s390x_AES_encrypt,.-_s390x_AES_encrypt
___

$code.=<<___;
.type	AES_Td,\@object
.align	64
AES_Td:
___
&_data_word(
	0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96,
	0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393,
	0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25,
	0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f,
	0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1,
	0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6,
	0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da,
	0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844,
	0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd,
	0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4,
	0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45,
	0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94,
	0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7,
	0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a,
	0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5,
	0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c,
	0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1,
	0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a,
	0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75,
	0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051,
	0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46,
	0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff,
	0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77,
	0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb,
	0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000,
	0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e,
	0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927,
	0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a,
	0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e,
	0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16,
	0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d,
	0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8,
	0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd,
	0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34,
	0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163,
	0xd731dcca, 0x42638510, 0x13972240, 0x84c61120,
	0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d,
	0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0,
	0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422,
	0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef,
	0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36,
	0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4,
	0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662,
	0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5,
	0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3,
	0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b,
	0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8,
	0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6,
	0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6,
	0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0,
	0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815,
	0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f,
	0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df,
	0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f,
	0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e,
	0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713,
	0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89,
	0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c,
	0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf,
	0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86,
	0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f,
	0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541,
	0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190,
	0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742);
$code.=<<___;
.byte	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38
.byte	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
.byte	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87
.byte	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
.byte	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d
.byte	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
.byte	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2
.byte	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
.byte	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16
.byte	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
.byte	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda
.byte	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
.byte	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a
.byte	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
.byte	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02
.byte	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
.byte	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea
.byte	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
.byte	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85
.byte	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
.byte	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89
.byte	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
.byte	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20
.byte	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
.byte	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31
.byte	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
.byte	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d
.byte	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
.byte	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0
.byte	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
.byte	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26
.byte	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
.size	AES_Td,.-AES_Td

# void AES_decrypt(const unsigned char *in, unsigned char *out,
# 		 const AES_KEY *key) {
.globl	AES_decrypt
.type	AES_decrypt,\@function
AES_decrypt:
	lghi	%r0,10
	c	%r0,240($key)
	jne	.Ldsoft
	lghi	%r0,0		# query capability vector
	la	%r1,16($sp)
	.long	0xb92e0042	# km %r4,%r2
	lg	%r0,16($sp)
	tmhl	%r0,`0x8000>>2`
	jz	.Ldsoft
	lghi	%r0,`0x80|0x12`	# decrypt AES-128
	la	%r1,160($key)
	la	%r2,0($inp)
	la	%r4,0($out)
	lghi	%r3,16		# single block length
	.long	0xb92e0042	# km %r4,%r2
	bcr	8,%r14
.Ldsoft:
	stmg	%r3,%r15,24($sp)

	bras	$tbl,.Ldpic
.Ldpic:	aghi	$tbl,AES_Td-.Ldpic

	llgf	$s0,0($inp)
	llgf	$s1,4($inp)
	llgf	$s2,8($inp)
	llgf	$s3,12($inp)

	llill	$mask,`0xff<<3`
	bras	$ra,_s390x_AES_decrypt

	lg	$out,24($sp)
	st	$s0,0($out)
	st	$s1,4($out)
	st	$s2,8($out)
	st	$s3,12($out)

	lmg	%r6,%r15,48($sp)
	br	%r14
.size	AES_decrypt,.-AES_decrypt

.type   _s390x_AES_decrypt,\@function
.align	16
_s390x_AES_decrypt:
	x	$s0,0($key)
	x	$s1,4($key)
	x	$s2,8($key)
	x	$s3,12($key)
	l	$rounds,240($key)
	aghi	$rounds,-1

.Ldec_loop:
	srlg	$i1,$s0,`16-3`
	srlg	$i2,$s0,`8-3`
	sllg	$i3,$s0,`0+3`
	srl	$s0,`24-3`
	nr	$s0,$mask
	nr	$i1,$mask
	nr	$i2,$mask
	ngr	$i3,$mask
	l	$s0,0($s0,$tbl)	# Td0[s0>>24]
	l	$t1,3($i1,$tbl)	# Td1[s0>>16]
	l	$t2,2($i2,$tbl)	# Td2[s0>>8]
	l	$t3,1($i3,$tbl)	# Td3[s0>>0]

	sllg	$i1,$s1,`0+3`	# i0
	srlg	$i2,$s1,`16-3`
	srlg	$i3,$s1,`8-3`
	srl	$s1,`24-3`
	ngr	$i1,$mask
	nr	$s1,$mask
	nr	$i2,$mask
	nr	$i3,$mask
	x	$s0,1($i1,$tbl)	# Td3[s1>>0]
	l	$s1,0($s1,$tbl)	# Td0[s1>>24]
	x	$t2,3($i2,$tbl)	# Td1[s1>>16]
	x	$t3,2($i3,$tbl)	# Td2[s1>>8]
	xr	$s1,$t1

	srlg	$i1,$s2,`8-3`	# i0
	sllg	$i2,$s2,`0+3`	# i1
	srlg	$i3,$s2,`16-3`
	srl	$s2,`24-3`
	nr	$i1,$mask
	ngr	$i2,$mask
	nr	$s2,$mask
	nr	$i3,$mask
	x	$s0,2($i1,$tbl)	# Td2[s2>>8]
	x	$s1,1($i2,$tbl)	# Td3[s2>>0]
	l	$s2,0($s2,$tbl)	# Td0[s2>>24]
	x	$t3,3($i3,$tbl)	# Td1[s2>>16]
	xr	$s2,$t2

	srlg	$i1,$s3,`16-3`	# i0
	srlg	$i2,$s3,`8-3`	# i1
	sllg	$i3,$s3,`0+3`	# i2
	srl	$s3,`24-3`
	nr	$i1,$mask
	nr	$i2,$mask
	ngr	$i3,$mask
	nr	$s3,$mask
	x	$s0,3($i1,$tbl)	# Td1[s3>>16]
	x	$s1,2($i2,$tbl)	# Td2[s3>>8]
	x	$s2,1($i3,$tbl)	# Td3[s3>>0]
	l	$s3,0($s3,$tbl)	# Td0[s3>>24]
	xr	$s3,$t3

	la	$key,16($key)
	x	$s0,0($key)
	x	$s1,4($key)
	x	$s2,8($key)
	x	$s3,12($key)

	brct	$rounds,.Ldec_loop

	l	$t1,`2048+0`($tbl)	# prefetch Td4
	l	$t2,`2048+32`($tbl)
	l	$t3,`2048+64`($tbl)
	l	$i1,`2048+96`($tbl)
	l	$i2,`2048+128`($tbl)
	l	$i3,`2048+160`($tbl)
	l	$t1,`2048+192`($tbl)
	l	$t2,`2048+224`($tbl)
	llill	$mask,0xff

	srlg	$i3,$s0,24	# i0
	srlg	$i1,$s0,16
	srlg	$i2,$s0,8
	nr	$s0,$mask	# i3
	nr	$i1,$mask
	nr	$i2,$mask
	llgc	$i3,2048($i3,$tbl)	# Td4[s0>>24]
	llgc	$t1,2048($i1,$tbl)	# Td4[s0>>16]
	llgc	$t2,2048($i2,$tbl)	# Td4[s0>>8]
	llgc	$t3,2048($s0,$tbl)	# Td4[s0>>0]
	sllg	$s0,$i3,24
	sll	$t1,16
	sll	$t2,8

	srlg	$i1,$s1,24
	srlg	$i2,$s1,16
	srlg	$i3,$s1,8
	nr	$s1,$mask	# i0
	nr	$i2,$mask
	nr	$i3,$mask
	llgc	$s1,2048($s1,$tbl)	# Td4[s1>>0]
	llgc	$i1,2048($i1,$tbl)	# Td4[s1>>24]
	llgc	$i2,2048($i2,$tbl)	# Td4[s1>>16]
	llgc	$i3,2048($i3,$tbl)	# Td4[s1>>8]
	sll	$i1,24
	sll	$i2,16
	sll	$i3,8
	or	$s0,$s1
	or	$t1,$i1
	or	$t2,$i2
	or	$t3,$i3

	srlg	$i1,$s2,8	# i0
	srlg	$i2,$s2,24
	srlg	$i3,$s2,16
	nr	$s2,$mask	# i1
	nr	$i1,$mask
	nr	$i3,$mask
	llgc	$i1,2048($i1,$tbl)	# Td4[s2>>8]
	llgc	$s1,2048($s2,$tbl)	# Td4[s2>>0]
	llgc	$i2,2048($i2,$tbl)	# Td4[s2>>24]
	llgc	$i3,2048($i3,$tbl)	# Td4[s2>>16]
	sll	$i1,8
	sll	$i2,24
	sll	$i3,16
	or	$s0,$i1
	or	$s1,$t1
	or	$t2,$i2
	or	$t3,$i3

	srlg	$i1,$s3,16	# i0
	srlg	$i2,$s3,8	# i1
	srlg	$i3,$s3,24
	nr	$s3,$mask	# i2
	nr	$i1,$mask
	nr	$i2,$mask
	llgc	$i1,2048($i1,$tbl)	# Td4[s3>>16]
	llgc	$i2,2048($i2,$tbl)	# Td4[s3>>8]
	llgc	$s2,2048($s3,$tbl)	# Td4[s3>>0]
	llgc	$s3,2048($i3,$tbl)	# Td4[s3>>24]
	sll	$i1,16
	sll	$i2,8
	sll	$s3,24
	or	$s0,$i1
	or	$s1,$i2
	or	$s2,$t2
	or	$s3,$t3

	x	$s0,16($key)
	x	$s1,20($key)
	x	$s2,24($key)
	x	$s3,28($key)

	br	$ra	
.size	_s390x_AES_decrypt,.-_s390x_AES_decrypt
.string	"AES for s390x, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
