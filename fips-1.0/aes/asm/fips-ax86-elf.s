





	.file	"aes-586.s"
.globl	AES_Te
.text
.globl	_x86_AES_encrypt
.type	_x86_AES_encrypt,@function
.align	16
_x86_AES_encrypt:
	movl	%edi,		12(%esp)
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	movl	240(%edi),	%esi
	leal	-2(%esi,%esi),	%esi
	leal	(%edi,%esi,8),	%esi
	movl	%esi,		16(%esp)
.align	4
.L000loop:
	movl	%eax,		%esi
	andl	$255,		%esi
	movl	(%ebp,%esi,8),	%esi
	movzbl	%bh,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%ecx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movl	%edx,		%edi
	shrl	$24,		%edi
	xorl	1(%ebp,%edi,8),	%esi
	movl	%esi,		4(%esp)

	movl	%ebx,		%esi
	andl	$255,		%esi
	shrl	$16,		%ebx
	movl	(%ebp,%esi,8),	%esi
	movzbl	%ch,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%edx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movl	%eax,		%edi
	shrl	$24,		%edi
	xorl	1(%ebp,%edi,8),	%esi
	movl	%esi,		8(%esp)

	movl	%ecx,		%esi
	andl	$255,		%esi
	shrl	$24,		%ecx
	movl	(%ebp,%esi,8),	%esi
	movzbl	%dh,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%eax,		%edi
	shrl	$16,		%edi
	andl	$255,		%edx
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movzbl	%bh,		%edi
	xorl	1(%ebp,%edi,8),	%esi

	movl	12(%esp),	%edi
	movl	(%ebp,%edx,8),	%edx
	movzbl	%ah,		%eax
	xorl	3(%ebp,%eax,8),	%edx
	movl	4(%esp),	%eax
	andl	$255,		%ebx
	xorl	2(%ebp,%ebx,8),	%edx
	movl	8(%esp),	%ebx
	xorl	1(%ebp,%ecx,8),	%edx
	movl	%esi,		%ecx

	addl	$16,		%edi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	cmpl	16(%esp),	%edi
	movl	%edi,		12(%esp)
	jb	.L000loop
	movl	%eax,		%esi
	andl	$255,		%esi
	movl	2(%ebp,%esi,8),	%esi
	andl	$255,		%esi
	movzbl	%bh,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%ecx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movl	%edx,		%edi
	shrl	$24,		%edi
	movl	2(%ebp,%edi,8),	%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	%esi,		4(%esp)
	movl	%ebx,		%esi
	andl	$255,		%esi
	shrl	$16,		%ebx
	movl	2(%ebp,%esi,8),	%esi
	andl	$255,		%esi
	movzbl	%ch,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%edx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movl	%eax,		%edi
	shrl	$24,		%edi
	movl	2(%ebp,%edi,8),	%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	%esi,		8(%esp)
	movl	%ecx,		%esi
	andl	$255,		%esi
	shrl	$24,		%ecx
	movl	2(%ebp,%esi,8),	%esi
	andl	$255,		%esi
	movzbl	%dh,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%eax,		%edi
	shrl	$16,		%edi
	andl	$255,		%edx
	andl	$255,		%edi
	movl	(%ebp,%edi,8),	%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movzbl	%bh,		%edi
	movl	2(%ebp,%edi,8),	%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	12(%esp),	%edi
	andl	$255,		%edx
	movl	2(%ebp,%edx,8),	%edx
	andl	$255,		%edx
	movzbl	%ah,		%eax
	movl	(%ebp,%eax,8),	%eax
	andl	$65280,		%eax
	xorl	%eax,		%edx
	movl	4(%esp),	%eax
	andl	$255,		%ebx
	movl	(%ebp,%ebx,8),	%ebx
	andl	$16711680,	%ebx
	xorl	%ebx,		%edx
	movl	8(%esp),	%ebx
	movl	2(%ebp,%ecx,8),	%ecx
	andl	$4278190080,	%ecx
	xorl	%ecx,		%edx
	movl	%esi,		%ecx
	addl	$16,		%edi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	ret
.align	64
AES_Te:
	.long	2774754246,2774754246
	.long	2222750968,2222750968
	.long	2574743534,2574743534
	.long	2373680118,2373680118
	.long	234025727,234025727
	.long	3177933782,3177933782
	.long	2976870366,2976870366
	.long	1422247313,1422247313
	.long	1345335392,1345335392
	.long	50397442,50397442
	.long	2842126286,2842126286
	.long	2099981142,2099981142
	.long	436141799,436141799
	.long	1658312629,1658312629
	.long	3870010189,3870010189
	.long	2591454956,2591454956
	.long	1170918031,1170918031
	.long	2642575903,2642575903
	.long	1086966153,1086966153
	.long	2273148410,2273148410
	.long	368769775,368769775
	.long	3948501426,3948501426
	.long	3376891790,3376891790
	.long	200339707,200339707
	.long	3970805057,3970805057
	.long	1742001331,1742001331
	.long	4255294047,4255294047
	.long	3937382213,3937382213
	.long	3214711843,3214711843
	.long	4154762323,4154762323
	.long	2524082916,2524082916
	.long	1539358875,1539358875
	.long	3266819957,3266819957
	.long	486407649,486407649
	.long	2928907069,2928907069
	.long	1780885068,1780885068
	.long	1513502316,1513502316
	.long	1094664062,1094664062
	.long	49805301,49805301
	.long	1338821763,1338821763
	.long	1546925160,1546925160
	.long	4104496465,4104496465
	.long	887481809,887481809
	.long	150073849,150073849
	.long	2473685474,2473685474
	.long	1943591083,1943591083
	.long	1395732834,1395732834
	.long	1058346282,1058346282
	.long	201589768,201589768
	.long	1388824469,1388824469
	.long	1696801606,1696801606
	.long	1589887901,1589887901
	.long	672667696,672667696
	.long	2711000631,2711000631
	.long	251987210,251987210
	.long	3046808111,3046808111
	.long	151455502,151455502
	.long	907153956,907153956
	.long	2608889883,2608889883
	.long	1038279391,1038279391
	.long	652995533,652995533
	.long	1764173646,1764173646
	.long	3451040383,3451040383
	.long	2675275242,2675275242
	.long	453576978,453576978
	.long	2659418909,2659418909
	.long	1949051992,1949051992
	.long	773462580,773462580
	.long	756751158,756751158
	.long	2993581788,2993581788
	.long	3998898868,3998898868
	.long	4221608027,4221608027
	.long	4132590244,4132590244
	.long	1295727478,1295727478
	.long	1641469623,1641469623
	.long	3467883389,3467883389
	.long	2066295122,2066295122
	.long	1055122397,1055122397
	.long	1898917726,1898917726
	.long	2542044179,2542044179
	.long	4115878822,4115878822
	.long	1758581177,1758581177
	.long	0,0
	.long	753790401,753790401
	.long	1612718144,1612718144
	.long	536673507,536673507
	.long	3367088505,3367088505
	.long	3982187446,3982187446
	.long	3194645204,3194645204
	.long	1187761037,1187761037
	.long	3653156455,3653156455
	.long	1262041458,1262041458
	.long	3729410708,3729410708
	.long	3561770136,3561770136
	.long	3898103984,3898103984
	.long	1255133061,1255133061
	.long	1808847035,1808847035
	.long	720367557,720367557
	.long	3853167183,3853167183
	.long	385612781,385612781
	.long	3309519750,3309519750
	.long	3612167578,3612167578
	.long	1429418854,1429418854
	.long	2491778321,2491778321
	.long	3477423498,3477423498
	.long	284817897,284817897
	.long	100794884,100794884
	.long	2172616702,2172616702
	.long	4031795360,4031795360
	.long	1144798328,1144798328
	.long	3131023141,3131023141
	.long	3819481163,3819481163
	.long	4082192802,4082192802
	.long	4272137053,4272137053
	.long	3225436288,3225436288
	.long	2324664069,2324664069
	.long	2912064063,2912064063
	.long	3164445985,3164445985
	.long	1211644016,1211644016
	.long	83228145,83228145
	.long	3753688163,3753688163
	.long	3249976951,3249976951
	.long	1977277103,1977277103
	.long	1663115586,1663115586
	.long	806359072,806359072
	.long	452984805,452984805
	.long	250868733,250868733
	.long	1842533055,1842533055
	.long	1288555905,1288555905
	.long	336333848,336333848
	.long	890442534,890442534
	.long	804056259,804056259
	.long	3781124030,3781124030
	.long	2727843637,2727843637
	.long	3427026056,3427026056
	.long	957814574,957814574
	.long	1472513171,1472513171
	.long	4071073621,4071073621
	.long	2189328124,2189328124
	.long	1195195770,1195195770
	.long	2892260552,2892260552
	.long	3881655738,3881655738
	.long	723065138,723065138
	.long	2507371494,2507371494
	.long	2690670784,2690670784
	.long	2558624025,2558624025
	.long	3511635870,3511635870
	.long	2145180835,2145180835
	.long	1713513028,1713513028
	.long	2116692564,2116692564
	.long	2878378043,2878378043
	.long	2206763019,2206763019
	.long	3393603212,3393603212
	.long	703524551,703524551
	.long	3552098411,3552098411
	.long	1007948840,1007948840
	.long	2044649127,2044649127
	.long	3797835452,3797835452
	.long	487262998,487262998
	.long	1994120109,1994120109
	.long	1004593371,1004593371
	.long	1446130276,1446130276
	.long	1312438900,1312438900
	.long	503974420,503974420
	.long	3679013266,3679013266
	.long	168166924,168166924
	.long	1814307912,1814307912
	.long	3831258296,3831258296
	.long	1573044895,1573044895
	.long	1859376061,1859376061
	.long	4021070915,4021070915
	.long	2791465668,2791465668
	.long	2828112185,2828112185
	.long	2761266481,2761266481
	.long	937747667,937747667
	.long	2339994098,2339994098
	.long	854058965,854058965
	.long	1137232011,1137232011
	.long	1496790894,1496790894
	.long	3077402074,3077402074
	.long	2358086913,2358086913
	.long	1691735473,1691735473
	.long	3528347292,3528347292
	.long	3769215305,3769215305
	.long	3027004632,3027004632
	.long	4199962284,4199962284
	.long	133494003,133494003
	.long	636152527,636152527
	.long	2942657994,2942657994
	.long	2390391540,2390391540
	.long	3920539207,3920539207
	.long	403179536,403179536
	.long	3585784431,3585784431
	.long	2289596656,2289596656
	.long	1864705354,1864705354
	.long	1915629148,1915629148
	.long	605822008,605822008
	.long	4054230615,4054230615
	.long	3350508659,3350508659
	.long	1371981463,1371981463
	.long	602466507,602466507
	.long	2094914977,2094914977
	.long	2624877800,2624877800
	.long	555687742,555687742
	.long	3712699286,3712699286
	.long	3703422305,3703422305
	.long	2257292045,2257292045
	.long	2240449039,2240449039
	.long	2423288032,2423288032
	.long	1111375484,1111375484
	.long	3300242801,3300242801
	.long	2858837708,2858837708
	.long	3628615824,3628615824
	.long	84083462,84083462
	.long	32962295,32962295
	.long	302911004,302911004
	.long	2741068226,2741068226
	.long	1597322602,1597322602
	.long	4183250862,4183250862
	.long	3501832553,3501832553
	.long	2441512471,2441512471
	.long	1489093017,1489093017
	.long	656219450,656219450
	.long	3114180135,3114180135
	.long	954327513,954327513
	.long	335083755,335083755
	.long	3013122091,3013122091
	.long	856756514,856756514
	.long	3144247762,3144247762
	.long	1893325225,1893325225
	.long	2307821063,2307821063
	.long	2811532339,2811532339
	.long	3063651117,3063651117
	.long	572399164,572399164
	.long	2458355477,2458355477
	.long	552200649,552200649
	.long	1238290055,1238290055
	.long	4283782570,4283782570
	.long	2015897680,2015897680
	.long	2061492133,2061492133
	.long	2408352771,2408352771
	.long	4171342169,4171342169
	.long	2156497161,2156497161
	.long	386731290,386731290
	.long	3669999461,3669999461
	.long	837215959,837215959
	.long	3326231172,3326231172
	.long	3093850320,3093850320
	.long	3275833730,3275833730
	.long	2962856233,2962856233
	.long	1999449434,1999449434
	.long	286199582,286199582
	.long	3417354363,3417354363
	.long	4233385128,4233385128
	.long	3602627437,3602627437
	.long	974525996,974525996
	.long	1,2,4,8
	.long	16,32,64,128
	.long	27,54,0,0,
	.long	0,0,0,0
.L__x86_AES_encrypt_end:
.size	_x86_AES_encrypt,.L__x86_AES_encrypt_end-_x86_AES_encrypt
.ident	"_x86_AES_encrypt"
.globl	AES_Te
.text
.globl	AES_encrypt
.type	AES_encrypt,@function
.align	16
AES_encrypt:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	movl	20(%esp),	%esi
	movl	28(%esp),	%edi
	movl	%esp,		%eax
	subl	$24,		%esp
	andl	$-64,		%esp
	addl	$4,		%esp
	movl	%eax,		16(%esp)
	call	.L001pic_point
.L001pic_point:
	popl	%ebp
	leal	AES_Te-.L001pic_point(%ebp),%ebp
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	call	_x86_AES_encrypt
	movl	16(%esp),	%esp
	movl	24(%esp),	%esi
	movl	%eax,		(%esi)
	movl	%ebx,		4(%esi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_AES_encrypt_end:
.size	AES_encrypt,.L_AES_encrypt_end-AES_encrypt
.ident	"AES_encrypt"
.globl	AES_Td
.text
.globl	_x86_AES_decrypt
.type	_x86_AES_decrypt,@function
.align	16
_x86_AES_decrypt:
	movl	%edi,		12(%esp)
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	movl	240(%edi),	%esi
	leal	-2(%esi,%esi),	%esi
	leal	(%edi,%esi,8),	%esi
	movl	%esi,		16(%esp)
.align	4
.L002loop:
	movl	%eax,		%esi
	andl	$255,		%esi
	movl	(%ebp,%esi,8),	%esi
	movzbl	%dh,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%ecx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movl	%ebx,		%edi
	shrl	$24,		%edi
	xorl	1(%ebp,%edi,8),	%esi
	movl	%esi,		4(%esp)

	movl	%ebx,		%esi
	andl	$255,		%esi
	movl	(%ebp,%esi,8),	%esi
	movzbl	%ah,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%edx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movl	%ecx,		%edi
	shrl	$24,		%edi
	xorl	1(%ebp,%edi,8),	%esi
	movl	%esi,		8(%esp)

	movl	%ecx,		%esi
	andl	$255,		%esi
	movl	(%ebp,%esi,8),	%esi
	movzbl	%bh,		%edi
	xorl	3(%ebp,%edi,8),	%esi
	movl	%eax,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	xorl	2(%ebp,%edi,8),	%esi
	movl	%edx,		%edi
	shrl	$24,		%edi
	xorl	1(%ebp,%edi,8),	%esi

	movl	12(%esp),	%edi
	andl	$255,		%edx
	movl	(%ebp,%edx,8),	%edx
	movzbl	%ch,		%ecx
	xorl	3(%ebp,%ecx,8),	%edx
	movl	%esi,		%ecx
	shrl	$16,		%ebx
	andl	$255,		%ebx
	xorl	2(%ebp,%ebx,8),	%edx
	movl	8(%esp),	%ebx
	shrl	$24,		%eax
	xorl	1(%ebp,%eax,8),	%edx
	movl	4(%esp),	%eax

	addl	$16,		%edi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	cmpl	16(%esp),	%edi
	movl	%edi,		12(%esp)
	jb	.L002loop
	movl	%eax,		%esi
	andl	$255,		%esi
	movl	2048(%ebp,%esi,4),%esi
	andl	$255,		%esi
	movzbl	%dh,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%ecx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movl	%ebx,		%edi
	shrl	$24,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	%esi,		4(%esp)
	movl	%ebx,		%esi
	andl	$255,		%esi
	movl	2048(%ebp,%esi,4),%esi
	andl	$255,		%esi
	movzbl	%ah,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%edx,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movl	%ecx,		%edi
	shrl	$24,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	%esi,		8(%esp)
	movl	%ecx,		%esi
	andl	$255,		%esi
	movl	2048(%ebp,%esi,4),%esi
	andl	$255,		%esi
	movzbl	%bh,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$65280,		%edi
	xorl	%edi,		%esi
	movl	%eax,		%edi
	shrl	$16,		%edi
	andl	$255,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$16711680,	%edi
	xorl	%edi,		%esi
	movl	%edx,		%edi
	shrl	$24,		%edi
	movl	2048(%ebp,%edi,4),%edi
	andl	$4278190080,	%edi
	xorl	%edi,		%esi
	movl	12(%esp),	%edi
	andl	$255,		%edx
	movl	2048(%ebp,%edx,4),%edx
	andl	$255,		%edx
	movzbl	%ch,		%ecx
	movl	2048(%ebp,%ecx,4),%ecx
	andl	$65280,		%ecx
	xorl	%ecx,		%edx
	movl	%esi,		%ecx
	shrl	$16,		%ebx
	andl	$255,		%ebx
	movl	2048(%ebp,%ebx,4),%ebx
	andl	$16711680,	%ebx
	xorl	%ebx,		%edx
	movl	8(%esp),	%ebx
	shrl	$24,		%eax
	movl	2048(%ebp,%eax,4),%eax
	andl	$4278190080,	%eax
	xorl	%eax,		%edx
	movl	4(%esp),	%eax
	addl	$16,		%edi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	ret
.align	64
AES_Td:
	.long	1353184337,1353184337
	.long	1399144830,1399144830
	.long	3282310938,3282310938
	.long	2522752826,2522752826
	.long	3412831035,3412831035
	.long	4047871263,4047871263
	.long	2874735276,2874735276
	.long	2466505547,2466505547
	.long	1442459680,1442459680
	.long	4134368941,4134368941
	.long	2440481928,2440481928
	.long	625738485,625738485
	.long	4242007375,4242007375
	.long	3620416197,3620416197
	.long	2151953702,2151953702
	.long	2409849525,2409849525
	.long	1230680542,1230680542
	.long	1729870373,1729870373
	.long	2551114309,2551114309
	.long	3787521629,3787521629
	.long	41234371,41234371
	.long	317738113,317738113
	.long	2744600205,2744600205
	.long	3338261355,3338261355
	.long	3881799427,3881799427
	.long	2510066197,2510066197
	.long	3950669247,3950669247
	.long	3663286933,3663286933
	.long	763608788,763608788
	.long	3542185048,3542185048
	.long	694804553,694804553
	.long	1154009486,1154009486
	.long	1787413109,1787413109
	.long	2021232372,2021232372
	.long	1799248025,1799248025
	.long	3715217703,3715217703
	.long	3058688446,3058688446
	.long	397248752,397248752
	.long	1722556617,1722556617
	.long	3023752829,3023752829
	.long	407560035,407560035
	.long	2184256229,2184256229
	.long	1613975959,1613975959
	.long	1165972322,1165972322
	.long	3765920945,3765920945
	.long	2226023355,2226023355
	.long	480281086,480281086
	.long	2485848313,2485848313
	.long	1483229296,1483229296
	.long	436028815,436028815
	.long	2272059028,2272059028
	.long	3086515026,3086515026
	.long	601060267,601060267
	.long	3791801202,3791801202
	.long	1468997603,1468997603
	.long	715871590,715871590
	.long	120122290,120122290
	.long	63092015,63092015
	.long	2591802758,2591802758
	.long	2768779219,2768779219
	.long	4068943920,4068943920
	.long	2997206819,2997206819
	.long	3127509762,3127509762
	.long	1552029421,1552029421
	.long	723308426,723308426
	.long	2461301159,2461301159
	.long	4042393587,4042393587
	.long	2715969870,2715969870
	.long	3455375973,3455375973
	.long	3586000134,3586000134
	.long	526529745,526529745
	.long	2331944644,2331944644
	.long	2639474228,2639474228
	.long	2689987490,2689987490
	.long	853641733,853641733
	.long	1978398372,1978398372
	.long	971801355,971801355
	.long	2867814464,2867814464
	.long	111112542,111112542
	.long	1360031421,1360031421
	.long	4186579262,4186579262
	.long	1023860118,1023860118
	.long	2919579357,2919579357
	.long	1186850381,1186850381
	.long	3045938321,3045938321
	.long	90031217,90031217
	.long	1876166148,1876166148
	.long	4279586912,4279586912
	.long	620468249,620468249
	.long	2548678102,2548678102
	.long	3426959497,3426959497
	.long	2006899047,2006899047
	.long	3175278768,3175278768
	.long	2290845959,2290845959
	.long	945494503,945494503
	.long	3689859193,3689859193
	.long	1191869601,1191869601
	.long	3910091388,3910091388
	.long	3374220536,3374220536
	.long	0,0
	.long	2206629897,2206629897
	.long	1223502642,1223502642
	.long	2893025566,2893025566
	.long	1316117100,1316117100
	.long	4227796733,4227796733
	.long	1446544655,1446544655
	.long	517320253,517320253
	.long	658058550,658058550
	.long	1691946762,1691946762
	.long	564550760,564550760
	.long	3511966619,3511966619
	.long	976107044,976107044
	.long	2976320012,2976320012
	.long	266819475,266819475
	.long	3533106868,3533106868
	.long	2660342555,2660342555
	.long	1338359936,1338359936
	.long	2720062561,2720062561
	.long	1766553434,1766553434
	.long	370807324,370807324
	.long	179999714,179999714
	.long	3844776128,3844776128
	.long	1138762300,1138762300
	.long	488053522,488053522
	.long	185403662,185403662
	.long	2915535858,2915535858
	.long	3114841645,3114841645
	.long	3366526484,3366526484
	.long	2233069911,2233069911
	.long	1275557295,1275557295
	.long	3151862254,3151862254
	.long	4250959779,4250959779
	.long	2670068215,2670068215
	.long	3170202204,3170202204
	.long	3309004356,3309004356
	.long	880737115,880737115
	.long	1982415755,1982415755
	.long	3703972811,3703972811
	.long	1761406390,1761406390
	.long	1676797112,1676797112
	.long	3403428311,3403428311
	.long	277177154,277177154
	.long	1076008723,1076008723
	.long	538035844,538035844
	.long	2099530373,2099530373
	.long	4164795346,4164795346
	.long	288553390,288553390
	.long	1839278535,1839278535
	.long	1261411869,1261411869
	.long	4080055004,4080055004
	.long	3964831245,3964831245
	.long	3504587127,3504587127
	.long	1813426987,1813426987
	.long	2579067049,2579067049
	.long	4199060497,4199060497
	.long	577038663,577038663
	.long	3297574056,3297574056
	.long	440397984,440397984
	.long	3626794326,3626794326
	.long	4019204898,4019204898
	.long	3343796615,3343796615
	.long	3251714265,3251714265
	.long	4272081548,4272081548
	.long	906744984,906744984
	.long	3481400742,3481400742
	.long	685669029,685669029
	.long	646887386,646887386
	.long	2764025151,2764025151
	.long	3835509292,3835509292
	.long	227702864,227702864
	.long	2613862250,2613862250
	.long	1648787028,1648787028
	.long	3256061430,3256061430
	.long	3904428176,3904428176
	.long	1593260334,1593260334
	.long	4121936770,4121936770
	.long	3196083615,3196083615
	.long	2090061929,2090061929
	.long	2838353263,2838353263
	.long	3004310991,3004310991
	.long	999926984,999926984
	.long	2809993232,2809993232
	.long	1852021992,1852021992
	.long	2075868123,2075868123
	.long	158869197,158869197
	.long	4095236462,4095236462
	.long	28809964,28809964
	.long	2828685187,2828685187
	.long	1701746150,1701746150
	.long	2129067946,2129067946
	.long	147831841,147831841
	.long	3873969647,3873969647
	.long	3650873274,3650873274
	.long	3459673930,3459673930
	.long	3557400554,3557400554
	.long	3598495785,3598495785
	.long	2947720241,2947720241
	.long	824393514,824393514
	.long	815048134,815048134
	.long	3227951669,3227951669
	.long	935087732,935087732
	.long	2798289660,2798289660
	.long	2966458592,2966458592
	.long	366520115,366520115
	.long	1251476721,1251476721
	.long	4158319681,4158319681
	.long	240176511,240176511
	.long	804688151,804688151
	.long	2379631990,2379631990
	.long	1303441219,1303441219
	.long	1414376140,1414376140
	.long	3741619940,3741619940
	.long	3820343710,3820343710
	.long	461924940,461924940
	.long	3089050817,3089050817
	.long	2136040774,2136040774
	.long	82468509,82468509
	.long	1563790337,1563790337
	.long	1937016826,1937016826
	.long	776014843,776014843
	.long	1511876531,1511876531
	.long	1389550482,1389550482
	.long	861278441,861278441
	.long	323475053,323475053
	.long	2355222426,2355222426
	.long	2047648055,2047648055
	.long	2383738969,2383738969
	.long	2302415851,2302415851
	.long	3995576782,3995576782
	.long	902390199,902390199
	.long	3991215329,3991215329
	.long	1018251130,1018251130
	.long	1507840668,1507840668
	.long	1064563285,1064563285
	.long	2043548696,2043548696
	.long	3208103795,3208103795
	.long	3939366739,3939366739
	.long	1537932639,1537932639
	.long	342834655,342834655
	.long	2262516856,2262516856
	.long	2180231114,2180231114
	.long	1053059257,1053059257
	.long	741614648,741614648
	.long	1598071746,1598071746
	.long	1925389590,1925389590
	.long	203809468,203809468
	.long	2336832552,2336832552
	.long	1100287487,1100287487
	.long	1895934009,1895934009
	.long	3736275976,3736275976
	.long	2632234200,2632234200
	.long	2428589668,2428589668
	.long	1636092795,1636092795
	.long	1890988757,1890988757
	.long	1952214088,1952214088
	.long	1113045200,1113045200
	.long	1381126738,151587081,1785358954,3587560917
	.long	808464432,909522486,2779096485,943208504
	.long	3217014719,1077952576,2745410467,2661195422
	.long	2172748161,4092851187,3621246935,4227595259
	.long	2088533116,3823363043,960051513,2189591170
	.long	2610666395,791621423,4294967295,2273806215
	.long	875836468,2391707278,1128481603,1145324612
	.long	3301229764,3739147998,3924421097,3419130827
	.long	1414812756,2071690107,2492765332,842150450
	.long	2795939494,3267543746,589505315,1027423549
	.long	4008636142,1280068684,2509608341,185273099
	.long	1111638594,4210752250,3284386755,1313754702
	.long	134744072,774778414,2711724449,1717986918
	.long	673720360,3654932953,606348324,2998055602
	.long	1987475062,1532713819,2728567458,1229539657
	.long	1835887981,2341178251,3520188881,623191333
	.long	1920103026,4177066232,4143380214,1684300900
	.long	2256963206,1751672936,2560137368,370546198
	.long	3570717908,2762253476,1549556828,3435973836
	.long	1566399837,1701143909,3065427638,2459079314
	.long	1819044972,1886417008,1212696648,1347440720
	.long	4261281277,3991793133,3115956665,3671775962
	.long	1583242846,353703189,1179010630,1465341783
	.long	2812782503,2374864269,2644352413,2223277188
	.long	2425393296,3638089944,2880154539,0
	.long	2358021260,3166485692,3553874899,168430090
	.long	4160223223,3840206052,1482184792,84215045
	.long	3099113656,3014898611,1162167621,101058054
	.long	3503345872,741092396,505290270,2408550287
	.long	3402287818,1061109567,252645135,33686018
	.long	3250700737,2947526575,3183328701,50529027
	.long	16843009,320017171,2324335242,1802201963
	.long	976894522,2442236305,286331153,1094795585
	.long	1330597711,1734829927,3705461980,3941264106
	.long	2543294359,4076008178,3486502863,3469659854
	.long	4042322160,3031741620,3873892070,1936946035
	.long	2526451350,2896997548,1953789044,572662306
	.long	3890735079,2913840557,892679477,2240120197
	.long	3806520034,4193909241,926365495,3907578088
	.long	471604252,1970632053,3755991007,1852730990
	.long	1195853639,4059165169,437918234,1903260017
	.long	488447261,690563369,3318072773,2307492233
	.long	1869573999,3082270647,1650614882,235802126
	.long	2863311530,404232216,3200171710,454761243
	.long	4244438268,1448498774,1044266558,1263225675
	.long	3334915782,3537031890,2038004089,538976288
	.long	2593823386,3688618971,3233857728,4278124286
	.long	2021161080,3452816845,1515870810,4109694196
	.long	522133279,3722304989,2829625512,858993459
	.long	2290649224,117901063,3351758791,825307441
	.long	2981212593,303174162,269488144,1499027801
	.long	656877351,2155905152,3974950124,1600085855
	.long	1616928864,1364283729,2139062143,2846468521
	.long	421075225,3048584629,1246382666,218959117
	.long	757935405,3857049061,2054847098,2678038431
	.long	2475922323,3385444809,2627509404,4025479151
	.long	2694881440,3772834016,993737531,1296911693
	.long	2930683566,707406378,4126537205,2964369584
	.long	3368601800,3958107115,3149642683,1010580540
	.long	2206434179,1397969747,2576980377,1633771873
	.long	387389207,724249387,67372036,2122219134
	.long	3132799674,2004318071,3604403926,640034342
	.long	3789677025,1768515945,336860180,1667457891
	.long	1431655765,555819297,202116108,2105376125
.L__x86_AES_decrypt_end:
.size	_x86_AES_decrypt,.L__x86_AES_decrypt_end-_x86_AES_decrypt
.ident	"_x86_AES_decrypt"
.globl	AES_Td
.text
.globl	AES_decrypt
.type	AES_decrypt,@function
.align	16
AES_decrypt:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	movl	20(%esp),	%esi
	movl	28(%esp),	%edi
	movl	%esp,		%eax
	subl	$24,		%esp
	andl	$-64,		%esp
	addl	$4,		%esp
	movl	%eax,		16(%esp)
	call	.L003pic_point
.L003pic_point:
	popl	%ebp
	leal	AES_Td-.L003pic_point(%ebp),%ebp
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	call	_x86_AES_decrypt
	movl	16(%esp),	%esp
	movl	24(%esp),	%esi
	movl	%eax,		(%esi)
	movl	%ebx,		4(%esi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_AES_decrypt_end:
.size	AES_decrypt,.L_AES_decrypt_end-AES_decrypt
.ident	"AES_decrypt"
.globl	AES_Te
.globl	AES_Td
.text
.globl	AES_cbc_encrypt
.type	AES_cbc_encrypt,@function
.align	16
AES_cbc_encrypt:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	movl	28(%esp),	%ecx
	cmpl	$0,		%ecx
	je	.L004enc_out
	call	.L005pic_point
.L005pic_point:
	popl	%ebp
	pushfl
	cld
	cmpl	$0,		44(%esp)
	je	.L006DECRYPT
	leal	AES_Te-.L005pic_point(%ebp),%ebp
	leal	-308(%esp),	%edi
	andl	$-64,		%edi
	movl	%ebp,		%eax
	leal	2048(%ebp),	%ebx
	movl	%edi,		%edx
	andl	$4095,		%eax
	andl	$4095,		%ebx
	andl	$4095,		%edx
	cmpl	%ebx,		%edx
	jb	.L007te_break_out
	subl	%ebx,		%edx
	subl	%edx,		%edi
	jmp	.L008te_ok
.L007te_break_out:
	subl	%eax,		%edx
	andl	$4095,		%edx
	addl	$320,		%edx
	subl	%edx,		%edi
.align	4
.L008te_ok:
	movl	24(%esp),	%eax
	movl	28(%esp),	%ebx
	movl	36(%esp),	%edx
	movl	40(%esp),	%esi
	xchgl	%edi,		%esp
	addl	$4,		%esp
	movl	%edi,		16(%esp)
	movl	%eax,		20(%esp)
	movl	%ebx,		24(%esp)
	movl	%ecx,		28(%esp)
	movl	%edx,		32(%esp)
	movl	%esi,		36(%esp)
	movl	$61,		%ecx
	movl	%edx,		%esi
	leal	60(%esp),	%edi
	movl	%edi,		32(%esp)
.align	4
	.long	4136216051
	movl	%eax,		%esi
	movl	$16,		%edi
.align	4
.L009prefetch_te:
	movl	(%ebp),		%eax
	movl	32(%ebp),	%ebx
	movl	64(%ebp),	%ecx
	movl	96(%ebp),	%edx
	leal	128(%ebp),	%ebp
	decl	%edi
	jnz	.L009prefetch_te
	subl	$2048,		%ebp
	movl	28(%esp),	%ecx
	movl	36(%esp),	%edi
	testl	$4294967280,	%ecx
	jz	.L010enc_tail
	movl	(%edi),		%eax
	movl	4(%edi),	%ebx
.align	4
.L011enc_loop:
	movl	8(%edi),	%ecx
	movl	12(%edi),	%edx
	xorl	(%esi),		%eax
	xorl	4(%esi),	%ebx
	xorl	8(%esi),	%ecx
	xorl	12(%esi),	%edx
	movl	32(%esp),	%edi
	call	_x86_AES_encrypt
	movl	20(%esp),	%esi
	movl	24(%esp),	%edi
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	28(%esp),	%ecx
	leal	16(%esi),	%esi
	movl	%esi,		20(%esp)
	leal	16(%edi),	%edx
	movl	%edx,		24(%esp)
	subl	$16,		%ecx
	testl	$4294967280,	%ecx
	movl	%ecx,		28(%esp)
	jnz	.L011enc_loop
	testl	$15,		%ecx
	jnz	.L010enc_tail
	movl	36(%esp),	%esi
	movl	8(%edi),	%ecx
	movl	12(%edi),	%edx
	movl	%eax,		(%esi)
	movl	%ebx,		4(%esi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	movl	32(%esp),	%edi
	movl	16(%esp),	%esp
	movl	$60,		%ecx
	xorl	%eax,		%eax
.align	4
	.long	4136217587
	popfl
.L004enc_out:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
	pushfl
.align	4
.L010enc_tail:
	pushl	%edi
	movl	24(%esp),	%edi
	movl	$16,		%ebx
	subl	%ecx,		%ebx
	cmpl	%esi,		%edi
	je	.L012enc_in_place
.align	4
	.long	4136215795
	jmp	.L013enc_skip_in_place
.L012enc_in_place:
	leal	(%edi,%ecx),	%edi
.L013enc_skip_in_place:
	movl	%ebx,		%ecx
	xorl	%eax,		%eax
.align	4
	.long	4136217331
	popl	%edi
	movl	24(%esp),	%esi
	movl	(%edi),		%eax
	movl	4(%edi),	%ebx
	movl	$16,		28(%esp)
	jmp	.L011enc_loop
.align	4
.L006DECRYPT:
	leal	AES_Td-.L005pic_point(%ebp),%ebp
	leal	-308(%esp),	%edi
	andl	$-64,		%edi
	movl	%ebp,		%eax
	leal	3072(%ebp),	%ebx
	movl	%edi,		%edx
	andl	$4095,		%eax
	andl	$4095,		%ebx
	andl	$4095,		%edx
	cmpl	%ebx,		%edx
	jb	.L014td_break_out
	subl	%ebx,		%edx
	subl	%edx,		%edi
	jmp	.L015td_ok
.L014td_break_out:
	subl	%eax,		%edx
	andl	$4095,		%edx
	addl	$320,		%edx
	subl	%edx,		%edi
.align	4
.L015td_ok:
	movl	24(%esp),	%eax
	movl	28(%esp),	%ebx
	movl	36(%esp),	%edx
	movl	40(%esp),	%esi
	xchgl	%edi,		%esp
	addl	$4,		%esp
	movl	%edi,		16(%esp)
	movl	%eax,		20(%esp)
	movl	%ebx,		24(%esp)
	movl	%ecx,		28(%esp)
	movl	%edx,		32(%esp)
	movl	%esi,		36(%esp)
	movl	$61,		%ecx
	movl	%edx,		%esi
	leal	60(%esp),	%edi
	movl	%edi,		32(%esp)
.align	4
	.long	4136216051
	movl	%eax,		%esi
	movl	$24,		%edi
.align	4
.L016prefetch_td:
	movl	(%ebp),		%eax
	movl	32(%ebp),	%ebx
	movl	64(%ebp),	%ecx
	movl	96(%ebp),	%edx
	leal	128(%ebp),	%ebp
	decl	%edi
	jnz	.L016prefetch_td
	subl	$3072,		%ebp
	cmpl	24(%esp),	%esi
	je	.L017dec_in_place
	movl	36(%esp),	%edi
	movl	%edi,		40(%esp)
.align	4
.L018dec_loop:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	32(%esp),	%edi
	call	_x86_AES_decrypt
	movl	40(%esp),	%edi
	movl	28(%esp),	%esi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	subl	$16,		%esi
	jc	.L019dec_partial
	movl	%esi,		28(%esp)
	movl	20(%esp),	%esi
	movl	24(%esp),	%edi
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	%esi,		40(%esp)
	leal	16(%esi),	%esi
	movl	%esi,		20(%esp)
	leal	16(%edi),	%edi
	movl	%edi,		24(%esp)
	jnz	.L018dec_loop
	movl	40(%esp),	%edi
.L020dec_end:
	movl	36(%esp),	%esi
	movl	(%edi),		%eax
	movl	4(%edi),	%ebx
	movl	8(%edi),	%ecx
	movl	12(%edi),	%edx
	movl	%eax,		(%esi)
	movl	%ebx,		4(%esi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	jmp	.L021dec_out
.align	4
.L019dec_partial:
	leal	44(%esp),	%edi
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	leal	16(%esi),	%ecx
	movl	%edi,		%esi
	movl	24(%esp),	%edi
	.long	4136215795
	movl	20(%esp),	%edi
	jmp	.L020dec_end
.align	4
.L017dec_in_place:
.L022dec_in_place_loop:
	leal	44(%esp),	%edi
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	32(%esp),	%edi
	call	_x86_AES_decrypt
	movl	36(%esp),	%edi
	movl	24(%esp),	%esi
	xorl	(%edi),		%eax
	xorl	4(%edi),	%ebx
	xorl	8(%edi),	%ecx
	xorl	12(%edi),	%edx
	movl	%eax,		(%esi)
	movl	%ebx,		4(%esi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	leal	16(%esi),	%esi
	movl	%esi,		24(%esp)
	leal	44(%esp),	%esi
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	20(%esp),	%esi
	leal	16(%esi),	%esi
	movl	%esi,		20(%esp)
	movl	28(%esp),	%ecx
	subl	$16,		%ecx
	jc	.L023dec_in_place_partial
	movl	%ecx,		28(%esp)
	jnz	.L022dec_in_place_loop
	jmp	.L021dec_out
.align	4
.L023dec_in_place_partial:
	movl	24(%esp),	%edi
	leal	44(%esp),	%esi
	leal	(%edi,%ecx),	%edi
	leal	16(%esi,%ecx),	%esi
	negl	%ecx
	.long	4136215795
.align	4
.L021dec_out:
	movl	32(%esp),	%edi
	movl	16(%esp),	%esp
	movl	$60,		%ecx
	xorl	%eax,		%eax
.align	4
	.long	4136217587
	popfl
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_AES_cbc_encrypt_end:
.size	AES_cbc_encrypt,.L_AES_cbc_encrypt_end-AES_cbc_encrypt
.ident	"AES_cbc_encrypt"
.globl	AES_Te
.text
.globl	AES_set_encrypt_key
.type	AES_set_encrypt_key,@function
.align	16
AES_set_encrypt_key:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	call	FIPS_selftest_failed
	cmpl	$0,%eax
	mov	$-3,%eax
	jne	.L029exit

	movl	20(%esp),	%esi
	movl	28(%esp),	%edi
	testl	$-1,		%esi
	jz	.L024badpointer
	testl	$-1,		%edi
	jz	.L024badpointer
	call	.L025pic_point
.L025pic_point:
	popl	%ebp
	leal	AES_Te-.L025pic_point(%ebp),%ebp
	movl	24(%esp),	%ecx
	cmpl	$128,		%ecx
	je	.L02610rounds
	cmpl	$192,		%ecx
	je	.L02712rounds
	cmpl	$256,		%ecx
	je	.L02814rounds
	movl	$-2,		%eax
	jmp	.L029exit
.L02610rounds:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	xorl	%ecx,		%ecx
	jmp	.L03010shortcut
.align	4
.L03110loop:
	movl	(%edi),		%eax
	movl	12(%edi),	%edx
.L03010shortcut:
	movzbl	%dl,		%esi
	movl	2(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$4278190080,	%ebx
	xorl	%ebx,		%eax
	movl	2(%ebp,%esi,8),	%ebx
	shrl	$16,		%edx
	andl	$255,		%ebx
	movzbl	%dl,		%esi
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$65280,		%ebx
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	andl	$16711680,	%ebx
	xorl	%ebx,		%eax
	xorl	2048(%ebp,%ecx,4),%eax
	movl	%eax,		16(%edi)
	xorl	4(%edi),	%eax
	movl	%eax,		20(%edi)
	xorl	8(%edi),	%eax
	movl	%eax,		24(%edi)
	xorl	12(%edi),	%eax
	movl	%eax,		28(%edi)
	incl	%ecx
	addl	$16,		%edi
	cmpl	$10,		%ecx
	jl	.L03110loop
	movl	$10,		80(%edi)
	xorl	%eax,		%eax
	jmp	.L029exit
.L02712rounds:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	16(%esi),	%ecx
	movl	20(%esi),	%edx
	movl	%ecx,		16(%edi)
	movl	%edx,		20(%edi)
	xorl	%ecx,		%ecx
	jmp	.L03212shortcut
.align	4
.L03312loop:
	movl	(%edi),		%eax
	movl	20(%edi),	%edx
.L03212shortcut:
	movzbl	%dl,		%esi
	movl	2(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$4278190080,	%ebx
	xorl	%ebx,		%eax
	movl	2(%ebp,%esi,8),	%ebx
	shrl	$16,		%edx
	andl	$255,		%ebx
	movzbl	%dl,		%esi
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$65280,		%ebx
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	andl	$16711680,	%ebx
	xorl	%ebx,		%eax
	xorl	2048(%ebp,%ecx,4),%eax
	movl	%eax,		24(%edi)
	xorl	4(%edi),	%eax
	movl	%eax,		28(%edi)
	xorl	8(%edi),	%eax
	movl	%eax,		32(%edi)
	xorl	12(%edi),	%eax
	movl	%eax,		36(%edi)
	cmpl	$7,		%ecx
	je	.L03412break
	incl	%ecx
	xorl	16(%edi),	%eax
	movl	%eax,		40(%edi)
	xorl	20(%edi),	%eax
	movl	%eax,		44(%edi)
	addl	$24,		%edi
	jmp	.L03312loop
.L03412break:
	movl	$12,		72(%edi)
	xorl	%eax,		%eax
	jmp	.L029exit
.L02814rounds:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	8(%esi),	%ecx
	movl	12(%esi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		8(%edi)
	movl	%edx,		12(%edi)
	movl	16(%esi),	%eax
	movl	20(%esi),	%ebx
	movl	24(%esi),	%ecx
	movl	28(%esi),	%edx
	movl	%eax,		16(%edi)
	movl	%ebx,		20(%edi)
	movl	%ecx,		24(%edi)
	movl	%edx,		28(%edi)
	xorl	%ecx,		%ecx
	jmp	.L03514shortcut
.align	4
.L03614loop:
	movl	28(%edi),	%edx
.L03514shortcut:
	movl	(%edi),		%eax
	movzbl	%dl,		%esi
	movl	2(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$4278190080,	%ebx
	xorl	%ebx,		%eax
	movl	2(%ebp,%esi,8),	%ebx
	shrl	$16,		%edx
	andl	$255,		%ebx
	movzbl	%dl,		%esi
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$65280,		%ebx
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	andl	$16711680,	%ebx
	xorl	%ebx,		%eax
	xorl	2048(%ebp,%ecx,4),%eax
	movl	%eax,		32(%edi)
	xorl	4(%edi),	%eax
	movl	%eax,		36(%edi)
	xorl	8(%edi),	%eax
	movl	%eax,		40(%edi)
	xorl	12(%edi),	%eax
	movl	%eax,		44(%edi)
	cmpl	$6,		%ecx
	je	.L03714break
	incl	%ecx
	movl	%eax,		%edx
	movl	16(%edi),	%eax
	movzbl	%dl,		%esi
	movl	2(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$255,		%ebx
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	shrl	$16,		%edx
	andl	$65280,		%ebx
	movzbl	%dl,		%esi
	xorl	%ebx,		%eax
	movl	(%ebp,%esi,8),	%ebx
	movzbl	%dh,		%esi
	andl	$16711680,	%ebx
	xorl	%ebx,		%eax
	movl	2(%ebp,%esi,8),	%ebx
	andl	$4278190080,	%ebx
	xorl	%ebx,		%eax
	movl	%eax,		48(%edi)
	xorl	20(%edi),	%eax
	movl	%eax,		52(%edi)
	xorl	24(%edi),	%eax
	movl	%eax,		56(%edi)
	xorl	28(%edi),	%eax
	movl	%eax,		60(%edi)
	addl	$32,		%edi
	jmp	.L03614loop
.L03714break:
	movl	$14,		48(%edi)
	xorl	%eax,		%eax
	jmp	.L029exit
.L024badpointer:
	movl	$-1,		%eax
.L029exit:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_AES_set_encrypt_key_end:
.size	AES_set_encrypt_key,.L_AES_set_encrypt_key_end-AES_set_encrypt_key
.ident	"AES_set_encrypt_key"
.globl	AES_Td
.globl	AES_Te
.text
.globl	AES_set_decrypt_key
.type	AES_set_decrypt_key,@function
.align	16
AES_set_decrypt_key:
	movl	4(%esp),	%eax
	movl	8(%esp),	%ecx
	movl	12(%esp),	%edx
	subl	$12,		%esp
	movl	%eax,		(%esp)
	movl	%ecx,		4(%esp)
	movl	%edx,		8(%esp)
	call	AES_set_encrypt_key
	addl	$12,		%esp
	cmpl	$0,		%eax
	je	.L038proceed
	ret
.L038proceed:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	28(%esp),	%esi
	movl	240(%esi),	%ecx
	leal	(,%ecx,4),	%ecx
	leal	(%esi,%ecx,4),	%edi
.align	4
.L039invert:
	movl	(%esi),		%eax
	movl	4(%esi),	%ebx
	movl	(%edi),		%ecx
	movl	4(%edi),	%edx
	movl	%eax,		(%edi)
	movl	%ebx,		4(%edi)
	movl	%ecx,		(%esi)
	movl	%edx,		4(%esi)
	movl	8(%esi),	%eax
	movl	12(%esi),	%ebx
	movl	8(%edi),	%ecx
	movl	12(%edi),	%edx
	movl	%eax,		8(%edi)
	movl	%ebx,		12(%edi)
	movl	%ecx,		8(%esi)
	movl	%edx,		12(%esi)
	addl	$16,		%esi
	subl	$16,		%edi
	cmpl	%edi,		%esi
	jne	.L039invert
	call	.L040pic_point
.L040pic_point:
	popl	%ebp
	leal	AES_Td-.L040pic_point(%ebp),%edi
	leal	AES_Te-.L040pic_point(%ebp),%ebp
	movl	28(%esp),	%esi
	movl	240(%esi),	%ecx
	decl	%ecx
.align	4
.L041permute:
	addl	$16,		%esi
	movl	(%esi),		%eax
	movl	%eax,		%edx
	movzbl	%ah,		%ebx
	shrl	$16,		%edx
	andl	$255,		%eax
	movzbl	2(%ebp,%eax,8),	%eax
	movzbl	2(%ebp,%ebx,8),	%ebx
	movl	(%edi,%eax,8),	%eax
	xorl	3(%edi,%ebx,8),	%eax
	movzbl	%dh,		%ebx
	andl	$255,		%edx
	movzbl	2(%ebp,%edx,8),	%edx
	movzbl	2(%ebp,%ebx,8),	%ebx
	xorl	2(%edi,%edx,8),	%eax
	xorl	1(%edi,%ebx,8),	%eax
	movl	%eax,		(%esi)
	movl	4(%esi),	%eax
	movl	%eax,		%edx
	movzbl	%ah,		%ebx
	shrl	$16,		%edx
	andl	$255,		%eax
	movzbl	2(%ebp,%eax,8),	%eax
	movzbl	2(%ebp,%ebx,8),	%ebx
	movl	(%edi,%eax,8),	%eax
	xorl	3(%edi,%ebx,8),	%eax
	movzbl	%dh,		%ebx
	andl	$255,		%edx
	movzbl	2(%ebp,%edx,8),	%edx
	movzbl	2(%ebp,%ebx,8),	%ebx
	xorl	2(%edi,%edx,8),	%eax
	xorl	1(%edi,%ebx,8),	%eax
	movl	%eax,		4(%esi)
	movl	8(%esi),	%eax
	movl	%eax,		%edx
	movzbl	%ah,		%ebx
	shrl	$16,		%edx
	andl	$255,		%eax
	movzbl	2(%ebp,%eax,8),	%eax
	movzbl	2(%ebp,%ebx,8),	%ebx
	movl	(%edi,%eax,8),	%eax
	xorl	3(%edi,%ebx,8),	%eax
	movzbl	%dh,		%ebx
	andl	$255,		%edx
	movzbl	2(%ebp,%edx,8),	%edx
	movzbl	2(%ebp,%ebx,8),	%ebx
	xorl	2(%edi,%edx,8),	%eax
	xorl	1(%edi,%ebx,8),	%eax
	movl	%eax,		8(%esi)
	movl	12(%esi),	%eax
	movl	%eax,		%edx
	movzbl	%ah,		%ebx
	shrl	$16,		%edx
	andl	$255,		%eax
	movzbl	2(%ebp,%eax,8),	%eax
	movzbl	2(%ebp,%ebx,8),	%ebx
	movl	(%edi,%eax,8),	%eax
	xorl	3(%edi,%ebx,8),	%eax
	movzbl	%dh,		%ebx
	andl	$255,		%edx
	movzbl	2(%ebp,%edx,8),	%edx
	movzbl	2(%ebp,%ebx,8),	%ebx
	xorl	2(%edi,%edx,8),	%eax
	xorl	1(%edi,%ebx,8),	%eax
	movl	%eax,		12(%esi)
	decl	%ecx
	jnz	.L041permute
	xorl	%eax,		%eax
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_AES_set_decrypt_key_end:
.size	AES_set_decrypt_key,.L_AES_set_decrypt_key_end-AES_set_decrypt_key
.ident	"AES_set_decrypt_key"
