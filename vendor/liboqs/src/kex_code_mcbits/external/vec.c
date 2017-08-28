static void vec_mul(uint64_t *h, uint64_t *f, const uint64_t *g) {
	int i;
	uint64_t result[2 * GFBITS - 1];

	//

	uint64_t t1 = f[11] & g[11];
	uint64_t t2 = f[11] & g[9];
	uint64_t t3 = f[11] & g[10];
	uint64_t t4 = f[9] & g[11];
	uint64_t t5 = f[10] & g[11];
	uint64_t t6 = f[10] & g[10];
	uint64_t t7 = f[10] & g[9];
	uint64_t t8 = f[9] & g[10];
	uint64_t t9 = f[9] & g[9];
	uint64_t t10 = t8 ^ t7;
	uint64_t t11 = t6 ^ t4;
	uint64_t t12 = t11 ^ t2;
	uint64_t t13 = t5 ^ t3;
	uint64_t t14 = f[8] & g[8];
	uint64_t t15 = f[8] & g[6];
	uint64_t t16 = f[8] & g[7];
	uint64_t t17 = f[6] & g[8];
	uint64_t t18 = f[7] & g[8];
	uint64_t t19 = f[7] & g[7];
	uint64_t t20 = f[7] & g[6];
	uint64_t t21 = f[6] & g[7];
	uint64_t t22 = f[6] & g[6];
	uint64_t t23 = t21 ^ t20;
	uint64_t t24 = t19 ^ t17;
	uint64_t t25 = t24 ^ t15;
	uint64_t t26 = t18 ^ t16;
	uint64_t t27 = f[5] & g[5];
	uint64_t t28 = f[5] & g[3];
	uint64_t t29 = f[5] & g[4];
	uint64_t t30 = f[3] & g[5];
	uint64_t t31 = f[4] & g[5];
	uint64_t t32 = f[4] & g[4];
	uint64_t t33 = f[4] & g[3];
	uint64_t t34 = f[3] & g[4];
	uint64_t t35 = f[3] & g[3];
	uint64_t t36 = t34 ^ t33;
	uint64_t t37 = t32 ^ t30;
	uint64_t t38 = t37 ^ t28;
	uint64_t t39 = t31 ^ t29;
	uint64_t t40 = f[2] & g[2];
	uint64_t t41 = f[2] & g[0];
	uint64_t t42 = f[2] & g[1];
	uint64_t t43 = f[0] & g[2];
	uint64_t t44 = f[1] & g[2];
	uint64_t t45 = f[1] & g[1];
	uint64_t t46 = f[1] & g[0];
	uint64_t t47 = f[0] & g[1];
	uint64_t t48 = f[0] & g[0];
	uint64_t t49 = t47 ^ t46;
	uint64_t t50 = t45 ^ t43;
	uint64_t t51 = t50 ^ t41;
	uint64_t t52 = t44 ^ t42;
	uint64_t t53 = t52 ^ t35;
	uint64_t t54 = t40 ^ t36;
	uint64_t t55 = t39 ^ t22;
	uint64_t t56 = t27 ^ t23;
	uint64_t t57 = t26 ^ t9;
	uint64_t t58 = t14 ^ t10;
	uint64_t t59 = g[6] ^ g[9];
	uint64_t t60 = g[7] ^ g[10];
	uint64_t t61 = g[8] ^ g[11];
	uint64_t t62 = f[6] ^ f[9];
	uint64_t t63 = f[7] ^ f[10];
	uint64_t t64 = f[8] ^ f[11];
	uint64_t t65 = t64 & t61;
	uint64_t t66 = t64 & t59;
	uint64_t t67 = t64 & t60;
	uint64_t t68 = t62 & t61;
	uint64_t t69 = t63 & t61;
	uint64_t t70 = t63 & t60;
	uint64_t t71 = t63 & t59;
	uint64_t t72 = t62 & t60;
	uint64_t t73 = t62 & t59;
	uint64_t t74 = t72 ^ t71;
	uint64_t t75 = t70 ^ t68;
	uint64_t t76 = t75 ^ t66;
	uint64_t t77 = t69 ^ t67;
	uint64_t t78 = g[0] ^ g[3];
	uint64_t t79 = g[1] ^ g[4];
	uint64_t t80 = g[2] ^ g[5];
	uint64_t t81 = f[0] ^ f[3];
	uint64_t t82 = f[1] ^ f[4];
	uint64_t t83 = f[2] ^ f[5];
	uint64_t t84 = t83 & t80;
	uint64_t t85 = t83 & t78;
	uint64_t t86 = t83 & t79;
	uint64_t t87 = t81 & t80;
	uint64_t t88 = t82 & t80;
	uint64_t t89 = t82 & t79;
	uint64_t t90 = t82 & t78;
	uint64_t t91 = t81 & t79;
	uint64_t t92 = t81 & t78;
	uint64_t t93 = t91 ^ t90;
	uint64_t t94 = t89 ^ t87;
	uint64_t t95 = t94 ^ t85;
	uint64_t t96 = t88 ^ t86;
	uint64_t t97 = t53 ^ t48;
	uint64_t t98 = t54 ^ t49;
	uint64_t t99 = t38 ^ t51;
	uint64_t t100 = t55 ^ t53;
	uint64_t t101 = t56 ^ t54;
	uint64_t t102 = t25 ^ t38;
	uint64_t t103 = t57 ^ t55;
	uint64_t t104 = t58 ^ t56;
	uint64_t t105 = t12 ^ t25;
	uint64_t t106 = t13 ^ t57;
	uint64_t t107 = t1 ^ t58;
	uint64_t t108 = t97 ^ t92;
	uint64_t t109 = t98 ^ t93;
	uint64_t t110 = t99 ^ t95;
	uint64_t t111 = t100 ^ t96;
	uint64_t t112 = t101 ^ t84;
	uint64_t t113 = t103 ^ t73;
	uint64_t t114 = t104 ^ t74;
	uint64_t t115 = t105 ^ t76;
	uint64_t t116 = t106 ^ t77;
	uint64_t t117 = t107 ^ t65;
	uint64_t t118 = g[3] ^ g[9];
	uint64_t t119 = g[4] ^ g[10];
	uint64_t t120 = g[5] ^ g[11];
	uint64_t t121 = g[0] ^ g[6];
	uint64_t t122 = g[1] ^ g[7];
	uint64_t t123 = g[2] ^ g[8];
	uint64_t t124 = f[3] ^ f[9];
	uint64_t t125 = f[4] ^ f[10];
	uint64_t t126 = f[5] ^ f[11];
	uint64_t t127 = f[0] ^ f[6];
	uint64_t t128 = f[1] ^ f[7];
	uint64_t t129 = f[2] ^ f[8];
	uint64_t t130 = t129 & t123;
	uint64_t t131 = t129 & t121;
	uint64_t t132 = t129 & t122;
	uint64_t t133 = t127 & t123;
	uint64_t t134 = t128 & t123;
	uint64_t t135 = t128 & t122;
	uint64_t t136 = t128 & t121;
	uint64_t t137 = t127 & t122;
	uint64_t t138 = t127 & t121;
	uint64_t t139 = t137 ^ t136;
	uint64_t t140 = t135 ^ t133;
	uint64_t t141 = t140 ^ t131;
	uint64_t t142 = t134 ^ t132;
	uint64_t t143 = t126 & t120;
	uint64_t t144 = t126 & t118;
	uint64_t t145 = t126 & t119;
	uint64_t t146 = t124 & t120;
	uint64_t t147 = t125 & t120;
	uint64_t t148 = t125 & t119;
	uint64_t t149 = t125 & t118;
	uint64_t t150 = t124 & t119;
	uint64_t t151 = t124 & t118;
	uint64_t t152 = t150 ^ t149;
	uint64_t t153 = t148 ^ t146;
	uint64_t t154 = t153 ^ t144;
	uint64_t t155 = t147 ^ t145;
	uint64_t t156 = t121 ^ t118;
	uint64_t t157 = t122 ^ t119;
	uint64_t t158 = t123 ^ t120;
	uint64_t t159 = t127 ^ t124;
	uint64_t t160 = t128 ^ t125;
	uint64_t t161 = t129 ^ t126;
	uint64_t t162 = t161 & t158;
	uint64_t t163 = t161 & t156;
	uint64_t t164 = t161 & t157;
	uint64_t t165 = t159 & t158;
	uint64_t t166 = t160 & t158;
	uint64_t t167 = t160 & t157;
	uint64_t t168 = t160 & t156;
	uint64_t t169 = t159 & t157;
	uint64_t t170 = t159 & t156;
	uint64_t t171 = t169 ^ t168;
	uint64_t t172 = t167 ^ t165;
	uint64_t t173 = t172 ^ t163;
	uint64_t t174 = t166 ^ t164;
	uint64_t t175 = t142 ^ t151;
	uint64_t t176 = t130 ^ t152;
	uint64_t t177 = t170 ^ t175;
	uint64_t t178 = t171 ^ t176;
	uint64_t t179 = t173 ^ t154;
	uint64_t t180 = t174 ^ t155;
	uint64_t t181 = t162 ^ t143;
	uint64_t t182 = t177 ^ t138;
	uint64_t t183 = t178 ^ t139;
	uint64_t t184 = t179 ^ t141;
	uint64_t t185 = t180 ^ t175;
	uint64_t t186 = t181 ^ t176;
	uint64_t t187 = t111 ^ t48;
	uint64_t t188 = t112 ^ t49;
	uint64_t t189 = t102 ^ t51;
	uint64_t t190 = t113 ^ t108;
	uint64_t t191 = t114 ^ t109;
	uint64_t t192 = t115 ^ t110;
	uint64_t t193 = t116 ^ t111;
	uint64_t t194 = t117 ^ t112;
	uint64_t t195 = t12 ^ t102;
	uint64_t t196 = t13 ^ t113;
	uint64_t t197 = t1 ^ t114;
	uint64_t t198 = t187 ^ t138;
	uint64_t t199 = t188 ^ t139;
	uint64_t t200 = t189 ^ t141;
	uint64_t t201 = t190 ^ t182;
	uint64_t t202 = t191 ^ t183;
	uint64_t t203 = t192 ^ t184;
	uint64_t t204 = t193 ^ t185;
	uint64_t t205 = t194 ^ t186;
	uint64_t t206 = t195 ^ t154;
	uint64_t t207 = t196 ^ t155;
	uint64_t t208 = t197 ^ t143;

	result[0] = t48;
	result[1] = t49;
	result[2] = t51;
	result[3] = t108;
	result[4] = t109;
	result[5] = t110;
	result[6] = t198;
	result[7] = t199;
	result[8] = t200;
	result[9] = t201;
	result[10] = t202;
	result[11] = t203;
	result[12] = t204;
	result[13] = t205;
	result[14] = t206;
	result[15] = t207;
	result[16] = t208;
	result[17] = t115;
	result[18] = t116;
	result[19] = t117;
	result[20] = t12;
	result[21] = t13;
	result[22] = t1;

	//

	for (i = 2 * GFBITS - 2; i >= GFBITS; i--) {
		result[i - 9] ^= result[i];
		result[i - GFBITS] ^= result[i];
	}

	//

	for (i = 0; i < GFBITS; i++)
		h[i] = result[i];
}

static void vec_sq(uint64_t *out, uint64_t *in) {
	int i;
	uint64_t result[GFBITS];

	//

	result[0] = in[0] ^ in[6];
	result[1] = in[11];
	result[2] = in[1] ^ in[7];
	result[3] = in[6];
	result[4] = in[2] ^ in[11] ^ in[8];
	result[5] = in[7];
	result[6] = in[3] ^ in[9];
	result[7] = in[8];
	result[8] = in[4] ^ in[10];
	result[9] = in[9];
	result[10] = in[5] ^ in[11];
	result[11] = in[10];

	//

	for (i = 0; i < GFBITS; i++)
		out[i] = result[i];
}

static void vec_copy(uint64_t *out, const uint64_t *in) {
	int i;

	for (i = 0; i < GFBITS; i++)
		out[i] = in[i];
}

static uint64_t vec_or(const uint64_t *in) {
	int i;
	uint64_t ret = in[0];

	for (i = 1; i < GFBITS; i++)
		ret |= in[i];

	return ret;
}

static void vec_inv(uint64_t *out, const uint64_t *in) {
	uint64_t tmp_11[GFBITS];
	uint64_t tmp_1111[GFBITS];

	vec_copy(out, in);

	vec_sq(out, out);
	vec_mul(tmp_11, out, in); // 11

	vec_sq(out, tmp_11);
	vec_sq(out, out);
	vec_mul(tmp_1111, out, tmp_11); // 1111

	vec_sq(out, tmp_1111);
	vec_sq(out, out);
	vec_sq(out, out);
	vec_sq(out, out);
	vec_mul(out, out, tmp_1111); // 11111111

	vec_sq(out, out);
	vec_sq(out, out);
	vec_mul(out, out, tmp_11); // 1111111111

	vec_sq(out, out);
	vec_mul(out, out, in); // 11111111111

	vec_sq(out, out); // 111111111110
}
