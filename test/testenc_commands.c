/* C preprocessor input for producing the list of openssl encryption commands
   that should be available.  Note that we use "_" instead of "-" in the names
   so that each command looks like one symbol to the C preprocessor --
   -- otherwise spaces might be inserted. */

#ifndef NO_RC4
rc4
#endif

#ifndef NO_DES
des_cfb des_ede_cfb des_ede3_cfb
des_ofb des_ede_ofb des_ede3_ofb
des_ecb des_ede des_ede3 desx
des_cbc des_ede_cbc des_ede3_cbc
#endif

#ifndef NO_IDEA
idea_ecb idea_cfb idea_ofb idea_cbc
#endif

#ifndef NO_RC2
rc2_ecb rc2_cfb rc2_ofb rc2_cbc
#endif

#ifndef NO_BLOWFISH
bf_ecb bf_cfb bf_ofb bf_cbc
#endif

#ifndef NO_RC4
rc4
#endif

#ifndef NO_CAST
cast5_ecb cast5_cfb cast5_ofb cast5_cbc
#endif
