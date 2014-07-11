#!/usr/bin/perl -w
# Perl utility to run or verify FIPS 140-2 CAVP algorithm tests based on the
# pathnames of input algorithm test files actually present (the unqualified
# file names are consistent but the pathnames are not).
#

# FIPS test definitions
# List of all the unqualified file names we expect and command lines to run

# DSA tests
my @fips_dsa_test_list = (

    "DSA",

    [ "PQGGen",  "fips_dssvs pqg", "path:[^C]DSA/.*PQGGen" ],
    [ "KeyPair", "fips_dssvs keypair", "path:[^C]DSA/.*KeyPair" ],
    [ "SigGen",  "fips_dssvs siggen", "path:[^C]DSA/.*SigGen" ],
    [ "SigVer",  "fips_dssvs sigver", "path:[^C]DSA/.*SigVer" ]

);

my @fips_dsa_pqgver_test_list = (

    [ "PQGVer",  "fips_dssvs pqgver", "path:[^C]DSA/.*PQGVer" ]

);

# DSA2 tests
my @fips_dsa2_test_list = (

    "DSA2",

    [ "PQGGen",  "fips_dssvs pqg", "path:[^C]DSA2/.*PQGGen" ],
    [ "KeyPair", "fips_dssvs keypair", "path:[^C]DSA2/.*KeyPair" ],
    [ "SigGen",  "fips_dssvs siggen", "path:[^C]DSA2/.*SigGen" ],
    [ "SigVer",  "fips_dssvs sigver", "path:[^C]DSA2/.*SigVer" ],
    [ "PQGVer",  "fips_dssvs pqgver", "path:[^C]DSA2/.*PQGVer" ]

);

# ECDSA and ECDSA2 tests
my @fips_ecdsa_test_list = (

    "ECDSA",

    [ "KeyPair", "fips_ecdsavs KeyPair", "path:/ECDSA/.*KeyPair" ],
    [ "PKV",  "fips_ecdsavs PKV", "path:/ECDSA/.*PKV" ],
    [ "SigGen",  "fips_ecdsavs SigGen", "path:/ECDSA/.*SigGen" ],
    [ "SigVer",  "fips_ecdsavs SigVer", "path:/ECDSA/.*SigVer" ],

    "ECDSA2",

    [ "KeyPair", "fips_ecdsavs KeyPair", "path:/ECDSA2/.*KeyPair" ],
    [ "PKV",  "fips_ecdsavs PKV", "path:/ECDSA2/.*PKV" ],
    [ "SigGen",  "fips_ecdsavs SigGen", "path:/ECDSA2/.*SigGen" ],
    [ "SigVer",  "fips_ecdsavs SigVer", "path:/ECDSA2/.*SigVer" ],

);

# RSA tests

my @fips_rsa_test_list = (

    "RSA",

    [ "SigGen15",  "fips_rsastest" ],
    [ "SigVer15",  "fips_rsavtest" ],
    [ "SigVerRSA", "fips_rsavtest -x931" ],
    [ "KeyGenRSA", "fips_rsagtest" ],
    [ "SigGenRSA", "fips_rsastest -x931" ]

);

# Special cases for PSS. The filename itself is
# not sufficient to determine the test. Addditionally we
# need to examine the file contents to determine the salt length
# In these cases the test filename has (saltlen) appended.

# RSA PSS salt length 0 tests

my @fips_rsa_pss0_test_list = (

    [ "SigGenPSS(0)", "fips_rsastest -saltlen 0",
					'file:^\s*#\s*salt\s+len:\s+0\s*$' ],
    [ "SigVerPSS(0)", "fips_rsavtest -saltlen 0",
					'file:^\s*#\s*salt\s+len:\s+0\s*$' ],

);

# RSA PSS salt length 62 tests

my @fips_rsa_pss62_test_list = (
    [ "SigGenPSS(62)", "fips_rsastest -saltlen 62",
					'file:^\s*#\s*salt\s+len:\s+62\s*$' ],
    [ "SigVerPSS(62)", "fips_rsavtest -saltlen 62",
					'file:^\s*#\s*salt\s+len:\s+62\s*$' ],
);

# SHA tests

my @fips_sha_test_list = (

    "SHA",

    [ "SHA1LongMsg",    "fips_shatest" ],
    [ "SHA1Monte",      "fips_shatest" ],
    [ "SHA1ShortMsg",   "fips_shatest" ],
    [ "SHA224LongMsg",  "fips_shatest" ],
    [ "SHA224Monte",    "fips_shatest" ],
    [ "SHA224ShortMsg", "fips_shatest" ],
    [ "SHA256LongMsg",  "fips_shatest" ],
    [ "SHA256Monte",    "fips_shatest" ],
    [ "SHA256ShortMsg", "fips_shatest" ],
    [ "SHA384LongMsg",  "fips_shatest" ],
    [ "SHA384Monte",    "fips_shatest" ],
    [ "SHA384ShortMsg", "fips_shatest" ],
    [ "SHA512LongMsg",  "fips_shatest" ],
    [ "SHA512Monte",    "fips_shatest" ],
    [ "SHA512ShortMsg", "fips_shatest" ]

);

# HMAC

my @fips_hmac_test_list = (

    "HMAC",

    [ "HMAC", "fips_hmactest" ]

);

# CMAC

my @fips_cmac_test_list = (

    "CMAC",

    [ "CMACGenAES128", "fips_cmactest -a aes128 -g" ],
    [ "CMACVerAES128", "fips_cmactest -a aes128 -v" ],
    [ "CMACGenAES192", "fips_cmactest -a aes192 -g" ],
    [ "CMACVerAES192", "fips_cmactest -a aes192 -v" ],
    [ "CMACGenAES256", "fips_cmactest -a aes256 -g" ],
    [ "CMACVerAES256", "fips_cmactest -a aes256 -v" ],
    [ "CMACGenTDES3", "fips_cmactest -a tdes3 -g" ],
    [ "CMACVerTDES3", "fips_cmactest -a tdes3 -v" ],

);

# RAND tests, AES version

my @fips_rand_aes_test_list = (

    "RAND (AES)",

    [ "ANSI931_AES128MCT", "fips_rngvs mct" ],
    [ "ANSI931_AES192MCT", "fips_rngvs mct" ],
    [ "ANSI931_AES256MCT", "fips_rngvs mct" ],
    [ "ANSI931_AES128VST", "fips_rngvs vst" ],
    [ "ANSI931_AES192VST", "fips_rngvs vst" ],
    [ "ANSI931_AES256VST", "fips_rngvs vst" ]

);

# RAND tests, DES2 version

my @fips_rand_des2_test_list = (

    "RAND (DES2)",

    [ "ANSI931_TDES2MCT", "fips_rngvs mct" ],
    [ "ANSI931_TDES2VST", "fips_rngvs vst" ]

);

# AES tests

my @fips_aes_test_list = (

    "AES",

    [ "CBCGFSbox128",     "fips_aesavs -f" ],
    [ "CBCGFSbox192",     "fips_aesavs -f" ],
    [ "CBCGFSbox256",     "fips_aesavs -f" ],
    [ "CBCKeySbox128",    "fips_aesavs -f" ],
    [ "CBCKeySbox192",    "fips_aesavs -f" ],
    [ "CBCKeySbox256",    "fips_aesavs -f" ],
    [ "CBCMCT128",        "fips_aesavs -f" ],
    [ "CBCMCT192",        "fips_aesavs -f" ],
    [ "CBCMCT256",        "fips_aesavs -f" ],
    [ "CBCMMT128",        "fips_aesavs -f" ],
    [ "CBCMMT192",        "fips_aesavs -f" ],
    [ "CBCMMT256",        "fips_aesavs -f" ],
    [ "CBCVarKey128",     "fips_aesavs -f" ],
    [ "CBCVarKey192",     "fips_aesavs -f" ],
    [ "CBCVarKey256",     "fips_aesavs -f" ],
    [ "CBCVarTxt128",     "fips_aesavs -f" ],
    [ "CBCVarTxt192",     "fips_aesavs -f" ],
    [ "CBCVarTxt256",     "fips_aesavs -f" ],
    [ "CFB128GFSbox128",  "fips_aesavs -f" ],
    [ "CFB128GFSbox192",  "fips_aesavs -f" ],
    [ "CFB128GFSbox256",  "fips_aesavs -f" ],
    [ "CFB128KeySbox128", "fips_aesavs -f" ],
    [ "CFB128KeySbox192", "fips_aesavs -f" ],
    [ "CFB128KeySbox256", "fips_aesavs -f" ],
    [ "CFB128MCT128",     "fips_aesavs -f" ],
    [ "CFB128MCT192",     "fips_aesavs -f" ],
    [ "CFB128MCT256",     "fips_aesavs -f" ],
    [ "CFB128MMT128",     "fips_aesavs -f" ],
    [ "CFB128MMT192",     "fips_aesavs -f" ],
    [ "CFB128MMT256",     "fips_aesavs -f" ],
    [ "CFB128VarKey128",  "fips_aesavs -f" ],
    [ "CFB128VarKey192",  "fips_aesavs -f" ],
    [ "CFB128VarKey256",  "fips_aesavs -f" ],
    [ "CFB128VarTxt128",  "fips_aesavs -f" ],
    [ "CFB128VarTxt192",  "fips_aesavs -f" ],
    [ "CFB128VarTxt256",  "fips_aesavs -f" ],
    [ "CFB8GFSbox128",    "fips_aesavs -f" ],
    [ "CFB8GFSbox192",    "fips_aesavs -f" ],
    [ "CFB8GFSbox256",    "fips_aesavs -f" ],
    [ "CFB8KeySbox128",   "fips_aesavs -f" ],
    [ "CFB8KeySbox192",   "fips_aesavs -f" ],
    [ "CFB8KeySbox256",   "fips_aesavs -f" ],
    [ "CFB8MCT128",       "fips_aesavs -f" ],
    [ "CFB8MCT192",       "fips_aesavs -f" ],
    [ "CFB8MCT256",       "fips_aesavs -f" ],
    [ "CFB8MMT128",       "fips_aesavs -f" ],
    [ "CFB8MMT192",       "fips_aesavs -f" ],
    [ "CFB8MMT256",       "fips_aesavs -f" ],
    [ "CFB8VarKey128",    "fips_aesavs -f" ],
    [ "CFB8VarKey192",    "fips_aesavs -f" ],
    [ "CFB8VarKey256",    "fips_aesavs -f" ],
    [ "CFB8VarTxt128",    "fips_aesavs -f" ],
    [ "CFB8VarTxt192",    "fips_aesavs -f" ],
    [ "CFB8VarTxt256",    "fips_aesavs -f" ],

    [ "ECBGFSbox128",  "fips_aesavs -f" ],
    [ "ECBGFSbox192",  "fips_aesavs -f" ],
    [ "ECBGFSbox256",  "fips_aesavs -f" ],
    [ "ECBKeySbox128", "fips_aesavs -f" ],
    [ "ECBKeySbox192", "fips_aesavs -f" ],
    [ "ECBKeySbox256", "fips_aesavs -f" ],
    [ "ECBMCT128",     "fips_aesavs -f" ],
    [ "ECBMCT192",     "fips_aesavs -f" ],
    [ "ECBMCT256",     "fips_aesavs -f" ],
    [ "ECBMMT128",     "fips_aesavs -f" ],
    [ "ECBMMT192",     "fips_aesavs -f" ],
    [ "ECBMMT256",     "fips_aesavs -f" ],
    [ "ECBVarKey128",  "fips_aesavs -f" ],
    [ "ECBVarKey192",  "fips_aesavs -f" ],
    [ "ECBVarKey256",  "fips_aesavs -f" ],
    [ "ECBVarTxt128",  "fips_aesavs -f" ],
    [ "ECBVarTxt192",  "fips_aesavs -f" ],
    [ "ECBVarTxt256",  "fips_aesavs -f" ],
    [ "OFBGFSbox128",  "fips_aesavs -f" ],
    [ "OFBGFSbox192",  "fips_aesavs -f" ],
    [ "OFBGFSbox256",  "fips_aesavs -f" ],
    [ "OFBKeySbox128", "fips_aesavs -f" ],
    [ "OFBKeySbox192", "fips_aesavs -f" ],
    [ "OFBKeySbox256", "fips_aesavs -f" ],
    [ "OFBMCT128",     "fips_aesavs -f" ],
    [ "OFBMCT192",     "fips_aesavs -f" ],
    [ "OFBMCT256",     "fips_aesavs -f" ],
    [ "OFBMMT128",     "fips_aesavs -f" ],
    [ "OFBMMT192",     "fips_aesavs -f" ],
    [ "OFBMMT256",     "fips_aesavs -f" ],
    [ "OFBVarKey128",  "fips_aesavs -f" ],
    [ "OFBVarKey192",  "fips_aesavs -f" ],
    [ "OFBVarKey256",  "fips_aesavs -f" ],
    [ "OFBVarTxt128",  "fips_aesavs -f" ],
    [ "OFBVarTxt192",  "fips_aesavs -f" ],
    [ "OFBVarTxt256",  "fips_aesavs -f" ]

);

my @fips_aes_cfb1_test_list = (

    # AES CFB1 tests

    [ "CFB1GFSbox128",  "fips_aesavs -f" ],
    [ "CFB1GFSbox192",  "fips_aesavs -f" ],
    [ "CFB1GFSbox256",  "fips_aesavs -f" ],
    [ "CFB1KeySbox128", "fips_aesavs -f" ],
    [ "CFB1KeySbox192", "fips_aesavs -f" ],
    [ "CFB1KeySbox256", "fips_aesavs -f" ],
    [ "CFB1MCT128",     "fips_aesavs -f" ],
    [ "CFB1MCT192",     "fips_aesavs -f" ],
    [ "CFB1MCT256",     "fips_aesavs -f" ],
    [ "CFB1MMT128",     "fips_aesavs -f" ],
    [ "CFB1MMT192",     "fips_aesavs -f" ],
    [ "CFB1MMT256",     "fips_aesavs -f" ],
    [ "CFB1VarKey128",  "fips_aesavs -f" ],
    [ "CFB1VarKey192",  "fips_aesavs -f" ],
    [ "CFB1VarKey256",  "fips_aesavs -f" ],
    [ "CFB1VarTxt128",  "fips_aesavs -f" ],
    [ "CFB1VarTxt192",  "fips_aesavs -f" ],
    [ "CFB1VarTxt256",  "fips_aesavs -f" ]

);

my @fips_aes_ccm_test_list = (

    # AES CCM tests

    "AES CCM",

    [ "DVPT128",  "fips_gcmtest -ccm" ],
    [ "DVPT192",  "fips_gcmtest -ccm" ],
    [ "DVPT256",  "fips_gcmtest -ccm" ],
    [ "VADT128",  "fips_gcmtest -ccm" ],
    [ "VADT192",  "fips_gcmtest -ccm" ],
    [ "VADT256",  "fips_gcmtest -ccm" ],
    [ "VNT128",  "fips_gcmtest -ccm" ],
    [ "VNT192",  "fips_gcmtest -ccm" ],
    [ "VNT256",  "fips_gcmtest -ccm" ],
    [ "VPT128",  "fips_gcmtest -ccm" ],
    [ "VPT192",  "fips_gcmtest -ccm" ],
    [ "VPT256",  "fips_gcmtest -ccm" ],
    [ "VTT128",  "fips_gcmtest -ccm" ],
    [ "VTT192",  "fips_gcmtest -ccm" ],
    [ "VTT256",  "fips_gcmtest -ccm" ]

);

my @fips_aes_gcm_test_list = (

    # AES GCM tests

    "AES GCM",

    [ "gcmDecrypt128",  "fips_gcmtest -decrypt" ],
    [ "gcmDecrypt192",  "fips_gcmtest -decrypt" ],
    [ "gcmDecrypt256",  "fips_gcmtest -decrypt" ],
    [ "gcmEncryptIntIV128",  "fips_gcmtest -encrypt" ],
    [ "gcmEncryptIntIV192",  "fips_gcmtest -encrypt" ],
    [ "gcmEncryptIntIV256",  "fips_gcmtest -encrypt" ],

);

my @fips_aes_xts_test_list = (
    # AES XTS tests

    "AES XTS",

    [ "XTSGenAES128",  "fips_gcmtest -xts" ],
    [ "XTSGenAES256",  "fips_gcmtest -xts" ],

);

# Triple DES tests

my @fips_des3_test_list = (

    "Triple DES",

    [ "TCBCinvperm",   "fips_desmovs -f" ],
    [ "TCBCMMT1",      "fips_desmovs -f" ],
    [ "TCBCMMT2",      "fips_desmovs -f" ],
    [ "TCBCMMT3",      "fips_desmovs -f" ],
    [ "TCBCMonte1",    "fips_desmovs -f" ],
    [ "TCBCMonte2",    "fips_desmovs -f" ],
    [ "TCBCMonte3",    "fips_desmovs -f" ],
    [ "TCBCpermop",    "fips_desmovs -f" ],
    [ "TCBCsubtab",    "fips_desmovs -f" ],
    [ "TCBCvarkey",    "fips_desmovs -f" ],
    [ "TCBCvartext",   "fips_desmovs -f" ],
    [ "TCFB64invperm", "fips_desmovs -f" ],
    [ "TCFB64MMT1",    "fips_desmovs -f" ],
    [ "TCFB64MMT2",    "fips_desmovs -f" ],
    [ "TCFB64MMT3",    "fips_desmovs -f" ],
    [ "TCFB64Monte1",  "fips_desmovs -f" ],
    [ "TCFB64Monte2",  "fips_desmovs -f" ],
    [ "TCFB64Monte3",  "fips_desmovs -f" ],
    [ "TCFB64permop",  "fips_desmovs -f" ],
    [ "TCFB64subtab",  "fips_desmovs -f" ],
    [ "TCFB64varkey",  "fips_desmovs -f" ],
    [ "TCFB64vartext", "fips_desmovs -f" ],
    [ "TCFB8invperm",  "fips_desmovs -f" ],
    [ "TCFB8MMT1",     "fips_desmovs -f" ],
    [ "TCFB8MMT2",     "fips_desmovs -f" ],
    [ "TCFB8MMT3",     "fips_desmovs -f" ],
    [ "TCFB8Monte1",   "fips_desmovs -f" ],
    [ "TCFB8Monte2",   "fips_desmovs -f" ],
    [ "TCFB8Monte3",   "fips_desmovs -f" ],
    [ "TCFB8permop",   "fips_desmovs -f" ],
    [ "TCFB8subtab",   "fips_desmovs -f" ],
    [ "TCFB8varkey",   "fips_desmovs -f" ],
    [ "TCFB8vartext",  "fips_desmovs -f" ],
    [ "TECBinvperm",   "fips_desmovs -f" ],
    [ "TECBMMT1",      "fips_desmovs -f" ],
    [ "TECBMMT2",      "fips_desmovs -f" ],
    [ "TECBMMT3",      "fips_desmovs -f" ],
    [ "TECBMonte1",    "fips_desmovs -f" ],
    [ "TECBMonte2",    "fips_desmovs -f" ],
    [ "TECBMonte3",    "fips_desmovs -f" ],
    [ "TECBpermop",    "fips_desmovs -f" ],
    [ "TECBsubtab",    "fips_desmovs -f" ],
    [ "TECBvarkey",    "fips_desmovs -f" ],
    [ "TECBvartext",   "fips_desmovs -f" ],
    [ "TOFBinvperm",   "fips_desmovs -f" ],
    [ "TOFBMMT1",      "fips_desmovs -f" ],
    [ "TOFBMMT2",      "fips_desmovs -f" ],
    [ "TOFBMMT3",      "fips_desmovs -f" ],
    [ "TOFBMonte1",    "fips_desmovs -f" ],
    [ "TOFBMonte2",    "fips_desmovs -f" ],
    [ "TOFBMonte3",    "fips_desmovs -f" ],
    [ "TOFBpermop",    "fips_desmovs -f" ],
    [ "TOFBsubtab",    "fips_desmovs -f" ],
    [ "TOFBvarkey",    "fips_desmovs -f" ],
    [ "TOFBvartext",   "fips_desmovs -f" ]

);

my @fips_des3_cfb1_test_list = (

    # DES3 CFB1 tests

    [ "TCFB1invperm",  "fips_desmovs -f" ],
    [ "TCFB1MMT1",     "fips_desmovs -f" ],
    [ "TCFB1MMT2",     "fips_desmovs -f" ],
    [ "TCFB1MMT3",     "fips_desmovs -f" ],
    [ "TCFB1Monte1",   "fips_desmovs -f" ],
    [ "TCFB1Monte2",   "fips_desmovs -f" ],
    [ "TCFB1Monte3",   "fips_desmovs -f" ],
    [ "TCFB1permop",   "fips_desmovs -f" ],
    [ "TCFB1subtab",   "fips_desmovs -f" ],
    [ "TCFB1varkey",   "fips_desmovs -f" ],
    [ "TCFB1vartext",  "fips_desmovs -f" ],

);

my @fips_drbg_test_list = (

    # SP800-90 DRBG tests
    "SP800-90 DRBG",
    [ "CTR_DRBG",   "fips_drbgvs" ],
    [ "Hash_DRBG",  "fips_drbgvs" ],
    [ "HMAC_DRBG",  "fips_drbgvs" ]

);

my @fips_dh_test_list = (

    # DH
    "DH Ephemeral Primitives Only",
    [ "KASValidityTest_FFCEphem_NOKC_ZZOnly_init",   "fips_dhvs dhver" ],
    [ "KASValidityTest_FFCEphem_NOKC_ZZOnly_resp",   "fips_dhvs dhver" ],

);

my @fips_ecdh_test_list = (

    # ECDH
    "ECDH Ephemeral Primitives Only",
    [ "KAS_ECC_CDH_PrimitiveTest", "fips_ecdhvs ecdhgen" ],
#    [ "KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init",
#							"fips_ecdhvs ecdhver" ],
#    [ "KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_resp",
#							"fips_ecdhvs ecdhver" ],

);


# Verification special cases.
# In most cases the output of a test is deterministic and
# it can be compared to a known good result. A few involve
# the genration and use of random keys and the output will
# be different each time. In thoses cases we perform special tests
# to simply check their consistency. For example signature generation
# output will be run through signature verification to see if all outputs
# show as valid.
#

my %verify_special = (
    "DSA:PQGGen"        => "fips_dssvs pqgver",
    "DSA:KeyPair"       => "fips_dssvs keyver",
    "DSA:SigGen"        => "fips_dssvs sigver",
    "DSA2:PQGGen"        => "fips_dssvs pqgver",
    "DSA2:KeyPair"       => "fips_dssvs keyver",
    "DSA2:SigGen"        => "fips_dssvs sigver",
    "ECDSA:KeyPair"     => "fips_ecdsavs PKV",
    "ECDSA:SigGen"      => "fips_ecdsavs SigVer",
    "ECDSA2:KeyPair"    => "fips_ecdsavs PKV",
    "ECDSA2:SigGen"     => "fips_ecdsavs SigVer",
    "RSA:SigGen15"      => "fips_rsavtest",
    "RSA:SigGenRSA"     => "fips_rsavtest -x931",
    "RSA:SigGenPSS(0)"  => "fips_rsavtest -saltlen 0",
    "RSA:SigGenPSS(62)" => "fips_rsavtest -saltlen 62",
    "ECDH Ephemeral Primitives Only:KAS_ECC_CDH_PrimitiveTest" => "skip"
);

my $win32  = $^O =~ m/mswin/i;
my $onedir = 0;
my $filter = "";
my $tvdir;
my $tprefix;
my $sfprefix = "";
my $debug          = 0;
my $quiet          = 0;
my $notest         = 0;
my $verify         = 1;
my $rspdir         = "resp";
my $ignore_missing = 0;
my $ignore_bogus   = 0;
my $bufout         = '';
my $list_tests     = 0;
my $minimal_script = 0;
my $outfile        = '';
my $no_warn_missing = 0;
my $no_warn_bogus = 0;
my $rmcmd = "rm -rf";
my $mkcmd = "mkdir";
my $cmpall = 0;

my %fips_enabled = (
    "dsa"        => 1,
    "dsa2"       => 2,
    "dsa-pqgver"  => 2,
    "ecdsa"      => 2,
    "rsa"        => 1,
    "rsa-pss0"  => 2,
    "rsa-pss62" => 1,
    "sha"        => 1,
    "hmac"       => 1,
    "cmac"       => 2,
    "rand-aes"  => 1,
    "rand-des2" => 0,
    "aes"        => 1,
    "aes-cfb1"  => 2,
    "des3"       => 1,
    "des3-cfb1" => 2,
    "drbg"	=> 2,
    "aes-ccm"	=> 2,
    "aes-xts"	=> 2,
    "aes-gcm"	=> 2,
    "dh"	=> 0,
    "ecdh"	=> 2,
    "v2"	=> 1,
);

foreach (@ARGV) {
    if ( $_ eq "--win32" ) {
        $win32 = 1;
    }
    elsif ( $_ eq "--onedir" ) {
        $onedir = 1;
    }
    elsif ( $_ eq "--debug" ) {
        $debug = 1;
    }
    elsif ( $_ eq "--quiet-missing" ) {
        $ignore_missing = 1;
        $no_warn_missing = 1;
    }
    elsif ( $_ eq "--ignore-missing" ) {
        $ignore_missing = 1;
    }
    elsif ( $_ eq "--quiet-bogus" ) {
        $ignore_bogus = 1;
	$no_warn_bogus = 1;
    }
    elsif ( $_ eq "--ignore-bogus" ) {
        $ignore_bogus = 1;
    }
    elsif ( $_ eq "--minimal-script" ) {
        $minimal_script = 1;
    }
    elsif (/--generate-script=(.*)$/) {
        $outfile = $1;
	$verify = 0;
    } elsif ( $_ eq "--generate" ) {
        $verify = 0;
    }
    elsif ( $_ eq "--compare-all" ) {
        $cmpall = 1;
    }
    elsif ( $_ eq "--notest" ) {
        $notest = 1;
    }
    elsif ( $_ eq "--quiet" ) {
        $quiet = 1;
    }
    elsif (/--dir=(.*)$/) {
        $tvdir = $1;
    }
    elsif (/--rspdir=(.*)$/) {
        $rspdir = $1;
    }
    elsif (/--tprefix=(.*)$/) {
        $tprefix = $1;
    }
    elsif (/^--disable-all$/) {
	foreach (keys %fips_enabled) {
		$fips_enabled{$_} = 0;
	}
    }
    elsif (/^--(enable|disable)-(.*)$/) {
        if ( !exists $fips_enabled{$2} ) {
            print STDERR "Unknown test $2\n";
	    exit(1);
        }
        if ( $1 eq "enable" ) {
            $fips_enabled{$2} = 1;
        }
        else {
            $fips_enabled{$2} = 0;
        }
    }
    elsif (/--filter=(.*)$/) {
        $filter = $1;
    }
    elsif (/--rm=(.*)$/) {
        $rmcmd = $1;
    }
    elsif (/--script-tprefix=(.*)$/) {
        $stprefix = $1;
    }
    elsif (/--script-fprefix=(.*)$/) {
        $sfprefix = $1;
    }
    elsif (/--mkdir=(.*)$/) {
        $mkcmd = $1;
    }
    elsif (/^--list-tests$/) {
        $list_tests = 1;
    }
    else {
        Help();
        exit(1);
    }
}

my @fips_test_list;


if (!$fips_enabled{"v2"}) {
	foreach (keys %fips_enabled) {
		$fips_enabled{$_} = 0 if $fips_enabled{$_} == 2;
	}
}

push @fips_test_list, @fips_dsa_test_list       if $fips_enabled{"dsa"};
push @fips_test_list, @fips_dsa_pqgver_test_list if $fips_enabled{"dsa-pqgver"};
push @fips_test_list, @fips_dsa2_test_list      if $fips_enabled{"dsa2"};
push @fips_test_list, @fips_ecdsa_test_list     if $fips_enabled{"ecdsa"};
push @fips_test_list, @fips_rsa_test_list       if $fips_enabled{"rsa"};
push @fips_test_list, @fips_rsa_pss0_test_list  if $fips_enabled{"rsa-pss0"};
push @fips_test_list, @fips_rsa_pss62_test_list if $fips_enabled{"rsa-pss62"};
push @fips_test_list, @fips_sha_test_list       if $fips_enabled{"sha"};
push @fips_test_list, @fips_hmac_test_list      if $fips_enabled{"hmac"};
push @fips_test_list, @fips_cmac_test_list      if $fips_enabled{"cmac"};
push @fips_test_list, @fips_rand_aes_test_list  if $fips_enabled{"rand-aes"};
push @fips_test_list, @fips_rand_des2_test_list if $fips_enabled{"rand-des2"};
push @fips_test_list, @fips_aes_test_list       if $fips_enabled{"aes"};
push @fips_test_list, @fips_aes_cfb1_test_list  if $fips_enabled{"aes-cfb1"};
push @fips_test_list, @fips_des3_test_list      if $fips_enabled{"des3"};
push @fips_test_list, @fips_des3_cfb1_test_list if $fips_enabled{"des3-cfb1"};
push @fips_test_list, @fips_drbg_test_list	if $fips_enabled{"drbg"};
push @fips_test_list, @fips_aes_ccm_test_list	if $fips_enabled{"aes-ccm"};
push @fips_test_list, @fips_aes_gcm_test_list	if $fips_enabled{"aes-gcm"};
push @fips_test_list, @fips_aes_xts_test_list	if $fips_enabled{"aes-xts"};
push @fips_test_list, @fips_dh_test_list	if $fips_enabled{"dh"};
push @fips_test_list, @fips_ecdh_test_list	if $fips_enabled{"ecdh"};

if ($list_tests) {
    my ( $test, $en );
    print "=====TEST LIST=====\n";
    foreach $test ( sort keys %fips_enabled ) {
        $en = $fips_enabled{$test};
        $test =~ tr/[a-z]/[A-Z]/;
        printf "%-10s %s\n", $test, $en ? "enabled" : "disabled";
    }
    exit(0);
}

foreach (@fips_test_list) {
    next unless ref($_);
    my $nm = $$_[0];
    $$_[3] = "";
    $$_[4] = "";
}

$tvdir = "." unless defined $tvdir;

if ($win32) {
    if ( !defined $tprefix ) {
        if ($onedir) {
            $tprefix = ".\\";
        }
        else {
            $tprefix = "..\\out32dll\\";
        }
    }
}
else {
    if ($onedir) {
        $tprefix       = "./" unless defined $tprefix;
    }
    else {
        $tprefix       = "../test/" unless defined $tprefix;
    }
}

sanity_check_exe( $win32, $tprefix) if $outfile eq "";

find_files( $filter, $tvdir );

sanity_check_files();

my ( $runerr, $cmperr, $cmpok, $scheckrunerr, $scheckerr, $scheckok, $skipcnt )
  = ( 0, 0, 0, 0, 0, 0, 0 );

exit(0) if $notest;
print "Outputting commands to $outfile\n" if $outfile ne "";
run_tests( $verify, $win32, $tprefix, $filter, $tvdir, $outfile );

if ($verify) {
    print "ALGORITHM TEST VERIFY SUMMARY REPORT:\n";
    print "Tests skipped due to missing files:        $skipcnt\n";
    print "Algorithm test program execution failures: $runerr\n";
    print "Test comparisons successful:               $cmpok\n";
    print "Test comparisons failed:                   $cmperr\n";
    print "Test sanity checks successful:             $scheckok\n";
    print "Test sanity checks failed:                 $scheckerr\n";
    print "Sanity check program execution failures:   $scheckrunerr\n";

    if ( $runerr || $cmperr || $scheckrunerr || $scheckerr ) {
        print "***TEST FAILURE***\n";
    }
    else {
        print "***ALL TESTS SUCCESSFUL***\n";
    }
}
elsif ($outfile eq "") {
    print "ALGORITHM TEST SUMMARY REPORT:\n";
    print "Tests skipped due to missing files:        $skipcnt\n";
    print "Algorithm test program execution failures: $runerr\n";

    if ($runerr) {
        print "***TEST FAILURE***\n";
    }
    else {
        print "***ALL TESTS SUCCESSFUL***\n";
    }
}

#--------------------------------
sub Help {
    ( my $cmd ) = ( $0 =~ m#([^/]+)$# );
    print <<EOF;
$cmd: generate run CAVP algorithm tests
	--debug                       Enable debug output
	--dir=<dirname>               Optional root for *.req file search
	--filter=<regexp>	      Regex for input files of interest
	--onedir <dirname>            Assume all components in current directory
	--rspdir=<dirname>            Name of subdirectories containing *.rsp files, default "resp"
	--tprefix=<prefix>            Pathname prefix for directory containing test programs
	--ignore-bogus                Ignore duplicate or bogus files
	--ignore-missing              Ignore missing test files
	--quiet                       Shhh....
	--quiet-bogus                 Skip unrecognized file warnings
	--quiet-missing               Skip missing request file warnings
	--generate                    Generate algorithm test output
	--generate-script=<filename>  Generate script to call algorithm programs
	--minimal-script              Simplest possible output for --generate-script
	--win32                       Win32 environment
	--compare-all                 Verify unconditionally for all tests
	--list-tests                  Show individual tests
	--mkdir=<cmd>                 Specify "mkdir" command
	--notest                      Exit before running tests
	--rm=<cmd>                    Specify "rm" command
	--script-tprefix              Pathname prefix for --generate-script output
	--enable-<alg>		      Enable algorithm set <alg>.
	--disable-<alg>		      Disable algorithm set <alg>.
	Where <alg> can be one of:
EOF

while (my ($key, $value) = each %fips_enabled)
	{
	printf "\t\t%-20s(%s by default)\n", $key ,
			$value == 1 ? "enabled" : "disabled";
	}
}

# Sanity check to see if all necessary executables exist

sub sanity_check_exe {
    my ( $win32, $tprefix, ) = @_;
    my %exe_list;
    my $bad = 0;
    foreach (@fips_test_list) {
        next unless ref($_);
        my $cmd = $_->[1];
        $cmd =~ s/ .*$//;
        $cmd = $tprefix . $cmd;
        $cmd .= ".exe" if $win32;
        $exe_list{$cmd} = 1;
    }

    foreach ( sort keys %exe_list ) {
        if ( !-f $_ ) {
            print STDERR "ERROR: can't find executable $_\n";
            $bad = 1;
        }
    }
    if ($bad) {
        print STDERR "FATAL ERROR: executables missing\n";
        exit(1);
    }
    elsif ($debug) {
        print STDERR "Executable sanity check passed OK\n";
    }
}

# Search for all request and response files

sub find_files {
    my ( $filter, $dir ) = @_;
    my ( $dirh, $testname, $tref );
    opendir( $dirh, $dir );
    while ( $_ = readdir($dirh) ) {
        next if ( $_ eq "." || $_ eq ".." );
        $_ = "$dir/$_";
        if ( -f "$_" ) {
            if (/\/([^\/]*)\.rsp$/) {
		$tref = find_test($1, $_);
                if ( defined $tref ) {
		    $testname = $$tref[0];
                    if ( $$tref[4] eq "" ) {
                        $$tref[4] = $_;
                    }
                    else {
                        print STDERR
"WARNING: duplicate response file $_ for test $testname\n";
                        $nbogus++;
                    }
                }
                else {
                    print STDERR "WARNING: bogus file $_\n" unless $no_warn_bogus;
                    $nbogus++;
                }
            }
            next unless /$filter.*\.req$/i;
            if (/\/([^\/]*)\.req$/) {
		$tref = find_test($1, $_);
                if ( defined $tref ) {
		    $testname = $$tref[0];
                    if ( $$tref[3] eq "" ) {
                        $$tref[3] = $_;
                    }
                    else {
                        print STDERR
"WARNING: duplicate request file $_ for test $testname\n";
                        $nbogus++;
                    }

                }
                elsif ( !/SHAmix\.req$/ ) {
                    print STDERR "WARNING: unrecognized filename $_\n" unless $no_warn_bogus;
                    $nbogus++;
                }
            }
        }
        elsif ( -d "$_" ) {
            find_files( $filter, $_ );
        }
    }
    closedir($dirh);
}
#
# Find test based on filename.
# In ambiguous cases search file contents for a match
#

sub find_test {
    my ( $test, $path ) = @_;
    foreach $tref (@fips_test_list) {
        next unless ref($tref);
        my ( $tst, $cmd, $excmd, $req, $resp ) = @$tref;
	my $regexp;
	$tst =~ s/\(.*$//;
	$test =~ s/_186-2//;
	if (defined $excmd) {
		if ($excmd =~ /^path:(.*)$/) {
			my $fmatch = $1;
			return $tref if ($path =~ /$fmatch/);
			next;
		}
		elsif ($excmd =~ /^file:(.*)$/) {
			$regexp = $1;
		}
	}
	if ($test eq $tst) {
		return $tref if (!defined $regexp);
		my $found = 0;
		my $line;
        	open( IN, $path ) || die "Can't Open File $path";
        	while ($line = <IN>) {
            	    if ($line =~ /$regexp/i) {
			$found = 1;
			last;
		    }
		}
		close IN;
		return $tref if $found == 1;
	}
    }
    return undef;
}

sub sanity_check_files {
    my $bad = 0;
    foreach (@fips_test_list) {
        next unless ref($_);
        my ( $tst, $cmd, $regexp, $req, $resp ) = @$_;

        #print STDERR "FILES $tst, $cmd, $req, $resp\n";
        if ( $req eq "" ) {
            print STDERR "WARNING: missing request file for $tst\n" unless $no_warn_missing;
            $bad = 1;
            next;
        }
        if ( $verify && $resp eq "" ) {
            print STDERR "WARNING: no response file for test $tst\n";
            $bad = 1;
        }
        elsif ( !$verify && $resp ne "" ) {
            print STDERR "WARNING: response file $resp will be overwritten\n";
        }
    }
    if ($bad) {
        print STDERR "ERROR: test vector file set not complete\n";
        exit(1) unless $ignore_missing;
    }
    if ($nbogus) {
        print STDERR
          "ERROR: $nbogus bogus or duplicate request and response files\n";
        exit(1) unless $ignore_bogus;
    }
    if ( $debug && !$nbogus && !$bad ) {
        print STDERR "test vector file set complete\n";
    }
}

sub run_tests {
    my ( $verify, $win32, $tprefix, $filter, $tvdir, $outfile ) = @_;
    my ( $tname, $tref );
    my $bad = 0;
    my $lastdir = "";
    $stprefix = $tprefix unless defined $stprefix;
    if ($outfile ne "") {
	open OUT, ">$outfile" || die "Can't open $outfile";
    }
    if ($outfile ne "" && !$minimal_script) {
        if ($win32) {
	    print OUT <<\END;
@echo off
rem Test vector run script
rem Auto generated by fipsalgtest.pl script
rem Do not edit

echo Running Algorithm Tests

END
	} else {
	    print OUT <<END;
#!/bin/sh

# Test vector run script
# Auto generated by fipsalgtest.pl script
# Do not edit

echo Running Algorithm Tests

RM="$rmcmd";
MKDIR="$mkcmd";
TPREFIX=$stprefix

END
	}

    }

    my $ttype = "";

    foreach (@fips_test_list) {
        if ( !ref($_) ) {
	    if ($outfile ne "") {
		print "Generating script for $_ tests\n";
		print OUT "\n\n\necho \"Running $_ tests\"\n" unless $minimal_script;
	    } else {	
            	print "Running $_ tests\n" unless $quiet;
	    }
	    $ttype = $_;
            next;
        }
        my ( $tname, $tcmd, $regexp, $req, $rsp ) = @$_;
        my $out = $rsp;
        if ($verify) {
            $out =~ s/\.rsp$/.tst/;
        }
        if ( $req eq "" ) {
            print STDERR
              "WARNING: Request file for $tname missing: test skipped\n" unless $no_warn_missing;
            $skipcnt++;
            next;
        }
        if ( $verify && $rsp eq "" ) {
            print STDERR
              "WARNING: Response file for $tname missing: test skipped\n";
            $skipcnt++;
            next;
        }
        elsif ( !$verify ) {
            if ( $rsp ne "" ) {
                print STDERR "WARNING: Response file for $tname deleted\n";
                unlink $rsp;
            }
            $out = $req;
            $out =~ s|/req/(\S+)\.req|/$rspdir/$1.rsp|;
            my $outdir = $out;
            $outdir =~ s|/[^/]*$||;
            if ( !-d $outdir  && ($outfile eq "" || $minimal_script)) {
                print STDERR "DEBUG: Creating directory $outdir\n" if $debug;
                mkdir($outdir) || die "Can't create directory $outdir";
            }
	    if ($outfile ne "") {
	    	if ($win32) {
		    $outdir =~ tr|/|\\|;
		    $req =~ tr|/|\\|;
		    $out =~ tr|/|\\|;
	    	}
		if ($outdir ne $lastdir && !$minimal_script) {
		    if ($win32) {
		    print OUT <<END
if exist \"$outdir\" rd /s /q "$outdir"
md \"$outdir\"

END
		    } else {
		    print OUT <<END
\$RM \"$outdir\"
\$MKDIR \"$outdir\"

END
		    }
		$lastdir = $outdir;
		}
            }
        }
        my $cmd = "$tcmd \"$sfprefix$req\" \"$sfprefix$out\"";
        print STDERR "DEBUG: running test $tname\n" if ( $debug && !$verify );
	if ($outfile ne "") {
	    if ($minimal_script) {
		print OUT "$stprefix$cmd\n";
	    } else {
		print OUT "echo \"    running $tname test\"\n" unless $minimal_script;
		print OUT "\${TPREFIX}$cmd\n";
	    }
        } else {
            $cmd = "$tprefix$cmd";
            system($cmd);
            if ( $? != 0 ) {
            	print STDERR
                     "WARNING: error executing test $tname for command: $cmd\n";
                $runerr++;
                next;
            }
        }
        if ($verify) {
            if ( exists $verify_special{"$ttype:$tname"} && !$cmpall) {
                my $vout = $rsp;
                $vout =~ s/\.rsp$/.ver/;
                $tcmd = $verify_special{"$ttype:$tname"};
		if ($tcmd eq "skip") {
			print STDERR "DEBUG: No verify possible: skipped.\n" if $debug;
			$scheckok++;
			next;
		}
                $cmd  = "$tprefix$tcmd ";
                $cmd .= "\"$out\" \"$vout\"";
                system($cmd);
                if ( $? != 0 ) {
                    print STDERR
                      "WARNING: error executing verify test $tname $cmd\n";
                    $scheckrunerr++;
                    next;
                }
                my ( $fcount, $pcount ) = ( 0, 0 );
                open VER, "$vout";
                while (<VER>) {
                    if (/^Result\s*=\s*(\S*)\s*$/i)

                    {
                        if ( $1 eq "F" ) {
                            $fcount++;
                        }
                        else {
                            $pcount++;
                        }
                    }
                }
                close VER;

                unlink $vout;
                if ( $fcount || $debug ) {
                    print STDERR "DEBUG: $tname, Pass=$pcount, Fail=$fcount\n";
                }
                if ( $fcount || !$pcount ) {
                    $scheckerr++;
                }
                else {
                    $scheckok++;
                }

            }
            elsif ( !cmp_file( $tname, $rsp, $out ) ) {
                $cmperr++;
            }
            else {
                $cmpok++;
            }
            unlink $out;
        }
    }
    if ($outfile ne "") {
	print OUT "\n\necho All Tests Completed\n" unless $minimal_script;
    	close OUT;
    }
}

sub cmp_file {
    my ( $tname, $rsp, $tst ) = @_;
    my ( $rspf,    $tstf );
    my ( $rspline, $tstline );
    my $monte = 0;
    if ( !open( $rspf, $rsp ) ) {
        print STDERR "ERROR: can't open request file $rsp\n";
        return 0;
    }
    if ( !open( $tstf, $tst ) ) {
        print STDERR "ERROR: can't open output file $tst\n";
        return 0;
    }
    $monte = 1 if ($rsp =~ /Monte[123]/);
    for ( ; ; ) {
        $rspline = next_line($rspf);
        $tstline = next_line($tstf);
        if ( !defined($rspline) && !defined($tstline) ) {
            print STDERR "DEBUG: $tname file comparison OK\n" if $debug;
            return 1;
        }
	# Workaround for old broken DES3 MCT format which added bogus
	# extra lines: after [ENCRYPT] or [DECRYPT] skip until first
	# COUNT line.
	if ($monte) {
		if ($rspline =~ /CRYPT/) {
			do {
				$rspline = next_line($rspf);
			} while (defined($rspline) && $rspline !~ /COUNT/);
		}
		if ($tstline =~ /CRYPT/) {
			do {
				$tstline = next_line($tstf);
			} while (defined($tstline) && $tstline !~ /COUNT/);
		}
	}
        if ( !defined($rspline) ) {
            print STDERR "ERROR: $tname EOF on $rsp\n";
            return 0;
        }
        if ( !defined($tstline) ) {
            print STDERR "ERROR: $tname EOF on $tst\n";
            return 0;
        }

        # Workaround for bug in RAND des2 test output */
        if ( $tstline =~ /^Key2 =/ && $rspline =~ /^Key1 =/ ) {
            $rspline =~ s/^Key1/Key2/;
        }

        if ( $tstline ne $rspline ) {
            print STDERR "ERROR: $tname mismatch:\n";
            print STDERR "\t \"$tstline\" != \"$rspline\"\n";
            return 0;
        }
    }
    return 1;
}

sub next_line {
    my ($in) = @_;

    while (<$in>) {
        chomp;

        # Delete comments
        s/#.*$//;

        # Ignore blank lines
        next if (/^\s*$/);

        # Translate multiple space into one
        s/\s+/ /g;
	# Delete trailing whitespace
	s/\s+$//;
	# Remove leading zeroes
	s/= 00/= /;
	# Translate to upper case
        return uc $_;
    }
    return undef;
}
