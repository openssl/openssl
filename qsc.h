///// OQS_TEMPLATE_FRAGMENT_OQS_CURVE_ID_NAME_STR_START
#define QSC_KEMS \
    { 0x0200, "frodo640aes" }, \
    { 0x2F00, "p256_frodo640aes" }, \
    { 0x0201, "frodo640shake" }, \
    { 0x2F01, "p256_frodo640shake" }, \
    { 0x0202, "frodo976aes" }, \
    { 0x2F02, "p384_frodo976aes" }, \
    { 0x0203, "frodo976shake" }, \
    { 0x2F03, "p384_frodo976shake" }, \
    { 0x0204, "frodo1344aes" }, \
    { 0x2F04, "p521_frodo1344aes" }, \
    { 0x0205, "frodo1344shake" }, \
    { 0x2F05, "p521_frodo1344shake" }, \
    { 0x023A, "kyber512" }, \
    { 0x2F3A, "p256_kyber512" }, \
    { 0x023C, "kyber768" }, \
    { 0x2F3C, "p384_kyber768" }, \
    { 0x023D, "kyber1024" }, \
    { 0x2F3D, "p521_kyber1024" }, \
    { 0x0241, "bikel1" }, \
    { 0x2F41, "p256_bikel1" }, \
    { 0x0242, "bikel3" }, \
    { 0x2F42, "p384_bikel3" }, \
    { 0x0243, "bikel5" }, \
    { 0x2F43, "p521_bikel5" }, \
    { 0x022C, "hqc128" }, \
    { 0x2F2C, "p256_hqc128" }, \
    { 0x022D, "hqc192" }, \
    { 0x2F2D, "p384_hqc192" }, \
    { 0x022E, "hqc256" }, \
    { 0x2F2E, "p521_hqc256" }, \
///// OQS_TEMPLATE_FRAGMENT_OQS_CURVE_ID_NAME_STR_END

///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_CPS_START
#define QSC_SIG_CPS \
    { 0xfea0, "dilithium2" }, \
    { 0xfea1, "p256_dilithium2" }, \
    { 0xfea2, "rsa3072_dilithium2" }, \
    { 0xfea3, "dilithium3" }, \
    { 0xfea4, "p384_dilithium3" }, \
    { 0xfea5, "dilithium5" }, \
    { 0xfea6, "p521_dilithium5" }, \
    { 0xfeae, "falcon512" }, \
    { 0xfeaf, "p256_falcon512" }, \
    { 0xfeb0, "rsa3072_falcon512" }, \
    { 0xfeb1, "falcon1024" }, \
    { 0xfeb2, "p521_falcon1024" }, \
    { 0xfeb3, "sphincssha2128fsimple" }, \
    { 0xfeb4, "p256_sphincssha2128fsimple" }, \
    { 0xfeb5, "rsa3072_sphincssha2128fsimple" }, \
    { 0xfeb6, "sphincssha2128ssimple" }, \
    { 0xfeb7, "p256_sphincssha2128ssimple" }, \
    { 0xfeb8, "rsa3072_sphincssha2128ssimple" }, \
    { 0xfeb9, "sphincssha2192fsimple" }, \
    { 0xfeba, "p384_sphincssha2192fsimple" }, \
    { 0xfec2, "sphincsshake128fsimple" }, \
    { 0xfec3, "p256_sphincsshake128fsimple" }, \
    { 0xfec4, "rsa3072_sphincsshake128fsimple" }, \
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_CPS_END

///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START
#define QSC_SIGS \
	oid_add_from_string("dilithium2", "1.3.6.1.4.1.2.267.7.4.4"); \
	oid_add_from_string("p256_dilithium2", "1.3.9999.2.7.1"); \
	oid_add_from_string("rsa3072_dilithium2", "1.3.9999.2.7.2"); \
	oid_add_from_string("dilithium3", "1.3.6.1.4.1.2.267.7.6.5"); \
	oid_add_from_string("p384_dilithium3", "1.3.9999.2.7.3"); \
	oid_add_from_string("dilithium5", "1.3.6.1.4.1.2.267.7.8.7"); \
	oid_add_from_string("p521_dilithium5", "1.3.9999.2.7.4"); \
	oid_add_from_string("falcon512", "1.3.9999.3.6"); \
	oid_add_from_string("p256_falcon512", "1.3.9999.3.7"); \
	oid_add_from_string("rsa3072_falcon512", "1.3.9999.3.8"); \
	oid_add_from_string("falcon1024", "1.3.9999.3.9"); \
	oid_add_from_string("p521_falcon1024", "1.3.9999.3.10"); \
	oid_add_from_string("sphincssha2128fsimple", "1.3.9999.6.4.13"); \
	oid_add_from_string("p256_sphincssha2128fsimple", "1.3.9999.6.4.14"); \
	oid_add_from_string("rsa3072_sphincssha2128fsimple", "1.3.9999.6.4.15"); \
	oid_add_from_string("sphincssha2128ssimple", "1.3.9999.6.4.16"); \
	oid_add_from_string("p256_sphincssha2128ssimple", "1.3.9999.6.4.17"); \
	oid_add_from_string("rsa3072_sphincssha2128ssimple", "1.3.9999.6.4.18"); \
	oid_add_from_string("sphincssha2192fsimple", "1.3.9999.6.5.10"); \
	oid_add_from_string("p384_sphincssha2192fsimple", "1.3.9999.6.5.11"); \
	oid_add_from_string("sphincsshake128fsimple", "1.3.9999.6.7.13"); \
	oid_add_from_string("p256_sphincsshake128fsimple", "1.3.9999.6.7.14"); \
	oid_add_from_string("rsa3072_sphincsshake128fsimple", "1.3.9999.6.7.15"); \


///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END

