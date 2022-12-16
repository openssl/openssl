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
    { 0x0238, "bikel1" }, \
    { 0x2F38, "p256_bikel1" }, \
    { 0x023B, "bikel3" }, \
    { 0x2F3B, "p384_bikel3" }, \
    { 0x023E, "kyber90s512" }, \
    { 0x2F3E, "p256_kyber90s512" }, \
    { 0x023F, "kyber90s768" }, \
    { 0x2F3F, "p384_kyber90s768" }, \
    { 0x0240, "kyber90s1024" }, \
    { 0x2F40, "p521_kyber90s1024" }, \
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
    { 0xfea7, "dilithium2_aes" }, \
    { 0xfea8, "p256_dilithium2_aes" }, \
    { 0xfea9, "rsa3072_dilithium2_aes" }, \
    { 0xfeaa, "dilithium3_aes" }, \
    { 0xfeab, "p384_dilithium3_aes" }, \
    { 0xfeac, "dilithium5_aes" }, \
    { 0xfead, "p521_dilithium5_aes" }, \
    { 0xfe0b, "falcon512" }, \
    { 0xfe0c, "p256_falcon512" }, \
    { 0xfe0d, "rsa3072_falcon512" }, \
    { 0xfe0e, "falcon1024" }, \
    { 0xfe0f, "p521_falcon1024" }, \
    { 0xfe42, "sphincsharaka128frobust" }, \
    { 0xfe43, "p256_sphincsharaka128frobust" }, \
    { 0xfe44, "rsa3072_sphincsharaka128frobust" }, \
    { 0xfe5e, "sphincssha256128frobust" }, \
    { 0xfe5f, "p256_sphincssha256128frobust" }, \
    { 0xfe60, "rsa3072_sphincssha256128frobust" }, \
    { 0xfe7a, "sphincsshake256128frobust" }, \
    { 0xfe7b, "p256_sphincsshake256128frobust" }, \
    { 0xfe7c, "rsa3072_sphincsshake256128frobust" }, \
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
	oid_add_from_string("dilithium2_aes", "1.3.6.1.4.1.2.267.11.4.4"); \
	oid_add_from_string("p256_dilithium2_aes", "1.3.9999.2.11.1"); \
	oid_add_from_string("rsa3072_dilithium2_aes", "1.3.9999.2.11.2"); \
	oid_add_from_string("dilithium3_aes", "1.3.6.1.4.1.2.267.11.6.5"); \
	oid_add_from_string("p384_dilithium3_aes", "1.3.9999.2.11.3"); \
	oid_add_from_string("dilithium5_aes", "1.3.6.1.4.1.2.267.11.8.7"); \
	oid_add_from_string("p521_dilithium5_aes", "1.3.9999.2.11.4"); \
	oid_add_from_string("falcon512", "1.3.9999.3.1"); \
	oid_add_from_string("p256_falcon512", "1.3.9999.3.2"); \
	oid_add_from_string("rsa3072_falcon512", "1.3.9999.3.3"); \
	oid_add_from_string("falcon1024", "1.3.9999.3.4"); \
	oid_add_from_string("p521_falcon1024", "1.3.9999.3.5"); \
	oid_add_from_string("sphincsharaka128frobust", "1.3.9999.6.1.1"); \
	oid_add_from_string("p256_sphincsharaka128frobust", "1.3.9999.6.1.2"); \
	oid_add_from_string("rsa3072_sphincsharaka128frobust", "1.3.9999.6.1.3"); \
	oid_add_from_string("sphincssha256128frobust", "1.3.9999.6.4.1"); \
	oid_add_from_string("p256_sphincssha256128frobust", "1.3.9999.6.4.2"); \
	oid_add_from_string("rsa3072_sphincssha256128frobust", "1.3.9999.6.4.3"); \
	oid_add_from_string("sphincsshake256128frobust", "1.3.9999.6.7.1"); \
	oid_add_from_string("p256_sphincsshake256128frobust", "1.3.9999.6.7.2"); \
	oid_add_from_string("rsa3072_sphincsshake256128frobust", "1.3.9999.6.7.3"); \


///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_END

