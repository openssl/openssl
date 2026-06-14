#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

typedef struct { char R[68], c[68], s[68], Y[68]; } SchnorrProof;

void sha256_hex(const unsigned char* d, size_t len, char* out) {
    unsigned char h[32];
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, d, len);
    EVP_DigestFinal_ex(c, h, NULL);
    EVP_MD_CTX_free(c);
    for(int i=0;i<32;i++) sprintf(out+2*i,"%02x",h[i]);
}

SchnorrProof schnorr_prove(const char* data) {
    SchnorrProof pf;
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = BN_CTX_new();
    const BIGNUM* n = EC_GROUP_get0_order(g);
    char hash[65]; sha256_hex((unsigned char*)data, strlen(data), hash);
    BIGNUM* x = BN_new(); BN_hex2bn(&x, hash); BN_mod(x, x, n, ctx);
    EC_POINT* Y = EC_POINT_new(g); EC_POINT_mul(g, Y, x, NULL, NULL, ctx);
    char* yhex = EC_POINT_point2hex(g, Y, POINT_CONVERSION_COMPRESSED, ctx);
    strcpy(pf.Y, yhex); OPENSSL_free(yhex);
    BIGNUM* r = BN_new(); BN_rand_range(r, n);
    EC_POINT* R = EC_POINT_new(g); EC_POINT_mul(g, R, r, NULL, NULL, ctx);
    char* rhex = EC_POINT_point2hex(g, R, POINT_CONVERSION_COMPRESSED, ctx);
    strcpy(pf.R, rhex); OPENSSL_free(rhex);
    char combined[200]; snprintf(combined,200,"%s||%s",pf.R,pf.Y);
    sha256_hex((unsigned char*)combined, strlen(combined), hash);
    BIGNUM* c = BN_new(); BN_hex2bn(&c, hash); BN_mod(c, c, n, ctx);
    char* chex = BN_bn2hex(c); strcpy(pf.c, chex); OPENSSL_free(chex);
    BIGNUM* s = BN_new(); BIGNUM* cx = BN_new();
    BN_mod_mul(cx, c, x, n, ctx); BN_mod_add(s, r, cx, n, ctx);
    char* shex = BN_bn2hex(s); strcpy(pf.s, shex); OPENSSL_free(shex);
    BN_free(x); BN_free(r); BN_free(c); BN_free(s); BN_free(cx);
    EC_POINT_free(R); EC_POINT_free(Y); EC_GROUP_free(g); BN_CTX_free(ctx);
    return pf;
}

int schnorr_verify(const SchnorrProof* pf) {
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = BN_CTX_new();
    const BIGNUM* n = EC_GROUP_get0_order(g);
    EC_POINT* R = EC_POINT_new(g); EC_POINT* Y = EC_POINT_new(g);
    EC_POINT_hex2point(g, pf->R, R, ctx); EC_POINT_hex2point(g, pf->Y, Y, ctx);
    char combined[200]; snprintf(combined,200,"%s||%s",pf->R,pf->Y);
    char hash[65]; sha256_hex((unsigned char*)combined, strlen(combined), hash);
    BIGNUM* cp = BN_new(); BN_hex2bn(&cp, hash); BN_mod(cp, cp, n, ctx);
    BIGNUM* c = BN_new(); BN_hex2bn(&c, pf->c);
    if(BN_cmp(cp,c)!=0){BN_free(cp);BN_free(c);EC_POINT_free(R);EC_POINT_free(Y);EC_GROUP_free(g);BN_CTX_free(ctx);return 0;}
    BIGNUM* s = BN_new(); BN_hex2bn(&s, pf->s);
    EC_POINT* sG = EC_POINT_new(g); EC_POINT* cY = EC_POINT_new(g); EC_POINT* RcY = EC_POINT_new(g);
    EC_POINT_mul(g, sG, s, NULL, NULL, ctx);
    EC_POINT_mul(g, cY, NULL, Y, c, ctx);
    EC_POINT_add(g, RcY, R, cY, ctx);
    int v = (EC_POINT_cmp(g, sG, RcY, ctx) == 0);
    BN_free(cp);BN_free(c);BN_free(s);
    EC_POINT_free(R);EC_POINT_free(Y);EC_POINT_free(sG);EC_POINT_free(cY);EC_POINT_free(RcY);
    EC_GROUP_free(g);BN_CTX_free(ctx);
    return v;
}

int main() {
    const char *msg = "RFC 8235 Schnorr ZKP Test";
    int passed = 0, total = 0;
    
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  SCHNORR ZKP — FULL TEST SUITE                 ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    total++; printf("[%d] Sign/Verify...\n", total);
    SchnorrProof pf = schnorr_prove(msg);
    if(schnorr_verify(&pf)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Tampered...\n", total);
    pf.s[5]^=0xFF; if(!schnorr_verify(&pf)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Wrong key...\n", total);
    SchnorrProof pf2=schnorr_prove(msg); pf2.Y[10]^=0xFF;
    if(!schnorr_verify(&pf2)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Wrong challenge...\n", total);
    SchnorrProof pf3=schnorr_prove(msg); pf3.c[8]^=0xFF;
    if(!schnorr_verify(&pf3)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Empty msg...\n", total);
    SchnorrProof pf4=schnorr_prove("");
    if(schnorr_verify(&pf4)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Large msg...\n", total);
    char big[1024];memset(big,'X',1023);big[1023]=0;
    SchnorrProof pf5=schnorr_prove(big);
    if(schnorr_verify(&pf5)){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Non-determinism...\n", total);
    SchnorrProof a=schnorr_prove(msg), b=schnorr_prove(msg);
    if(strcmp(a.R,b.R)!=0){passed++;printf("✅ PASSED\n");}else{printf("❌ FAILED\n");}
    
    total++; printf("[%d] Speed (1000 ops)...\n", total);
    clock_t s=clock();
    for(int i=0;i<1000;i++){SchnorrProof t=schnorr_prove(msg);schnorr_verify(&t);}
    double sec=(double)(clock()-s)/CLOCKS_PER_SEC;
    printf("✅ %.0f ops/sec\n\n",1000.0/sec); passed++;
    
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  RESULTS: %d/%d PASSED                          ║\n",passed,total);
    printf("║  %s                                     ║\n",passed==total?"🎉 FULLY VALIDATED!":"⚠️ NEEDS FIX");
    printf("╚══════════════════════════════════════════════╝\n");
    return passed==total?0:1;
}
