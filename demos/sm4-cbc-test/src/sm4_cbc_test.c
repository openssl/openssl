/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * SM4-CBC Algorithm Test Suite
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define MAX_TEST_LEN (1024 * 1024)
#define ITERATIONS_PER_LEN 100

typedef struct {
    int test_id;
    size_t plaintext_len;
    unsigned char key[SM4_KEY_SIZE];
    unsigned char iv[SM4_BLOCK_SIZE];
    unsigned char *plaintext;
    unsigned char *ciphertext;
    unsigned char *decrypted;
    int match;
    double enc_time_ms;
    double dec_time_ms;
    char status[32];
} TestResult;

int sm4_cbc_encrypt(const unsigned char *in, int in_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int len, out_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &len, in, in_len);
    out_len = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    out_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

int sm4_cbc_decrypt(const unsigned char *in, int in_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int len, out_len = 0;
    EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &len, in, in_len);
    out_len = len;
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    out_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

void generate_random_data(unsigned char *buf, size_t len) {
    RAND_bytes(buf, len);
}

TestResult* run_single_test(int test_id, size_t data_len) {
    TestResult *result = calloc(1, sizeof(TestResult));
    if (!result) return NULL;
    
    result->test_id = test_id;
    result->plaintext_len = data_len;
    
    result->plaintext = malloc(data_len + SM4_BLOCK_SIZE);
    result->ciphertext = malloc(data_len + SM4_BLOCK_SIZE);
    result->decrypted = malloc(data_len + SM4_BLOCK_SIZE);
    if (!result->plaintext || !result->ciphertext || !result->decrypted) {
        free(result->plaintext);
        free(result->ciphertext);
        free(result->decrypted);
        free(result);
        return NULL;
    }
    
    generate_random_data(result->key, SM4_KEY_SIZE);
    generate_random_data(result->iv, SM4_BLOCK_SIZE);
    generate_random_data(result->plaintext, data_len);
    
    clock_t start = clock();
    int cipher_len = sm4_cbc_encrypt(result->plaintext, data_len,
                                      result->key, result->iv,
                                      result->ciphertext);
    clock_t end = clock();
    result->enc_time_ms = (double)(end - start) * 1000 / CLOCKS_PER_SEC;
    
    if (cipher_len < 0) {
        strcpy(result->status, "ENCRYPT_FAIL");
        return result;
    }
    
    start = clock();
    int decrypted_len = sm4_cbc_decrypt(result->ciphertext, cipher_len,
                                         result->key, result->iv,
                                         result->decrypted);
    end = clock();
    result->dec_time_ms = (double)(end - start) * 1000 / CLOCKS_PER_SEC;
    
    if (decrypted_len < 0) {
        strcpy(result->status, "DECRYPT_FAIL");
        return result;
    }
    
    result->match = (data_len == decrypted_len) &&
                    (memcmp(result->plaintext, result->decrypted, data_len) == 0);
    strcpy(result->status, result->match ? "PASS" : "FAIL");
    
    return result;
}

void log_test_result(TestResult *result, FILE *log_file) {
    fprintf(log_file, "{\n");
    fprintf(log_file, "  \"test_id\": %d,\n", result->test_id);
    fprintf(log_file, "  \"plaintext_len\": %zu,\n", result->plaintext_len);
    fprintf(log_file, "  \"key\": \"");
    for (int i = 0; i < SM4_KEY_SIZE; i++)
        fprintf(log_file, "%02x", result->key[i]);
    fprintf(log_file, "\",\n");
    fprintf(log_file, "  \"iv\": \"");
    for (int i = 0; i < SM4_BLOCK_SIZE; i++)
        fprintf(log_file, "%02x", result->iv[i]);
    fprintf(log_file, "\",\n");
    fprintf(log_file, "  \"status\": \"%s\",\n", result->status);
    fprintf(log_file, "  \"enc_time_ms\": %.3f,\n", result->enc_time_ms);
    fprintf(log_file, "  \"dec_time_ms\": %.3f\n", result->dec_time_ms);
    fprintf(log_file, "},\n");
}

int run_test_suite(void) {
    FILE *log_file = fopen("logs/test_results.json", "w");
    if (!log_file) {
        fprintf(stderr, "Cannot create log file\n");
        return 1;
    }
    
    fprintf(log_file, "{\n  \"test_suite\": \"SM4-CBC\",\n");
    fprintf(log_file, "  \"timestamp\": \"%s\",\n", __DATE__ " " __TIME__);
    fprintf(log_file, "  \"results\": [\n");
    
    size_t test_lengths[] = {
        0, 1, 15, 16, 17, 31, 32, 33, 64, 65, 127, 128,
        256, 512, 1024, 4096, 65536, 1048576
    };
    int num_lengths = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    int total_tests = 0, passed = 0, failed = 0;
    int test_id = 0;
    
    for (int i = 0; i < num_lengths; i++) {
        size_t len = test_lengths[i];
        printf("Testing length: %zu bytes ...\n", len);
        
        for (int iter = 0; iter < ITERATIONS_PER_LEN; iter++) {
            TestResult *result = run_single_test(test_id++, len);
            if (!result) {
                fprintf(stderr, "Test allocation failed at len=%zu\n", len);
                continue;
            }
            
            log_test_result(result, log_file);
            total_tests++;
            if (result->match) passed++;
            else failed++;
            
            if (iter % 10 == 0) {
                printf("  Progress: %d/%d iterations for len=%zu\n",
                       iter, ITERATIONS_PER_LEN, len);
            }
            
            free(result->plaintext);
            free(result->ciphertext);
            free(result->decrypted);
            free(result);
        }
    }
    
    fprintf(log_file, "  ],\n");
    fprintf(log_file, "  \"summary\": {\n");
    fprintf(log_file, "    \"total_tests\": %d,\n", total_tests);
    fprintf(log_file, "    \"passed\": %d,\n", passed);
    fprintf(log_file, "    \"failed\": %d,\n", failed);
    fprintf(log_file, "    \"pass_rate\": \"%.2f%%\"\n",
            total_tests > 0 ? (100.0 * passed / total_tests) : 0);
    fprintf(log_file, "  }\n");
    fprintf(log_file, "}\n");
    
    fclose(log_file);
    
    printf("\n========== SUMMARY ==========\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("Pass rate: %.2f%%\n",
           total_tests > 0 ? (100.0 * passed / total_tests) : 0);
    
    return (failed == 0) ? 0 : 1;
}

int main(int argc, char **argv) {
    printf("===========================================\n");
    printf("     SM4-CBC Algorithm Test Suite\n");
    printf("     OpenSSL Integration Test\n");
    printf("===========================================\n\n");
    
    system("mkdir logs 2>nul");
    
    int ret = run_test_suite();
    
    printf("\nTest complete. Log saved to logs/test_results.json\n");
    return ret;
}