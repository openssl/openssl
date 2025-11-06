#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAX_ALGORITHMS 3
#define MAX_TRUST_CHAINS 10

const char *algorithms[] = {"RSA", "ECC", "SM2"};

// 加载目录中的所有证书到X509_STORE
int load_certs_from_dir(X509_STORE *store, const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        perror("opendir");
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        char file_path[256];
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

        FILE *fp = fopen(file_path, "r");
        if (fp == NULL) {
            perror("fopen");
            continue;
        }

        X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);

        if (cert != NULL) {
            if (X509_STORE_add_cert(store, cert) != 1) {
                fprintf(stderr, "Failed to add cert: %s\n", file_path);
                X509_free(cert);
            } else {
                printf("Loaded cert: %s\n", file_path);
                X509_free(cert); // X509_STORE_add_cert makes a copy
            }
        } else {
            fprintf(stderr, "Failed to read cert: %s\n", file_path);
            ERR_print_errors_fp(stderr);
        }
    }

    closedir(dir);
    return 1;
}

// 加载目录中的所有CRL到X509_STORE
int load_crls_from_dir(X509_STORE *store, const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        perror("opendir");
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        char file_path[256];
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

        FILE *fp = fopen(file_path, "r");
        if (fp == NULL) {
            perror("fopen");
            continue;
        }

        X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
        fclose(fp);

        if (crl != NULL) {
            if (X509_STORE_add_crl(store, crl) != 1) {
                fprintf(stderr, "Failed to add CRL: %s\n", file_path);
                X509_CRL_free(crl);
            } else {
                printf("Loaded CRL: %s\n", file_path);
                X509_CRL_free(crl); // X509_STORE_add_crl makes a copy
            }
        } else {
            fprintf(stderr, "Failed to read CRL: %s\n", file_path);
            ERR_print_errors_fp(stderr);
        }
    }

    closedir(dir);
    return 1;
}

// 下载CRL文件（模拟实现）
int download_crl(const char *url, const char *save_path) {
    // 这里应该实现实际的HTTP下载功能
    // 目前只是模拟下载成功
    printf("Simulated downloading CRL from %s to %s\n", url, save_path);
    return 1;
}

// 从证书中提取CRL分发点并下载CRL
int download_crls_from_cert(X509 *cert, const char *save_dir) {
    int ret = 1;
    STACK_OF(DIST_POINT) *crl_dps = NULL;
    
    // 检查证书是否有CRL分发点扩展
    crl_dps = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crl_dps == NULL) {
        printf("No CRL distribution points found in certificate\n");
        return ret;
    }

    for (int i = 0; i < sk_DIST_POINT_num(crl_dps); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crl_dps, i);
        if (dp->distpoint != NULL) {
            if (dp->distpoint->type == 0) { // fullname
                STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
                if (names != NULL) {
                    for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
                        GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, j);
                        if (gn->type == GEN_URI) {
                            const char *url = ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier);
                            char save_path[256];
                            snprintf(save_path, sizeof(save_path), "%s/crl_%d_%d.pem", save_dir, i, j);
                            
                            if (!download_crl(url, save_path)) {
                                fprintf(stderr, "Failed to download CRL from %s\n", url);
                                ret = 0;
                            }
                        }
                    }
                }
            }
        }
    }

    sk_DIST_POINT_pop_free(crl_dps, DIST_POINT_free);
    return ret;
}

// 获取证书使用的算法
const char *get_cert_algorithm(X509 *cert) {
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    if (pkey == NULL) {
        return "Unknown";
    }

    int type = EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            return "RSA";
        case EVP_PKEY_EC:
            return "ECC";
        case EVP_PKEY_SM2:
            return "SM2";
        default:
            return "Unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <trust_chain_root_dir> <cert_file>\n", argv[0]);
        return 1;
    }

    const char *trust_root_dir = argv[1];
    const char *cert_file = argv[2];

    // 初始化OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ERR_load_crypto_strings();

    // 读取待验证证书
    FILE *fp = fopen(cert_file, "r");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (cert == NULL) {
        fprintf(stderr, "Failed to read certificate: %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 获取证书使用的算法
    const char *cert_alg = get_cert_algorithm(cert);
    printf("Certificate algorithm: %s\n", cert_alg);

    // 创建X509_STORE
    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "Failed to create X509_STORE\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return 1;
    }

    // 启用CRL验证，但允许没有CRL
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_IGNORE_CRITICAL);

    // 加载对应算法的信任证书链
    char alg_dir[256];
    int alg_index = -1;
    for (int i = 0; i < MAX_ALGORITHMS; i++) {
        if (strcmp(cert_alg, algorithms[i]) == 0) {
            alg_index = i;
            break;
        }
    }

    if (alg_index == -1) {
        fprintf(stderr, "Unsupported certificate algorithm: %s\n", cert_alg);
        X509_free(cert);
        X509_STORE_free(store);
        return 1;
    }

    snprintf(alg_dir, sizeof(alg_dir), "%s/%s", trust_root_dir, algorithms[alg_index]);
    printf("Loading trust chains from: %s\n", alg_dir);

    // 遍历算法目录下的所有子目录（每套信任证书链一个子目录）
    DIR *alg_dir_ptr = opendir(alg_dir);
    if (alg_dir_ptr == NULL) {
        perror("opendir");
        X509_free(cert);
        X509_STORE_free(store);
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(alg_dir_ptr)) != NULL) {
        if (entry->d_type != DT_DIR || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char chain_dir[256];
        snprintf(chain_dir, sizeof(chain_dir), "%s/%s", alg_dir, entry->d_name);
        printf("\nLoading trust chain: %s\n", entry->d_name);

        // 加载证书
        char cert_dir[256];
        snprintf(cert_dir, sizeof(cert_dir), "%s/certs", chain_dir);
        if (!load_certs_from_dir(store, cert_dir)) {
            fprintf(stderr, "Failed to load certs from %s\n", cert_dir);
        }

        // 加载CRL
        char crl_dir[256];
        snprintf(crl_dir, sizeof(crl_dir), "%s/crl", chain_dir);
        if (!load_crls_from_dir(store, crl_dir)) {
            fprintf(stderr, "Failed to load CRLs from %s\n", crl_dir);
        }
    }

    closedir(alg_dir_ptr);

    // 下载CRL（如果证书有CRL分发点）
    printf("\nChecking for CRL distribution points in certificate...\n");
    char temp_crl_dir[] = "./temp_crl";
    mkdir(temp_crl_dir, 0755);
    download_crls_from_cert(cert, temp_crl_dir);
    load_crls_from_dir(store, temp_crl_dir);

    // 执行证书验证
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create X509_STORE_CTX\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        X509_STORE_free(store);
        return 1;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "Failed to initialize X509_STORE_CTX\n");
        ERR_print_errors_fp(stderr);
        X509_STORE_CTX_free(ctx);
        X509_free(cert);
        X509_STORE_free(store);
        return 1;
    }

    printf("\nStarting certificate verification...\n");
    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        printf("Certificate verification PASSED\n");
    } else {
        printf("Certificate verification FAILED\n");
        printf("Error: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

    // 清理资源
    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    X509_STORE_free(store);
    ERR_free_strings();

    // 删除临时CRL目录
    system("rm -rf ./temp_crl");

    return ret == 1 ? 0 : 1;
}