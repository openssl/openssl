
#include <openssl/crypto.h>

int main(int argc, char **argv)
{
#if defined(OPENSSL_SYS_LINUX) || defined(OPENSSL_SYS_UNIX)
    char *p = NULL, *q = NULL;

    if (!CRYPTO_secure_malloc_init(4096, 32)) {
        perror("failed");
        return 1;
    }
    p = OPENSSL_secure_malloc(20);
    if (!CRYPTO_secure_allocated(p)) {
        perror("failed 1");
        return 1;
    }
    q = OPENSSL_malloc(20);
    if (CRYPTO_secure_allocated(q)) {
        perror("failed 1");
        return 1;
    }
    CRYPTO_secure_free(p);
    CRYPTO_free(q);
    CRYPTO_secure_malloc_done();
#else
    /* Should fail. */
    if (CRYPTO_secure_malloc_init(4096, 32)) {
        perror("failed");
        return 1;
    }
#endif
    return 0;
}
