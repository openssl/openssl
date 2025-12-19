#include <stdlib.h>
#include <openssl/evp.h>

static EVP_MD *mymd = NULL;
static int dso1_cleanup = 1;
int do_dso1_setup(int do_cleanup);
int do_dso1_fini(void);

int do_dso1_setup(int do_cleanup)
{
    if ((do_cleanup & 2) == 2) {
        if (!OPENSSL_add_library_user())
            return 0;
    } else {
        fprintf(stderr, "Skipping OPENSSL_add_library_user in dso1_do_setup()\n");
    }
    mymd = EVP_MD_fetch(NULL, "SHA-256", NULL);
    dso1_cleanup = do_cleanup;
    return mymd != NULL ? 1 : 0;
}

int do_dso1_fini(void)
{
    EVP_MD_free(mymd);
    mymd = NULL;
    if (dso1_cleanup & 0x1) {
        fprintf(stdout, "calling OPENSSL_cleanup from do_dso1_fini()\n");
        OPENSSL_cleanup_ex();
    } else {
        fprintf(stdout, "skipping call to OPENSSL_cleanup from do_dso1_fini()\n");
    }
    return 1;
}
