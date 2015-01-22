#include <openssl/err.h>

#include "test_err.h"

/* Simple error test routine */

void a_test_function(void)
{
    TESTerr(TEST_F_A_TEST_FUNCTION, TEST_R_TEST_REASON_CODE);
    TESTerr(TEST_F_A_TEST_FUNCTION, TEST_R_ANOTHER_TEST_REASON_CODE);
    ERR_add_error_data(1, "some additional error data");
}

int main(int argc, char **argv)
{
    ERR_load_TEST_strings();
    a_test_function();
    ERR_print_errors_fp(stderr);
}
