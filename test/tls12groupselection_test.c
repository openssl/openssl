#include "testutil.h"
#include "helpers/ssltestlib.h"
#include <openssl/objects.h>

#define TEST_true_or_end(a) if (!TEST_true(a)) \
        goto end;

#define SERVER_PREFERENCE 1
#define CLIENT_PREFERENCE 0

#define WORK_ON_SSL_OBJECT 1
#define WORK_ON_CONTEXT 0

#if !defined(OPENSSL_NO_EC)

static char *cert = NULL;
static char *privkey = NULL;

struct tls12groupselection_test_st {
    const char *client_groups;
    const char *server_groups;
    int preference;
    const char *expected_group;
};

static const struct tls12groupselection_test_st tls12groupselection_tests[] =
    {
        { "secp521r1:secp384r1:X25519:prime256v1:X448",  /* test 0 */
          "X25519:secp521r1:secp384r1:prime256v1:X448",
          CLIENT_PREFERENCE,
          "secp521r1"
        },
        { "secp521r1:secp384r1:X25519:prime256v1:X448",  /* test 1 */
          "X25519:secp521r1:secp384r1:prime256v1:X448",
          SERVER_PREFERENCE,
          "X25519"
        },
        { "secp384r1:prime256v1:X448",                   /* test 2 */
          "prime256v1:X448:secp384r1",
          CLIENT_PREFERENCE,
          "secp384r1"
        },
        { "secp384r1:prime256v1:X448",                   /* test 3 */
          "prime256v1:X448:secp384r1",
          SERVER_PREFERENCE,
          "prime256v1"
        },
        { "secp521r1:secp384r1:X25519:prime256v1:X448",  /* test 4 */
          "X25519:secp384r1:prime256v1",
          CLIENT_PREFERENCE,
          "secp384r1"
        },
        { "secp521r1:secp384r1:X25519:prime256v1:X448", /* test 5 */
          "X25519:secp384r1:prime256v1",
          SERVER_PREFERENCE,
          "X25519"
        },
        { NULL,                                        /* test 6 */
          NULL,
          CLIENT_PREFERENCE,
          "X25519"
        },
        { NULL,                                        /* test 7 */
          NULL,
          SERVER_PREFERENCE,
          "X25519"
        },
        { "secp521r1:secp384r1:X25519:prime256v1", /* test 8 */
          "X448:X25519:secp384r1:prime256v1",
          SERVER_PREFERENCE,
          "X25519"
        },
    };

#endif /* !defined(OPENSSL_NO_EC) */

static int run_12groupselection(const struct tls12groupselection_test_st *current_test_vector,
                                int ssl_or_ctx);
static int run_12groupselection(const struct tls12groupselection_test_st *current_test_vector,
                                int ssl_or_ctx)
{
#if !defined(OPENSSL_NO_EC)
    int ok = 0;
    int negotiated_group_client = 0;
    int negotiated_group_server = 0;
    SSL_CTX *client_ctx = NULL, *server_ctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    /* Creation of the contexts */
    TEST_true_or_end(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                         TLS_client_method(),
                                         TLS1_VERSION, 0,
                                         &server_ctx, &client_ctx,
                                         cert, privkey));

    /* Customization of the contexts */
    if (ssl_or_ctx == WORK_ON_CONTEXT) {
        if (current_test_vector->client_groups != NULL) {
            TEST_true_or_end(SSL_CTX_set1_groups_list(client_ctx,
                                                      current_test_vector->client_groups));
        }
        if (current_test_vector->server_groups != NULL) {
            TEST_true_or_end(SSL_CTX_set1_groups_list(server_ctx,
                                                      current_test_vector->server_groups));
        }
        TEST_true_or_end(SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION));
        TEST_true_or_end(SSL_CTX_set_min_proto_version(server_ctx, TLS1_2_VERSION));
        TEST_true_or_end(SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION));
        TEST_true_or_end(SSL_CTX_set_max_proto_version(server_ctx, TLS1_2_VERSION));
        if (current_test_vector->preference == SERVER_PREFERENCE)
            SSL_CTX_set_options(server_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }
    /* Creation of the SSL objects */
    if (!TEST_true(create_ssl_objects(server_ctx, client_ctx,
                                      &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    /* Customization of the SSL objects */
    if (ssl_or_ctx == WORK_ON_SSL_OBJECT) {
        if (current_test_vector->client_groups != NULL)
            TEST_true_or_end(SSL_set1_groups_list(clientssl, current_test_vector->client_groups));
        if (current_test_vector->server_groups != NULL)
            TEST_true_or_end(SSL_set1_groups_list(serverssl, current_test_vector->server_groups));
        TEST_true_or_end(SSL_set_min_proto_version(clientssl, TLS1_2_VERSION));
        TEST_true_or_end(SSL_set_min_proto_version(serverssl, TLS1_2_VERSION));
        TEST_true_or_end(SSL_set_max_proto_version(clientssl, TLS1_2_VERSION));
        TEST_true_or_end(SSL_set_max_proto_version(serverssl, TLS1_2_VERSION));
        if (current_test_vector->preference == SERVER_PREFERENCE)
            SSL_set_options(serverssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    /* Creating a test connection */
    TEST_true_or_end(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE));

    /*
     * Checking that the negotiated group matches our expectation
     * and must be identical on server- and client-side obviously
     */
    negotiated_group_client = SSL_get_negotiated_group(clientssl);
    negotiated_group_server = SSL_get_negotiated_group(serverssl);
    if (!TEST_int_eq(negotiated_group_client, negotiated_group_server))
        goto end;
    if (!TEST_int_eq(negotiated_group_client, OBJ_sn2nid(current_test_vector->expected_group)))
        goto end;

    ok = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    return ok;
#else
    return 1;
#endif /* !defined(OPENSSL_NO_EC) */
}

static int tls12groupselection_test(void)
{
    int testresult = 1; /* Assume the test will succeed */
    unsigned long i;

#if !defined(OPENSSL_NO_EC)

    /*
     * Call the code under test, once such that the ssl object is used,
     * once such that the ctx is usedIf any of the tests fail (= return 0),
     * the end result will be 0 thanks to multiplication
     */
    for (i = 0;
         i < sizeof(tls12groupselection_tests) / sizeof(tls12groupselection_tests[0]);
         i++) {
        fprintf(stdout, "==> Running test %lu\n", i);
        testresult *= run_12groupselection(&tls12groupselection_tests[i],
                                           WORK_ON_SSL_OBJECT);
        testresult *= run_12groupselection(&tls12groupselection_tests[i],
                                           WORK_ON_CONTEXT);
    }

#endif /* !defined(OPENSSL_NO_EC) */

    return testresult;
}

int setup_tests(void)
{

#if !defined(OPENSSL_NO_EC)
    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;
#endif /* !defined(OPENSSL_NO_EC) */

    ADD_TEST(tls12groupselection_test);
    return 1;

}
