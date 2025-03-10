/*
* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/

#include <string.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "testutil.h"

/* Invalid RSA key with version = 17 */
static const char invalid_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBEQKCAQEAubZR/vxN1MmxwDEu5p8IA5kNWlOXhd0U8faIDZGY7h9xs7q7\n"
"Hr6Xd4azC+oXDyS3oOexFvLGkIzzdJI5hJJBh4benU4PXz5W176euXHT+KT4EgV8\n"
"+fkFO4KdHFTRo0D+XJCm4iilhx2pAHcBQbTG5vKYQJcYyxZGek9f9jiCsgQlUCj0\n"
"l0Xe3Hyktcum14rPMrZQ8Gv4GGLtoIVqFOh2ftQIY0IoSm+XUulkNfcRmgXMMiCp\n"
"VHdKkx2+vh8asN+drq7bEydBw7XEjhoUJszZVPubUUDBTa7Jp5vpx8jlBhDftInH\n"
"U5mZz8FKx1dlurSuio312Ww940wSQ1saAs9uyQIDAQABAoIBAAmnaNIfWIZtaQrr\n"
"ePDZJzKqA/qEP5YLB5nfwx59c/HmUDlTxYK+zU3pLSk7OoakKyg3Ux/fxU23Xg0w\n"
"cBgBqFwSDpl7zisZKQI0cQ4v1MvnUNP9qrZYk8U5BXohuKIgG05Bi23/R0I5Bajg\n"
"sX/dFL07CDTMsKfCA9jmLmq0xlUtm3d4R8h050OsFZQqIYFrsXeRkhXuI1Bk+wp7\n"
"O6qvrBSS4psvyA3Ba2M1Jdg+7XP6R6VamJQUilA1jrlMYrGehPPX2vhmzWpgaSDV\n"
"S6QdeqZI53fVJp/gCxKoz1zPgj9iwejcRC7Dp+M1aRP0RJGbqkpccpk0WBdUO0rd\n"
"X5waR38CgYEA+DN/vNS1ThTUImiJcl2dxxPkDIfmLOGIalF8cps9Ez3FGb+wJggX\n"
"iFCdK1A7wJZr3GfEV3HkH5hEzuG+losyY3NdbEfZgdrP3h/iEQxKy/5lZZmJC48T\n"
"HCDSRokZWfRdBtT63yBflPnqBQxmHv3HYNdHGhljvxYzODfvbcT4268CgYEAv4wq\n"
"1UrPZ/i2h4SfkezkdhkB6KvIsLyGBPVeZK1BOmIC27KOrARj+HgRwcqCaw7q+1PR\n"
"FbUN5ad190xenPgWG/wDD15AJmQ4jqHvfQrehVWeTmjO9RnLT1guxB+ZQknYuGCn\n"
"Qz8GEjIoJ6h7PMDXhQdYEbdrzLyQ/xU6EVkvowcCgYEA4M3MUd0bBkjJRw0GCOcQ\n"
"BANZF5xzd40jAKEjpa5DqEzXXBYJ1riXj+jsIhH+vNXBhhUaedV3OMKy9+rxs+sJ\n"
"zZftMyj0sa/dfKPGH4jRqmiVsGta/HQva9eyfR6qLpatN4XqX/QzfnzJYJ81U7aq\n"
"QmVaSiJa/PV/mNjY7MRuXpMCgYEAkErtpVlCnocMMVAlyI6Ul6ZE+toVR5Xsu2V/\n"
"YwXkwi89CfUbZtez22PPtJVx42YMe6FrOxf1zQ92XQGJsGNufEw+neAZIRKUTFYO\n"
"i7qZYAXcSCLJ7Hcu4amDKTjIgdgRSut8dLrQPvrLpvxTQbPfZpXesRHkQgm2jIGY\n"
"CaOOsBcCgYA3ijrhl4w4Hc47SGsDhgHPBt+ndof9zS1WcyOAv/TzLuwgAnA0vNU7\n"
"6AFi5AVKt/79vD5f6SOqgTDSyasB1qcP2jYV8GaIbqYQ4Gwpz1wuBkmkDKk28pC3\n"
"ec2eK8O4cJUmZn91oQFuJorjuVAa5GluyMGvCdxWeAQVH96xSG7lEg==\n"
"-----END RSA PRIVATE KEY-----\n";

/* A valid RSA key with version = 0 */
static const char valid_key[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdtzJxhAb9nEDZ\n"
"tCDfqIJB8DqDFYy+Osk3YxoDH2Xtd0epf6ezcTYIAq1ur/ThKh3BTNpquh168XgD\n"
"6cvZC9oriN0i4idjp3dG+Bt3CW+rie+ky1VSus3Ccm5LbFEsvijKUH+KCZpToZyX\n"
"xFsCiiOFuoNVJjGPX5jw8IrXFcnxqyFi4yCYCt7JxFMtc5B9iRG2YSShm9AdWOd/\n"
"blNIImexOZ++4CUH58KNXyi8zEiqM1IKjG6zJvkRJ3m/p7tnntJTlAKn32orjdzr\n"
"ocRFlHL4ZAuC7OVXmVt0J76SRx17AJbdyH/LrIMwtlorNqmWWde2Ch+kAQTAzqxu\n"
"yJIEUpdXAgMBAAECggEAS0mpreC9yZEur/459yqky79W3z6JSkIbzfHj9/ukF6Dq\n"
"N7K1poZzqY1Fp2IdvuLxA1ahqXMhIZBln1CbPAhZZJDYJ4/YB81oths4WTHK+hNF\n"
"r+BU4cJE+P7RQfX6Jia8qB+XUpjU7/llHFnirCqvXGY1zY8G949GHjZlwNko5tDu\n"
"wgB20B0+RG58gGqNpsJroG0wXsseefXSkegBN2p+By1hxd9A2tseuUlQJPVaNbAg\n"
"ray6O6DhS6UPcxp5mBeqL/MAEdEu9XeZy/+vfCjqXwM2XM0cgAQ+qq3A7UG+RD9Y\n"
"w3cIhKwOiIPd7rqNQgvrDiOZecqR3TrtTZ2Xqn/TuQKBgQDdplazM9TnnitjZjz+\n"
"jESOZD01h82rFyOUYO6o+bl6ofV5US7hIGpQYLSVi3UNmWxM2Qo4VGUduwQvPIPS\n"
"HlaJsrhfCKBogqdY2t1YmNUq601LFiEo72kFuK+4xx7/+i7jr+7Md/A4LOZ7mHFM\n"
"O9fYN/a7W3g32XTvwK5Kvw1BswKBgQC2KFsHb9BIUF+CkiOLYJQBjO+AAsIleUGr\n"
"Egoqu4F8vI8Ww7O20rbJW/iR+r2lTY6H+zQ7EG4jiZrfzoeD5XMcQYjabqNUcshk\n"
"iDl69BLdYVnW88SQudjvxlk73ZyX97PZTfH0Xd6NiWKkKuTiksm0EAkqlT1qLe/4\n"
"MpVnOUuZzQKBgAuL3LxdGNwv+yakbsz71Z5tTlr5hhdBj1LtccFPsP/YbAcz2XNU\n"
"0vT49K9Non1g3qlqLQQeMV5JHcCwMFXDytJFgyFAO8r1823HiPxSidhAhbhBoNyX\n"
"DCuGIXFIvi6rg8HMqm3wWY0zmZYarNxByc6zq6C69RpDs7nBmdK+/RvNAoGAIn7z\n"
"9i2TmQ43eCequYtZnA2PkYN0NtqGuBnbeQo3VGL1Cg+XqgiveuSC50o/vd05H8FP\n"
"u9u5r9swTC/1c+Hw8anre8o1/hkaoAc4M3OjWu9DrzRMxkebsJS0c2Tdcd4D3iQn\n"
"rOpV6iHZX1OMMugvcH0U706B6ei3KB6UMo8kJQUCgYBcJ1DquYhPbzyPPHav4t8S\n"
"Z06xsu7t1GRvznjb+BWFaETEiJ+DaK+L69TVo5MkEnvLc+eM21giUW7tTwtUeqsM\n"
"t6ymPDw9LjoUMy9dD3WTKxZ/ZY0OfWP6vLYmw2YMuLsOlWWNapzWYzO6oFhdlBzV\n"
"+8w2Xvhb+GUNjlmqki1pxQ==\n"
"-----END PRIVATE KEY-----";

static int test_invalid_rsa_version(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    bio = BIO_new_mem_buf(invalid_key, -1);
    if (!TEST_ptr(bio))
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!TEST_ptr_null(pkey)) {
        TEST_info("RSA key with invalid version 17 was incorrectly accepted");
        goto end;
    }

    if (!TEST_true(ERR_peek_error() != 0)) {
        TEST_info("No error was raised");
        goto end;
    }

    ret = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_valid_rsa_version(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    bio = BIO_new_mem_buf(valid_key, -1);
    if (!TEST_ptr(bio))
        goto end;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!TEST_ptr(pkey)) {
        TEST_info("Valid RSA key was incorrectly rejected");
        goto end;
    }

    if (!TEST_true(EVP_PKEY_is_a(pkey, "RSA"))) {
        TEST_info("Key is not recognized as RSA");
        goto end;
    }

    ret = 1;
end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_invalid_rsa_version);
    ADD_TEST(test_valid_rsa_version);
    return 1;
}