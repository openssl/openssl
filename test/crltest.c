/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <time.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "testutil.h"

/*
 * Test fixtures for certificate chain and CRL validation.
 *
 * This dataset contains:
 *  - a root CA certificate with the corresponding private key
 *  - a leaf certificate with the corresponding private key
 *  - several CRLs representing valid, invalid, and malformed revocation data
 *
 * The availability of the private keys allows additional certificates, CRLs, or
 * related artifacts to be generated within the same chain. This makes it
 * straightforward to add new test cases or regenerate existing ones if the
 * validation logic or expected behavior changes.
 *
 *   Root CA  (self-signed, trust anchor)
 *       └── leaf  (signed by Root CA)
 *
 * The hierarchy is intentionally flat, no intermediate CA. Chain
 * building is trivial: the leaf is verified directly against the root,
 * and every CRL is issued directly by the root.  No -untrusted store or
 * additional lookup callbacks are required in the test code.
 *
 * Root CA:  CN=Example Corp Root CA
 *           RSA-2048, SHA-256, validity 10 years, pathlen:0
 *
 * Leaf:     CN=www.example.com, serial 0x1000
 *           RSA-2048, SHA-256, validity 1 year
 *           SANs: www.example.com, example.com, api.example.com, 127.0.0.1
 *           CRL Distribution Point: http://crl.example.com/root.crl
 *
 * All CRLs were produced and signed with kRoot. Every malformed CRL carries a
 * valid RSA-2048/SHA-256 signature — the defect is structural or semantic, not
 * cryptographic.
 */

/* Verification time. */
static time_t kVerify = 1775779200; /* 2026-04-10 00:00:00 UTC */

static const char *kRoot[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIEFjCCAv6gAwIBAgIUQR1kHB+/IzJcfAT/HHVPp+wPmxwwDQYJKoZIhvcNAQEL\n",
    "BQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQH\n",
    "DA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQKDAxFeGFtcGxlIENvcnAxHjAcBgNVBAsM\n",
    "FUNlcnRpZmljYXRlIEF1dGhvcml0eTEdMBsGA1UEAwwURXhhbXBsZSBDb3JwIFJv\n",
    "b3QgQ0EwHhcNMjYwMzEwMTEzMDUzWhcNMzYwMzA3MTEzMDUzWjCBkDELMAkGA1UE\n",
    "BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lz\n",
    "Y28xFTATBgNVBAoMDEV4YW1wbGUgQ29ycDEeMBwGA1UECwwVQ2VydGlmaWNhdGUg\n",
    "QXV0aG9yaXR5MR0wGwYDVQQDDBRFeGFtcGxlIENvcnAgUm9vdCBDQTCCASIwDQYJ\n",
    "KoZIhvcNAQEBBQADggEPADCCAQoCggEBALm21ITU+2o6ZHWukCyBw9H270fSABYT\n",
    "rl8lhPCcTXynW9tBeHAaV50WMiOxBl+thfv1fGS3t8BbyjEjP3I5LAkBS9dTUI7F\n",
    "PSQnngBgKvKrpsnsiJXVhNOISm6GfT/EXj1NWKLXR3MXGIGfiVud5ln9CQxzaq3e\n",
    "TzW8X8zsdv6WGaeRIBm48QYe8TkK/TDmvoYZ7fD9lPMk3AUoNasZfuPeGpzh1cBR\n",
    "bfvOYEHJQ31+GFzrJFldqoaq/k0If/khwVgjOdmF+R25OCF0jsrMjmZ42Qr2cNrd\n",
    "VYEIjQL2R1grCVCGaIagzQuyN0Qvvl5BXsHKI51TpDQlq9SFkCOvRckCAwEAAaNm\n",
    "MGQwHQYDVR0OBBYEFP4UDhMbCWfLSg1L2k/z75C1Q9szMB8GA1UdIwQYMBaAFP4U\n",
    "DhMbCWfLSg1L2k/z75C1Q9szMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/\n",
    "BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBcYi8b4tetG18ElSqF/CJkjm93xS6k\n",
    "tk4jia0k+79FSAvy/TlcarBAe3PwlLA7GcLYDUmmM7GCiEMf91+c6dOmKkIdbw1B\n",
    "FILQBnghZ9s+xl0+n1P0775dDWc0msXhXci/wcRK3HFqxEOXQUkDYZwrq1gXBESr\n",
    "6yjpYe2RFKQUdnW+yrMlY1QyGNhelV7//BbSG8fD1esU7VaBE0wF/b8Ly2ykK5QE\n",
    "d6XUwqTT6sIlcyxVGUgEMVj7kSZUQJ2LS/ze/r+a1FeC2I0UljD78UB+I40FafZe\n",
    "pLLvkABIXRqtOiZ5YkdEK3Z4xI0yqSZC3og4jHsoCrfWbXasRieYR7dT\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

/* gitguardian:ignore */
static const char *kRootPrivateKey[] = {
    "-----BEGIN PRIVATE KEY-----\n",
    "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC5ttSE1PtqOmR1\n",
    "rpAsgcPR9u9H0gAWE65fJYTwnE18p1vbQXhwGledFjIjsQZfrYX79Xxkt7fAW8ox\n",
    "Iz9yOSwJAUvXU1COxT0kJ54AYCryq6bJ7IiV1YTTiEpuhn0/xF49TVii10dzFxiB\n",
    "n4lbneZZ/QkMc2qt3k81vF/M7Hb+lhmnkSAZuPEGHvE5Cv0w5r6GGe3w/ZTzJNwF\n",
    "KDWrGX7j3hqc4dXAUW37zmBByUN9fhhc6yRZXaqGqv5NCH/5IcFYIznZhfkduTgh\n",
    "dI7KzI5meNkK9nDa3VWBCI0C9kdYKwlQhmiGoM0LsjdEL75eQV7ByiOdU6Q0JavU\n",
    "hZAjr0XJAgMBAAECgf9u3uJWatBYcC6JaIL/ZHkDYJMkIrrqcyrRTWo65cAHgI0r\n",
    "gxU5LSt2cfR9BQeebHm7cf2mzgdlT2c7mU9yDFpoWzMWhHwTaq1AaGZrfajQ4f6G\n",
    "ONqnQ6bd96p3/CfKFJwuUiltuMLEctquiA/4zMuN7az5Qe5DiUoV9TU8TJoTDNo9\n",
    "72b4lqv5ptORlcu0JCPedlfXWVue3HfX0RUXr1kz6TWi+TRYRz+t3oPj1f/XyWSJ\n",
    "RzmjKgG0orOPfN6XFeS8/vSglE73K1rosYJZ9YIvoxw63ID1eCGY8nlc3Wz99tpt\n",
    "dE0qiNht+2O2wt2DR0VQCUhnAmj8l0UDLPUcGbkCgYEA3BTBbCsjwvxiApddPYDx\n",
    "rwtxH7evdPPmZ+PofnGEKWL/eghBHy+arMhGt6zbJ6aTUfjmvz+nIpbs4SiGijEx\n",
    "NWRyLtUcRCdhSNj/4c4sNT5biRBFaogGVUi/BxO3lXxx43Kw04hLSuch2vAXN4OZ\n",
    "eQnWHB3zyijUUzcEayiRiv0CgYEA2AYvfwvpQBPOA8I17qmkXMrjonGnr0NGHzLq\n",
    "+PtwTZhxnkR6dCXR9OtOYcvlo8aGb91zETYYR2MU0ArJRBj5gerxfG7/c0gthaAI\n",
    "xgmFgNXLTEsj7lY8MGedbxTsahJYiN/U61W1zZQ+B2lW7bBCpD1w8CZjPJkikxFz\n",
    "y3KBHb0CgYBLkxEMvQ+twI9DhojtOt9DlfFFzAUDa1HesSPAb+jLcYR7emQqemVq\n",
    "Geg24LPtPMVwK8HJQOl69krn0svInrXgONsA/AuV19QPePz9pJgHvJ8gRSchOw65\n",
    "sJ5wprOvMKnHSjYwnagFU7OLhFDkrltAdkFBLIPwEu8+mDD7P1YjXQKBgQCxMrG3\n",
    "JxAXracp0h7nPGREcXC0CUKhMy/L27p+rdF69PcN+eHwcC1/F51d/yDJbMlN7Xq7\n",
    "vYHA3Pdvh8l8gHf6J7wac/o6mBQvLgzEVX8bJUPzuxcoI7iPhA7R1XnvsEjLTb+b\n",
    "otzUWytebPwPUKv5iSSg+Pwh8wM3W/N+CNj8iQKBgGQfG/6793AHJ2G+uhotwAv4\n",
    "7PCC7qnZ6Cj5n/HwfjMTe+U6EzsRsZ6qmY+cCuXp5xUOFHVJPMQJTzwOG2WoyEdo\n",
    "qXVWEwK9CXZlZgvj5BwdA17qKGjj6RejIiiHsJ7K48H82idUixj4M8BLBg0Ff160\n",
    "rZXnLhJEdTFhSZGRXJgu\n",
    "-----END PRIVATE KEY-----\n",
    NULL
};

static const char *kLeaf[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIEajCCA1KgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVT\n",
    "MRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUw\n",
    "EwYDVQQKDAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhv\n",
    "cml0eTEdMBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EwHhcNMjYwMzEwMTE0\n",
    "NjUzWhcNMjcwMzEwMTE0NjUzWjBqMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\n",
    "aWZvcm5pYTEVMBMGA1UECgwMRXhhbXBsZSBDb3JwMRUwEwYDVQQLDAxXZWIgU2Vy\n",
    "dmljZXMxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB\n",
    "BQADggEPADCCAQoCggEBAKSuf+LYfmahQUGet4JsLlvfE3WvcHCCtufFZu2hzt1K\n",
    "gqvwKWimmCVMlmpuzSoNyLn+xdTYDtXyiP/M52aep3+tgUZvdWv7kxCVu8728RWO\n",
    "mSasl+gqXLulP7C7ZIxSG+0APz9Y5ApafL+ykxAK0dprMYkB49S3Phn5uiULjBWc\n",
    "Es9gLqzsr/zvRB0qN9Ly3at2XiZJzjfmkXB0OA0VFswxGl6HG3kIzLzs4YJgoOZd\n",
    "UZO2jGaOgp+rVPQvuVJVefUrYlyaLGd9Dt/YKPoxhlnvEK3khYz69dPHCwaCZXwz\n",
    "sJdaqYE2p7Us26ce3rEnWcz6gUIe//VQRohSEq0fZbUCAwEAAaOB8jCB7zAdBgNV\n",
    "HQ4EFgQU7Y2XD9s8Xb5gnFtGbfrjd8ICMZowHwYDVR0jBBgwFoAU/hQOExsJZ8tK\n",
    "DUvaT/PvkLVD2zMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\n",
    "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD4GA1UdEQQ3MDWCD3d3dy5leGFtcGxl\n",
    "LmNvbYILZXhhbXBsZS5jb22CD2FwaS5leGFtcGxlLmNvbYcEfwAAATAwBgNVHR8E\n",
    "KTAnMCWgI6Ahhh9odHRwOi8vY3JsLmV4YW1wbGUuY29tL3Jvb3QuY3JsMA0GCSqG\n",
    "SIb3DQEBCwUAA4IBAQB2BnaCrEzcEACF0hMx79MFn+6w2qq168mOO1fKKtn78N4i\n",
    "Fvdt17J8aJB9A4O7G7Qt+sJc7/g9U4h9vgNZ0d/RruA5qTNiyfOqCpUrZQawfoP7\n",
    "ZbGq1owzSNPzC2XDt2W+V3mw7/lnJl29H/799ckd0tL3tdg9exqHYJTWRoO5H1CI\n",
    "BCeOSvFxuHr48INiPRAqrI67aTsr9PWtUnPuKfW26eQYAt7M8bkMNu2tzEs01/A7\n",
    "HkZXNWRfS6H+P+hshnrNS8TXdonHODbqU8DvGhgtBDIg4VForc4yfxzoCSXfidd/\n",
    "/5VYiKF/M+F+UWklBm4ij0xf6o7HkjlfyukN5TjN\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

/* gitguardian:ignore */
static const char *kLeafPrivateKey[] = {
    "-----BEGIN PRIVATE KEY-----\n",
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCkrn/i2H5moUFB\n",
    "nreCbC5b3xN1r3BwgrbnxWbtoc7dSoKr8CloppglTJZqbs0qDci5/sXU2A7V8oj/\n",
    "zOdmnqd/rYFGb3Vr+5MQlbvO9vEVjpkmrJfoKly7pT+wu2SMUhvtAD8/WOQKWny/\n",
    "spMQCtHaazGJAePUtz4Z+bolC4wVnBLPYC6s7K/870QdKjfS8t2rdl4mSc435pFw\n",
    "dDgNFRbMMRpehxt5CMy87OGCYKDmXVGTtoxmjoKfq1T0L7lSVXn1K2JcmixnfQ7f\n",
    "2Cj6MYZZ7xCt5IWM+vXTxwsGgmV8M7CXWqmBNqe1LNunHt6xJ1nM+oFCHv/1UEaI\n",
    "UhKtH2W1AgMBAAECggEAJouPdF2e7E+nEgBfzH+ctDU4/U00gKkfvYz3Q/yhCiuz\n",
    "/SGH165SozxTYpMPo125k0s+K8zsYAhWJ6ViriLJarmGLiHNdppaOEILxOwIzrZj\n",
    "Q2mXXqh3rxYFG80owi0/yw/JPf8E1SWL2GSoRlN5/ekkHYDbPkEroHHSr3QN9EqE\n",
    "fALsLA1y4Kt3gpTlZ3X9wHrZRhB1WW8/LYbNfA4WGZZDMzYQEdUp5SX0BobVkrAU\n",
    "HaCew75jhXtPjT424JjRqmIE+gK04oVx2TXKLQnEHTjPivvfrOuE+ne2syn1tZIS\n",
    "tXCZYy0gg2ElyatzhOAGTx0FMWkftVYnJ4BIF3hh8QKBgQDjwn37UmXRPM11J0vT\n",
    "LK1MGkMUBCP//yFfH+CyJ5JkTsmsrXoNox182cixIUnlkK3eRm5ilwXYmu+yMv3J\n",
    "3hC1KJDUK+BJfIfPw10OIN9bGJdzmOujM6P/kw1KluZQLSDDQ/FI/Rv8KZTxcgmu\n",
    "nM807oFQMVbXsFUeHyHEi5xpnQKBgQC5GctGeKG1BJFSKONs1FfjuA8SAosVddVi\n",
    "CD8pBmL16ytinnJgUoxdaJBJ58M11unj1x7I7wPVGmgGC2xLadOQM18C+qJbUx/2\n",
    "y6VL4kaK5la1Php+OAI1dmCYuggHiBqKd/r1IF7u3Co5WW+Fmtb6Faqk69xS6zBF\n",
    "Q3TA2tWc+QKBgQCAGHP4dHg1POgk+qvnohn5Uk/lowqIQPqI4InkSONJrRI6Hvsl\n",
    "TlcYT/hSvvErvro66AvPQTcVgtZKt+kKru1gpecGnYKwceyESlE8z/ou5t7PMfNd\n",
    "P37+D7uK9uGjuC3UBJNgxJIHuW8+eC+/2AulrnpmGsnH1zGYFlRMkWSv9QKBgBqB\n",
    "uBtiYP3UJp9WXaMTEXb5v6a7mIE9O45rUeglEvzWbYMU35otmA40UB1VRB4spZfM\n",
    "EYuCttDIlEbxUdPG1tYalSuPCrr7P2OPLB+eyq1PaPFRcGfMy3wudIzKbyXs9qgH\n",
    "oHeD6DRacO1/gjnmv4xWl/ZAFHAHYAU7MLgBXn+5AoGBAJIp58yKL03CrXfzQA0y\n",
    "D1bbuvbBA902XBuBXaFfBPw8JwcmhmyF/ipYffwQBg7l00JKYC5ASv0zV5LQaaFl\n",
    "S672xAaFwhlZXU6FVm6tRFPHTAz4petGVO/o3E3AABl31ABxxOvB3dRUnQJkQ9Eb\n",
    "UjtDosbWW3y64bplzfgGZS0n\n",
    "-----END PRIVATE KEY-----\n",
    NULL
};

static const char *kCrlRecovated[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICUjCCAToCAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowRDAgAgEBFw0yNjAyMDgwODAwMDBaMAwwCgYDVR0VBAMKAQEw\n",
    "IAIBAhcNMjYwMjA4MDgwMDAwWjAMMAoGA1UdFQQDCgEEoC8wLTAfBgNVHSMEGDAW\n",
    "gBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIBAzANBgkqhkiG9w0BAQsF\n",
    "AAOCAQEAZAlvLBRuoem3rlI0QbC9SlYe5yKRGRXNYqpe8fQ4vB0IuGp3jqADecxD\n",
    "qjuJClAhwijra2FYr6oPZ79EXeqiMKXb3AXYJ0x2WhKFyf4AuaiGjXULHUweSDL1\n",
    "F7Rjx/3vX4zRmQMDc/FXm3TK9OUjcNYdOERu7dzHhjUR+c0/nNG9g9Zjg9iAXCyQ\n",
    "dgkiRkFuorvnM1xTs7BVy2A+uM3FXfe5wE4plYBnVHOKJPWGmSYJu9PbweHSqaci\n",
    "cR5kb5IeDXiIjKYPimaeVxnZdoA8MzasOv9GnDWrNmuq55t3v7apic9x7/L85EDc\n",
    "LPVUUd5Y0tewL68R7vM96wGtZ+GLHg==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlExtensionDuplicate[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICPTCCASUCAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowIzAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "oDswOTAfBgNVHSMEGDAWgBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIB\n",
    "DDAKBgNVHRQEAwIBYzANBgkqhkiG9w0BAQsFAAOCAQEAGfTawbm18r/wEiCoCNok\n",
    "i1dPdoZIm6ZK+NUL09SYmdQm99D3UqaXDkBMu5j524ozKwr+wkRZcAd2Q+mJKXAt\n",
    "TAO+geiDrhDRdjC+B04KPhvZnqWQsvLCxhU6kmCM34bHxUHTGltMbQxx96TqEsbn\n",
    "1TLn4iN6WPyYyRolIPPy5bPymTCV7vTPeyZhZYNPv2xZwDSS50rFIQFr+H1/PyUY\n",
    "OxRqBmdYOwbfNn0L7SOkAzP+OStK+0krtFWSRIp+aBCfDvsdXQFy3P4C8IVwiGQY\n",
    "ld2Dcfnr13EzzD2XaNJ2cqPdiSGso9fXwLGpn+9SvqzFwdS2QyV5eolbhe5ZiNjO\n",
    "0Q==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlExtensionDuplicateEntry[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICYDCCAUgCAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowUjAtAgIQABcNMjYwMzA5MDgwMDAwWjAYMAoGA1UdFQQDCgEB\n",
    "MAoGA1UdFQQDCgEBMCECAhABFw0yNjAzMDkwODAwMDBaMAwwCgYDVR0VBAMKAQSg\n",
    "LzAtMB8GA1UdIwQYMBaAFP4UDhMbCWfLSg1L2k/z75C1Q9szMAoGA1UdFAQDAgEL\n",
    "MA0GCSqGSIb3DQEBCwUAA4IBAQCRInhKVl+Hz4Ukacr7lSCHyir2cFoOqC5H5pye\n",
    "f9CP3M8fa4oIwv0FFAVwHT/E+6ko2id7qqVdADFql+koVY7DBXIqrQ1qcAoGyclm\n",
    "n/UEEbs2UdbqJiVzlurh5jupExYSj2uJo8ZYONhnqKnDzPfpyvBmfE7/X/wPla6P\n",
    "nSGDg4kYC3mtjrIUBwCqxn3WOG7Ai2WtpRvtCtNzhlEddroOonIS36Bh3c0T+dNT\n",
    "lsvIKfqkfZazv26F1vDFEYS+L7yrzRnhD2eHvX+9xYtotnzwUhPCMuXLbp9sttDu\n",
    "9SD2VaXnw/5olvv15CSvlw661kh0CQrHydCgRXVxgJX5mfAv\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlExtensionDuplicateSerial[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICdzCCAV8CAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowaTAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "MCECAhAAFw0yNjAzMDkwODAwMDBaMAwwCgYDVR0VBAMKAQMwIQICEAEXDTI2MDMw\n",
    "OTA4MDAwMFowDDAKBgNVHRUEAwoBBKAvMC0wHwYDVR0jBBgwFoAU/hQOExsJZ8tK\n",
    "DUvaT/PvkLVD2zMwCgYDVR0UBAMCAQowDQYJKoZIhvcNAQELBQADggEBAAtpEQmD\n",
    "QEYmCCPl1948oulVBj4ZeAB3+AK3o96pd/oUY9VKNmP7uMezD/s9ilC7Ip56u2en\n",
    "EgrjbSEyrFF7XqXY72Z18EU54xG85dzZv3Ri7SpUoXTL0vNRIvl4/GHZjHzQZTB1\n",
    "FGvm10FcFUpgX2EHJVuIWuldqxp4OeJrBIN0wSFciH8PQqs6o5Dw+sYdj2Culnsk\n",
    "gi30uB9qfacgppqB3zFf0ayuauO8rupnpSLk+IfapHLWiS5JY6ZX9R/WIKdAc0eR\n",
    "6FDo5g9+QvOfhtANWTYJFh8f1Gcnt2BsWGMl8134V3YQ2q+Wb1I9tdli6/4o+dNZ\n",
    "ROh6Cs4QAn5WVyc=\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlIDPOnlyCaOnlyAttr[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICajCCAVICAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowIzAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "oGgwZjAfBgNVHSMEGDAWgBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIB\n",
    "FjA3BgNVHRwBAf8ELTAroCOgIYYfaHR0cDovL2NybC5leGFtcGxlLmNvbS9yb290\n",
    "LmNybIIB/4UB/zANBgkqhkiG9w0BAQsFAAOCAQEAHC06Da0jYHaO6pqNpXmZ7WVX\n",
    "a/LZgrqJkdr1CPM9OBMYChOOYBy0Gkb6JJaRzMgKpNmXtx+mYhr/WoQ2B03R/FOW\n",
    "AL8BuTTgy9XRGGZyyUXzXL9VLRtE23ebk3jkxtB4msqenlY/CfkjGwqrikJcCBwp\n",
    "sS/FAO5Z8Sg1V3cg2cvJmnuwqMK6+PDx55hasC0GyWKH620JeK472HbWPgJT0HVR\n",
    "GjQo7Z3+iuSOLW+ZXJyZ8bsHKtWI/mpQS1SfP1NXUlOdtjr6ISNBmUrIq7tL6SBR\n",
    "5NdHaH/jzW3yMQE8LMFtONafDofXXTRjCOdZjh/5Bx3lVlxgAp8PKlzCYkTERQ==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlIDPOnlyUserOnlyAttr[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICajCCAVICAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowIzAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "oGgwZjAfBgNVHSMEGDAWgBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIB\n",
    "FTA3BgNVHRwBAf8ELTAroCOgIYYfaHR0cDovL2NybC5leGFtcGxlLmNvbS9yb290\n",
    "LmNybIEB/4UB/zANBgkqhkiG9w0BAQsFAAOCAQEAhx9Zg1b1Y5ITgN9BX15SDjuE\n",
    "viYCk+oQpGAcLnTYq8cFKoGUug3mn3vEYh4dg64hxsWX64X8jcD/fQRM3Ot1SHDZ\n",
    "hYOG1QBJyMN/bU5kc4zqXoH/bRrEERiE5maF84wqKHr+DvJukpAX6i1uehyLEG7s\n",
    "mjSKin54s44lVQsX8I93aTks8LPCjxfhusCKvrWmNWDHgfh4gwKsIj3U5ToYjISr\n",
    "nrFBEAAKzCAaxTgxLrg6+uagA3bFGhRwrqBMFLAysKTJnJpp1Gn8PQdEQlLeYYmo\n",
    "pDhvJcCx5qWn+SV1jfOar5JhR12G+ulc73aJR8c6zaJzoOp7OYtrMtai1gKvgQ==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlIDPOnlyUserOnlyCA[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICajCCAVICAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowIzAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "oGgwZjAfBgNVHSMEGDAWgBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIB\n",
    "FDA3BgNVHRwBAf8ELTAroCOgIYYfaHR0cDovL2NybC5leGFtcGxlLmNvbS9yb290\n",
    "LmNybIEB/4IB/zANBgkqhkiG9w0BAQsFAAOCAQEAScvTwUwgBhEANXRN5bL9S3nE\n",
    "vuxU/kZR8xtaGqUHTsrvcBxylR5VinF53RJlz0NaMxQRRpE+NLDZaW2tUbt+k/22\n",
    "QPWoGFTfZN2GolzuFqu7v/ZPtAM02NNfSoxVu+Xb9ycJWJFP1hOreioOknn7FqjR\n",
    "212EypnY5a2D6TVgK11g1brPxVaN1rVt08zhrCj1mq7FWP4M6W2DkTZ6r1ExgIqu\n",
    "Kl//1G15cP+k7+SJe91c3cJ/GWzDHOrruLkzsaLAajKr6i5CWBEGEYHLvRf0RZq1\n",
    "eucBJgsWxYlHvIHgSA4/EbCq6mK4+m2MUAkOOPfaec8MzGJCm73VWgTnRwIWlg==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlIDPOnlyUserOnlyCAOnlyAttr[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICbTCCAVUCAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowIzAhAgIQABcNMjYwMzA5MDgwMDAwWjAMMAoGA1UdFQQDCgEB\n",
    "oGswaTAfBgNVHSMEGDAWgBT+FA4TGwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIB\n",
    "FzA6BgNVHRwBAf8EMDAuoCOgIYYfaHR0cDovL2NybC5leGFtcGxlLmNvbS9yb290\n",
    "LmNybIEB/4IB/4UB/zANBgkqhkiG9w0BAQsFAAOCAQEAQ7OlOy+pMrRHeM1W3d+s\n",
    "3Ev/fIEO852mBxy32OV4t3zjHnS+XK0u3U8fWUR6i31FrDQUJDLqNFhWPGHD/MqI\n",
    "bqn6zzLy35S5+AK2pChAKOdUxSzy8bjOx0tahpqSKXnijxCzFkEqs65J5yVwJJTN\n",
    "jK8ieuqTmsHKwbfPe6x93+7ceygknpeu3rsR2gMGwybNW8Yq7CUQ87sVcI4H3RAU\n",
    "6qbenT+eec6Xn6VpFQ1qnUvKxnw2CF6q11V/T9Rxqb0TKLia3NXG2IT6EHf6APJ6\n",
    "wN+DQSZq2qLdt3i3pbJQDcpT90a/PfaSlXcjtM6FcpN4bpex3CgLYIoCivDP9UXR\n",
    "2Q==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlCINoIndirectFlag[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICrzCCAZcCAQEwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYD\n",
    "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQK\n",
    "DAxFeGFtcGxlIENvcnAxHjAcBgNVBAsMFUNlcnRpZmljYXRlIEF1dGhvcml0eTEd\n",
    "MBsGA1UEAwwURXhhbXBsZSBDb3JwIFJvb3QgQ0EXDTI2MDMxMDA4MDAwMFoXDTI2\n",
    "MDYwODA4MDAwMFowbjBsAgIQABcNMjYwMzA5MDgwMDAwWjBXMFUGA1UdHQROMEyk\n",
    "SjBIMQswCQYDVQQGEwJVUzEVMBMGA1UECgwMRXhhbXBsZSBDb3JwMSIwIAYDVQQD\n",
    "DBlFeGFtcGxlIENvcnAgSXNzdWluZyBDQSAyoGIwYDAfBgNVHSMEGDAWgBT+FA4T\n",
    "Gwlny0oNS9pP8++QtUPbMzAKBgNVHRQEAwIBKDAxBgNVHRwBAf8EJzAloCOgIYYf\n",
    "aHR0cDovL2NybC5leGFtcGxlLmNvbS9yb290LmNybDANBgkqhkiG9w0BAQsFAAOC\n",
    "AQEAc2tRh8V2jStk9g78UUUp/v+zI8rGaeU2mS7EIqxyqzH916tj1+aKcH+wY5ed\n",
    "YGrsG5ERsdZWVWREpZmoIpqagF1nvU9Ya5unNDVGQZqRXtANX2bI1sdqu0tLZ+ul\n",
    "t3Um6jbga/0Ej1rGDjF3Y2/tvQ8q7v42Hk859TQp2xmX7er48ERj9RbL8I7O0AIS\n",
    "15dIAIhsFQJruelovjzJ6Y0tKZgJ+ExAItezAVhEPl6dqEYO5zXXXzwKRBG1A2Jh\n",
    "dKdLqbcqkFbd8jIr7b1JNrJU1jcIMAm3/X0l+XwH+ychKy4+6wjPiDVFgyDfn1qf\n",
    "ZjPymdOBXXH7OvqdCw43/RadaQ==\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
 * We cannot use old certificates for new tests because the private key
 * associated with them is no longer available. Therefore, we add kCRLTestLeaf,
 * kCRLTestLeaf2 and PARAM_TIME2, as well as pass the verification time to the
 * verify function as a parameter. Certificates and CRL from
 * https://github.com/openssl/openssl/issues/27506 are used.
 */

#define PARAM_TIME 1474934400 /* Sep 27th, 2016 */
#define PARAM_TIME2 1753284700 /* July 23th, 2025 */

static const char *kCRLTestRoot[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDbzCCAlegAwIBAgIJAODri7v0dDUFMA0GCSqGSIb3DQEBCwUAME4xCzAJBgNV\n",
    "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBW\n",
    "aWV3MRIwEAYDVQQKDAlCb3JpbmdTU0wwHhcNMTYwOTI2MTUwNjI2WhcNMjYwOTI0\n",
    "MTUwNjI2WjBOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG\n",
    "A1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJQm9yaW5nU1NMMIIBIjANBgkq\n",
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo16WiLWZuaymsD8n5SKPmxV1y6jjgr3B\n",
    "S/dUBpbrzd1aeFzNlI8l2jfAnzUyp+I21RQ+nh/MhqjGElkTtK9xMn1Y+S9GMRh+\n",
    "5R/Du0iCb1tCZIPY07Tgrb0KMNWe0v2QKVVruuYSgxIWodBfxlKO64Z8AJ5IbnWp\n",
    "uRqO6rctN9qUoMlTIAB6dL4G0tDJ/PGFWOJYwOMEIX54bly2wgyYJVBKiRRt4f7n\n",
    "8H922qmvPNA9idmX9G1VAtgV6x97XXi7ULORIQvn9lVQF6nTYDBJhyuPB+mLThbL\n",
    "P2o9orxGx7aCtnnBZUIxUvHNOI0FaSaZH7Fi0xsZ/GkG2HZe7ImPJwIDAQABo1Aw\n",
    "TjAdBgNVHQ4EFgQUWPt3N5cZ/CRvubbrkqfBnAqhq94wHwYDVR0jBBgwFoAUWPt3\n",
    "N5cZ/CRvubbrkqfBnAqhq94wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n",
    "AQEAORu6M0MOwXy+3VEBwNilfTxyqDfruQsc1jA4PT8Oe8zora1WxE1JB4q2FJOz\n",
    "EAuM3H/NXvEnBuN+ITvKZAJUfm4NKX97qmjMJwLKWe1gVv+VQTr63aR7mgWJReQN\n",
    "XdMztlVeZs2dppV6uEg3ia1X0G7LARxGpA9ETbMyCpb39XxlYuTClcbA5ftDN99B\n",
    "3Xg9KNdd++Ew22O3HWRDvdDpTO/JkzQfzi3sYwUtzMEonENhczJhGf7bQMmvL/w5\n",
    "24Wxj4Z7KzzWIHsNqE/RIs6RV3fcW61j/mRgW2XyoWnMVeBzvcJr9NXp4VQYmFPw\n",
    "amd8GKMZQvP0ufGnUn7D7uartA==\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kCRLTestLeaf[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDkDCCAnigAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCVVMx\n",
    "EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEjAQ\n",
    "BgNVBAoMCUJvcmluZ1NTTDAeFw0xNjA5MjYxNTA4MzFaFw0xNzA5MjYxNTA4MzFa\n",
    "MEsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQKDAlC\n",
    "b3JpbmdTU0wxEzARBgNVBAMMCmJvcmluZy5zc2wwggEiMA0GCSqGSIb3DQEBAQUA\n",
    "A4IBDwAwggEKAoIBAQDc5v1S1M0W+QWM+raWfO0LH8uvqEwuJQgODqMaGnSlWUx9\n",
    "8iQcnWfjyPja3lWg9K62hSOFDuSyEkysKHDxijz5R93CfLcfnVXjWQDJe7EJTTDP\n",
    "ozEvxN6RjAeYv7CF000euYr3QT5iyBjg76+bon1p0jHZBJeNPP1KqGYgyxp+hzpx\n",
    "e0gZmTlGAXd8JQK4v8kpdYwD6PPifFL/jpmQpqOtQmH/6zcLjY4ojmqpEdBqIKIX\n",
    "+saA29hMq0+NK3K+wgg31RU+cVWxu3tLOIiesETkeDgArjWRS1Vkzbi4v9SJxtNu\n",
    "OZuAxWiynRJw3JwH/OFHYZIvQqz68ZBoj96cepjPAgMBAAGjezB5MAkGA1UdEwQC\n",
    "MAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRl\n",
    "MB0GA1UdDgQWBBTGn0OVVh/aoYt0bvEKG+PIERqnDzAfBgNVHSMEGDAWgBRY+3c3\n",
    "lxn8JG+5tuuSp8GcCqGr3jANBgkqhkiG9w0BAQsFAAOCAQEAd2nM8gCQN2Dc8QJw\n",
    "XSZXyuI3DBGGCHcay/3iXu0JvTC3EiQo8J6Djv7WLI0N5KH8mkm40u89fJAB2lLZ\n",
    "ShuHVtcC182bOKnePgwp9CNwQ21p0rDEu/P3X46ZvFgdxx82E9xLa0tBB8PiPDWh\n",
    "lV16jbaKTgX5AZqjnsyjR5o9/mbZVupZJXx5Syq+XA8qiJfstSYJs4KyKK9UOjql\n",
    "ICkJVKpi2ahDBqX4MOH4SLfzVk8pqSpviS6yaA1RXqjpkxiN45WWaXDldVHMSkhC\n",
    "5CNXsXi4b1nAntu89crwSLA3rEwzCWeYj+BX7e1T9rr3oJdwOU/2KQtW1js1yQUG\n",
    "tjJMFw==\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kCRLTestRoot2[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIID4zCCAsugAwIBAgIUGTcyNat9hTOo8nnGdzF7MTzL9WAwDQYJKoZIhvcNAQEL\n",
    "BQAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n",
    "DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxEzARBgNVBAMMCk15\n",
    "IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJvb3QgQ0EwHhcNMjUwMzAzMDcxNDA0WhcN\n",
    "MzUwMzAxMDcxNDA0WjB5MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5p\n",
    "YTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEGA1UECgwKTXkgQ29tcGFueTET\n",
    "MBEGA1UEAwwKTXkgUm9vdCBDQTETMBEGA1UECwwKTXkgUm9vdCBDQTCCASIwDQYJ\n",
    "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6jjwkmV+pse430MQfyaWv+JtAd2r6K\n",
    "qzEquBcoofzuf/yvdEhQPjK3bcotgfEcFq3QMo1MJ7vqRHEIu0hJ+5ZnEQtIRcrg\n",
    "Vm7/EoVCBpDc9BDtW40TDp69z9kaKyyKYy6rxmSKgJydGBeGGMwBxgTK/o0xAriC\n",
    "C3lLXHT8G8YMamKUpToPL5iCRX+GJPnnizB2ODvpQGMWkbp9+1xEc4dD7Db2wfUb\n",
    "gatDYUoGndQKWD49UhURavQZeLpDxlz93YutRRkZTWc4IB7WebiEb39BDjSP3QYm\n",
    "2h+rZYyjp3Gxy8pBNTPzE9Dk4yjiqS7o3WGvi/S6zKTLDvWl9t6pMOMCAwEAAaNj\n",
    "MGEwHQYDVR0OBBYEFNdhiR+Tlot2VBbp5XfcfLdlG4AkMA4GA1UdDwEB/wQEAwIB\n",
    "hjAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDAPBgNVHRMBAf8EBTAD\n",
    "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCvwutY0WMcKoqulifnYfhxGLtXSSvD2GET\n",
    "uNRv+S1KI5JKcAdfvnbNDpUwlujMDIpe3ewmv9i6kcitpHwZXdVAw6KWagJ0kDSt\n",
    "jbArJxuuuFmSFDS7kj8x7FZok5quAWDSSg+ubV2tCVxmDuTs1WXJXD3l9g+3J9GU\n",
    "kyeFMKqwRp8w22vm9ilgXrzeesAmmAg/pEb56ljTPeaONQxVe7KJhv2q8J17sML8\n",
    "BE7TdVx7UFQbO/t9XqdT5O9eF8JUx4Vn4QSr+jdjJ/ns4T3/IC9dJq9k7tjD48iA\n",
    "TNc+7x+uj8P39VA96HpjujVakj8/qn5SQMPJgDds+MSXrX+6JBWm\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kCRLTestLeaf2[] = {
    "-----BEGIN CERTIFICATE-----\n",
    "MIIECjCCAvKgAwIBAgIUPxuMqMtuN1j3XZVRVrNmaTCIP04wDQYJKoZIhvcNAQEL\n",
    "BQAweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n",
    "DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCk15IENvbXBhbnkxEzARBgNVBAMMCk15\n",
    "IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJvb3QgQ0EwHhcNMjUwNDE3MTAxNjQ5WhcN\n",
    "MjYwNDE3MTAxNjQ5WjBoMQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQ\n",
    "MA4GA1UEBwwHQmVpamluZzEYMBYGA1UECgwPTXkgT3JnYW5pemF0aW9uMRswGQYD\n",
    "VQQDDBJNeSBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n",
    "ggEKAoIBAQDIxRxZQokflDaLYoD21HT2U4EshqtKpSf9zPS5unBMCfnQkU4IJjBF\n",
    "3qQmfgz5ZOpZv3x0w48fDjiysk0eOVCFAo+uixEjMeuln6Wj3taetch2Sk0YNm5J\n",
    "SJCNF2olHZXn5R8ngEmho2j1wbwNnpcccZyRNzUSjR9oAgObkP3O7fyQKJRxwNU0\n",
    "sN7mfoyEOczKtUaYbqi2gPx6OOqNLjXlLmfZ8PJagKCN/oYkGU5PoRNXp65Znhu6\n",
    "s8FuSmvTodu8Qhs9Uizo+SycaBXn5Fbqt32S+9vPfhH9FfELDfQIaBp+iQAxcKPX\n",
    "tUglXEjiEVrbNf722PuWIWN9EIBolULVAgMBAAGjgZowgZcwEgYDVR0TAQH/BAgw\n",
    "BgEB/wIBATAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vbG9jYWxob3N0OjgwMDAv\n",
    "Y2FfY3JsLmRlcjAdBgNVHQ4EFgQUh40vFgoopz5GUggPEEk2+bKgbwQwHwYDVR0j\n",
    "BBgwFoAU12GJH5OWi3ZUFunld9x8t2UbgCQwDgYDVR0PAQH/BAQDAgGGMA0GCSqG\n",
    "SIb3DQEBCwUAA4IBAQDANfJuTgo0vRaMPYqOeW8R4jLHdVazdGLeQQ/85vXr/Gl1\n",
    "aL40tLp4yZbThxuxTzPzfY1OGkG69YQ/8Vo0gCEi5KjBMYPKmZISKy1MwROQ1Jfp\n",
    "HkmyZk1TfuzG/4fN/bun2gjpDYcihf4xA4NhSVzQyvqm1N6VkTgK+bEWTOGzqw66\n",
    "6IYPN6oVDmLbwU1EvV3rggB7HUJCJP4qW9DbAQRAijUurPUGoU2vEbrSyYkfQXCf\n",
    "p4ouOTMl6O7bJ110SKzxbCfWqom+iAwHlU2tOPVmOp1CLDCClMRNHIFMDGAoBomH\n",
    "s01wD+IcIi9OkQEbqVb/XDKes8fqzQgTtSM9C9Ot\n",
    "-----END CERTIFICATE-----\n",
    NULL
};

static const char *kBasicCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBpzCBkAIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n",
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoA4wDDAKBgNV\n",
    "HRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAnrBKKgvd9x9zwK9rtUvVeFeJ7+LN\n",
    "ZEAc+a5oxpPNEsJx6hXoApYEbzXMxuWBQoCs5iEBycSGudct21L+MVf27M38KrWo\n",
    "eOkq0a2siqViQZO2Fb/SUFR0k9zb8xl86Zf65lgPplALun0bV/HT7MJcl04Tc4os\n",
    "dsAReBs5nqTGNEd5AlC1iKHvQZkM//MD51DspKnDpsDiUVi54h9C1SpfZmX8H2Vv\n",
    "diyu0fZ/bPAM3VAGawatf/SyWfBMyKpoPXEG39oAzmjjOj8en82psn7m474IGaho\n",
    "/vBbhl1ms5qQiLYPjm4YELtnXQoFyC72tBjbdFd/ZE9k4CNKDbxFUXFbkw==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kRevokedCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n",
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEyNDRaFw0xNjEwMjYxNTEyNDRaMBUwEwICEAAX\n",
    "DTE2MDkyNjE1MTIyNlqgDjAMMAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBCwUAA4IB\n",
    "AQCUGaM4DcWzlQKrcZvI8TMeR8BpsvQeo5BoI/XZu2a8h//PyRyMwYeaOM+3zl0d\n",
    "sjgCT8b3C1FPgT+P2Lkowv7rJ+FHJRNQkogr+RuqCSPTq65ha4WKlRGWkMFybzVH\n",
    "NloxC+aU3lgp/NlX9yUtfqYmJek1CDrOOGPrAEAwj1l/BUeYKNGqfBWYJQtPJu+5\n",
    "OaSvIYGpETCZJscUWODmLEb/O3DM438vLvxonwGqXqS0KX37+CHpUlyhnSovxXxp\n",
    "Pz4aF+L7OtczxL0GYtD2fR9B7TDMqsNmHXgQrixvvOY7MUdLGbd4RfJL3yA53hyO\n",
    "xzfKY2TzxLiOmctG0hXFkH5J\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kInvalidCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kBadIssuerCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBwjCBqwIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEWMBQGA1UECgwN\n",
    "Tm90IEJvcmluZ1NTTBcNMTYwOTI2MTUxMjQ0WhcNMTYxMDI2MTUxMjQ0WjAVMBMC\n",
    "AhAAFw0xNjA5MjYxNTEyMjZaoA4wDDAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsF\n",
    "AAOCAQEAlBmjOA3Fs5UCq3GbyPEzHkfAabL0HqOQaCP12btmvIf/z8kcjMGHmjjP\n",
    "t85dHbI4Ak/G9wtRT4E/j9i5KML+6yfhRyUTUJKIK/kbqgkj06uuYWuFipURlpDB\n",
    "cm81RzZaMQvmlN5YKfzZV/clLX6mJiXpNQg6zjhj6wBAMI9ZfwVHmCjRqnwVmCUL\n",
    "TybvuTmkryGBqREwmSbHFFjg5ixG/ztwzON/Ly78aJ8Bql6ktCl9+/gh6VJcoZ0q\n",
    "L8V8aT8+Ghfi+zrXM8S9BmLQ9n0fQe0wzKrDZh14EK4sb7zmOzFHSxm3eEXyS98g\n",
    "Od4cjsc3ymNk88S4jpnLRtIVxZB+SQ==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kEmptyIdpCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICOTCCASECAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowJzAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWqBLMEkwGAYDVR0UBBECDxnP/97a\n",
    "dO3y9qRGDM7hQDAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDAMBgNV\n",
    "HRwBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAf+mtlDi9IftsYwTcxYYKxE203\n",
    "+prttFB00om29jjtkGYRxcs3vZQRTvera21YFn3mrS/lxvhBq6GMx0I61AQ48Pr4\n",
    "63bDvZgf+/P6T2+MLgLds23o3TOfy2SBSdnFEcN0bFUgF5U0bFpQqlQWx+FYhrAf\n",
    "ZX3RAhURiKKfGKGeVOVKS0u+x666FoDQ7pbhbHM3+jnuzdtv8RQMkj1AZMw0FMl8\n",
    "m2dFQhZqT9WdJqZAc8ldc6V3a0rUeOV8BUPACf1k4B0CKhn4draIqltZkWgl3cmU\n",
    "SX2V/a51lS12orfNYSEx+vtJ9gpx4LDxyOnai18vueVyljrXuQSrcYuxS2Cd\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
 * This is kBasicCRL but with a critical issuing distribution point
 * extension.
 */
static const char *kKnownCriticalCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBujCBowIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n",
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoCEwHzAKBgNV\n",
    "HRQEAwIBATARBgNVHRwBAf8EBzAFoQMBAf8wDQYJKoZIhvcNAQELBQADggEBAA+3\n",
    "i+5e5Ub8sccfgOBs6WVJFI9c8gvJjrJ8/dYfFIAuCyeocs7DFXn1n13CRZ+URR/Q\n",
    "mVWgU28+xeusuSPYFpd9cyYTcVyNUGNTI3lwgcE/yVjPaOmzSZKdPakApRxtpKKQ\n",
    "NN/56aQz3bnT/ZSHQNciRB8U6jiD9V30t0w+FDTpGaG+7bzzUH3UVF9xf9Ctp60A\n",
    "3mfLe0scas7owSt4AEFuj2SPvcE7yvdOXbu+IEv21cEJUVExJAbhvIweHXh6yRW+\n",
    "7VVeiNzdIjkZjyTmAzoXGha4+wbxXyBRbfH+XWcO/H+8nwyG8Gktdu2QB9S9nnIp\n",
    "o/1TpfOMSGhMyMoyPrk=\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
 * kUnknownCriticalCRL is kBasicCRL but with an unknown critical extension.
 */
static const char *kUnknownCriticalCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBvDCBpQIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n",
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoCMwITAKBgNV\n",
    "HRQEAwIBATATBgwqhkiG9xIEAYS3CQABAf8EADANBgkqhkiG9w0BAQsFAAOCAQEA\n",
    "GvBP0xqL509InMj/3493YVRV+ldTpBv5uTD6jewzf5XdaxEQ/VjTNe5zKnxbpAib\n",
    "Kf7cwX0PMSkZjx7k7kKdDlEucwVvDoqC+O9aJcqVmM6GDyNb9xENxd0XCXja6MZC\n",
    "yVgP4AwLauB2vSiEprYJyI1APph3iAEeDm60lTXX/wBM/tupQDDujKh2GPyvBRfJ\n",
    "+wEDwGg3ICwvu4gO4zeC5qnFR+bpL9t5tOMAQnVZ0NWv+k7mkd2LbHdD44dxrfXC\n",
    "nhtfERx99SDmC/jtUAJrGhtCO8acr7exCeYcduN7KKCm91OeCJKK6OzWst0Og1DB\n",
    "kwzzU2rL3G65CrZ7H0SZsQ==\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
 * kUnknownCriticalCRL2 is kBasicCRL but with a critical issuing distribution
 * point extension followed by an unknown critical extension
 */
static const char *kUnknownCriticalCRL2[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIBzzCBuAIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n",
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n",
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoDYwNDAKBgNV\n",
    "HRQEAwIBATARBgNVHRwBAf8EBzAFoQMBAf8wEwYMKoZIhvcSBAGEtwkAAQH/BAAw\n",
    "DQYJKoZIhvcNAQELBQADggEBACTcpQC8jXL12JN5YzOcQ64ubQIe0XxRAd30p7qB\n",
    "BTXGpgqBjrjxRfLms7EBYodEXB2oXMsDq3km0vT1MfYdsDD05S+SQ9CDsq/pUfaC\n",
    "E2WNI5p8WircRnroYvbN2vkjlRbMd1+yNITohXYXCJwjEOAWOx3XIM10bwPYBv4R\n",
    "rDobuLHoMgL3yHgMHmAkP7YpkBucNqeBV8cCdeAZLuhXFWi6yfr3r/X18yWbC/r2\n",
    "2xXdkrSqXLFo7ToyP8YKTgiXpya4x6m53biEYwa2ULlas0igL6DK7wjYZX95Uy7H\n",
    "GKljn9weIYiMPV/BzGymwfv2EW0preLwtyJNJPaxbdin6Jc=\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
 * RFC 5280 states that only CRL files with the Indirect CRL flag set to True in
 * the IDP extension require the certificate_issuer extension.
 * https://github.com/openssl/openssl/issues/27465
 */

static const char *kCertIssuerNoIDPCRL[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIIDBDCCAewCAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowgf8wJQIUHIACLvgf\n",
    "JAXulqYS3LYf4KxwHl4XDTI1MDQxNzEwMTY1MVowgdUCEQCMuBk+zOZx7AAAAABY\n",
    "LIp6Fw0yNTAzMDQwMDAwMDBaMIGwMAoGA1UdFQQDCgEEMBgGA1UdGAQRGA8yMDI1\n",
    "MDMxNDAwMDAwMFowgYcGA1UdHQEB/wR9MHukeTB3MQswCQYDVQQGDAJVTjEPMA0G\n",
    "A1UECAwGTXkgU1QxMRUwEwYDVQQHDAxNWSBMb2NhbGl0eTExETAPBgNVBAoTCE15\n",
    "IFVuaXQxMREwDwYDVQQLDAhNeSBVbml0MTEaMBgGA1UEAwwRd3d3Lm15Y29tcGFu\n",
    "eS5jb22gPTA7MBgGA1UdFAQRAg8Zz//e2nTt8vakRgzO4UAwHwYDVR0jBBgwFoAU\n",
    "12GJH5OWi3ZUFunld9x8t2UbgCQwDQYJKoZIhvcNAQELBQADggEBAFOSlDm/mLRm\n",
    "YnnKJr4lZb6HzjY3KvJ/p//uIh9/OOOGBlVNF+wwrCi/JtPMY/N29DHH17l6dV9d\n",
    "hmyeg/8KScZUKxvDGyQxkd3sKrK/nahjmcLR5FGx5sqhnBUl7wzcdgObey5pAwYv\n",
    "azVKH4EkKJ5KE/a9sGgxiAXHp8anSu8xvmqjSA6M9mS1X643QvCsPDdGHWD2iHom\n",
    "0/FegR60yNqYaMERJz0jJv8SJ3Co38TlhH/Zr+N86RLYj3tPOsxcY5K1P8VZVPV/\n",
    "DxVqhesv7EaeiXDhiSTFcRXytqOQX3wju4RdxiyqMd4iT98N8nTxRdbBo4EVQKql\n",
    "PNhJBxQG0VQ=\n",
    NULL
};

/*
 * CRLs with an invalid Invalidity Date.
 * https://github.com/openssl/openssl/issues/27445
 */

static const char *kInvalidDateMM[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICwDCCAagCAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowgbswJQIUHIACLvgf\n",
    "JAXulqYS3LYf4KxwHl4XDTI1MDQxNzEwMTY1MVowSAIRAIy4GT7M5nHsAAAAAFgs\n",
    "inoXDTI1MDMwNDAwMDAwMFowJDAKBgNVHRUEAwoBADAWBgNVHRgEDxgNMjAxMTEz\n",
    "MTIyNDQ2WjBIAhEAjLgZPszmcewAAAAAWCyKehcNMjUwMzA0MDAwMDAwWjAkMAoG\n",
    "A1UdFQQDCgEEMBYGA1UdGAQPGA0yMDEyMTMxMjI1NDdaoD0wOzAYBgNVHRQEEQIP\n",
    "Gc//3tp07fL2pEYMzuFAMB8GA1UdIwQYMBaAFNdhiR+Tlot2VBbp5XfcfLdlG4Ak\n",
    "MA0GCSqGSIb3DQEBCwUAA4IBAQCXPgi5aD+9nPVYmpebHQHeyZgyj5DWf+Jhb0iT\n",
    "ljjOVLht83c59eCH2bsi+ZiGSI7d6nPdqP5PL0sX2Pp1NBEJk3LanlTXdmJbhEzV\n",
    "uTEQPgtHt2fFHVLDbFatQhTpXt+wXTahogE1oRleunG2nYzSuDBUQHKj+2VEhPxh\n",
    "ghMLkp3ZM59SJUp8MPWLLjoGtHsIYBHlw6clnq/7tmuzDYBZPerW2gMPjKuywSYj\n",
    "pcWJOYTFzeOrEW5wRHVMs0jDwaOOeJNlRHEJ19SsGTDSNPTk8n3OwTKSOaJ+Y9M0\n",
    "O2p9+7c2oIK6AnLuVNTyiBtEqMvukBkHT8PPPIpsJrzGUTj6\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kInvalidDateSS[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICdTCCAV0CAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowcTAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWjBIAhEAjLgZPszmcewAAAAAWCyK\n",
    "ehcNMjUwMzA0MDAwMDAwWjAkMAoGA1UdFQQDCgEFMBYGA1UdGAQPGA0yMDI0MDgy\n",
    "MTAwMDBaoD0wOzAYBgNVHRQEEQIPGc//3tp07fL2pEYMzuFAMB8GA1UdIwQYMBaA\n",
    "FNdhiR+Tlot2VBbp5XfcfLdlG4AkMA0GCSqGSIb3DQEBCwUAA4IBAQCl9pd3BaSn\n",
    "crbjvcjLZH0nomP8ipuez5+eTYSdb3Tpams7/70l/YrDZnR633LJLWKOTJpkP8DA\n",
    "2e9FWVY086enUy3AxAzsAEpnFeuACPLqqGAAgOGy/Ad6gIwR3CK4vcF+SfSHNvh0\n",
    "50305mFrur737C3yaC1MALqkMOPeZYIm+loKK8Q3qmk2dbt5Vj4hdi09tsti3Wl+\n",
    "SoR94psjlmzgi3/+Wf5Ubdo9LhyXjjGlx/oZm+Y55Ti30NC4HuAA7UsWLwcaD23T\n",
    "fLmUgatPdqozdGKtK0PsuxH2sfPaVnWQExkTBysZV4iQ7OvcadhShLyjwvGHT69D\n",
    "EK028LrNrWTA\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kInvalidDateUTC[] = {

    "-----BEGIN X509 CRL-----\n",
    "MIICdTCCAV0CAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowcTAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWjBIAhEAjLgZPszmcewAAAAAWCyK\n",
    "ehcNMjUwMzA0MDAwMDAwWjAkMAoGA1UdFQQDCgEEMBYGA1UdGAQPFw0yNDExMTQw\n",
    "NjQ0MDBaoD0wOzAYBgNVHRQEEQIPGc//3tp07fL2pEYMzuFAMB8GA1UdIwQYMBaA\n",
    "FNdhiR+Tlot2VBbp5XfcfLdlG4AkMA0GCSqGSIb3DQEBCwUAA4IBAQDKX5PynQJ8\n",
    "EHENKO7avhGO2z/lz/7nU76tbkGVZHgS/Vufsr/x934sRTBxkGdE8COU67FiU+Yx\n",
    "dO2yfPjHqgoxDlxXTrI71lElSCMURDY1vR/7cHhlbQlr/TXW4vLBnwAsXYx6gjV7\n",
    "nHxvTwvb6DE5VXN7CrWfQ+UpVpE/OymjDVcPBBp5mMKvac4PaNdlGU3BcRGx+6iH\n",
    "/CRNHU3fgOi37KqQ3rEZBRN1CI5JX7gFf6fCFRJNFnWez65FoHkA0L/J52y6QLdm\n",
    "KPHBluIk4UD6eeZNDAC1keYDfIsY1fDvPm4W1Hd0J5QgjKcxFXK8qRi7BPy3UZjw\n",
    "yYUQ4YV+e1Je\n",
    "-----END X509 CRL-----\n",
    NULL
};

/* https://github.com/openssl/openssl/issues/27374 */
static const char *kCrlDeltaIndicatorString[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICPzCCAScCAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowJzAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWqBRME8wGAYDVR0UBBECDxnP/97a\n",
    "dO3y9qRGDM7hQDAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDASBgNV\n",
    "HRsECwQJRzYzMjg3NTEwMA0GCSqGSIb3DQEBCwUAA4IBAQCUvLefNHqdQdJC8gbp\n",
    "QME2dQM6C8yLBjcykeNImrW0Ah1fpNTcT3XP+Gc9O5i1OIrCfQ8bDmvBNryrqZfC\n",
    "43CsQsW1YBwNIa5oWjgaRwOzqng8Q6ITYpuLDnc7n20ejft8XmgdiTFNflgGM/Hx\n",
    "p/a+xhIQAgqfgFH7ocm5DInDS5VFTHTtbPHMPiY4EUy9FnUTenkbFpVA47mswCXd\n",
    "5p1QJGrDJR/sx7lmP/W77dhIWNtbmpUUo61AqcO1JdF2RUkc1yg2UBuzkgV1WU3t\n",
    "UcQuw9IXm62Io2pRgNeiqOTz5daA1OVlDRaMNEVFvlMs0NgKDx0MGPT9p3KIzSoW\n",
    "dbXQ\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlNumberString[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICJTCCAQ0CAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowJzAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNTI4MDMwOTE4WqA3MDUwEgYDVR0UBAsECUc2MzI4\n",
    "NzUxMDAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDANBgkqhkiG9w0B\n",
    "AQsFAAOCAQEAU+jupFC7puUTELqIipJuywX2NWiA9kZIGSZM8k7gE8UZicsDy77F\n",
    "hnpyY8ATvRXTaFL/QKipowNlGUf9LsS9vo36XKBOb4mJQQRUV2MLBqMacG9/t1/t\n",
    "KBbNe+zxE9edfs+gco8K0pR/UWCjo0hKvqohEZ2S2Yl7FjSB6SuPMQA58+CkGdTM\n",
    "P9k+LlqnPFl9Csm/2XUt1Fmw9AG2K5RN2fLC1NzMG1COo6g4LX8Sj4d7WW1LQUY5\n",
    "cgd8PXFHW27u6F2c+xl5a7depdYKKDeWf01soQjjnT3e9OXZuBDM/vXBjl8T3YLF\n",
    "s2kylOJHvGL3sxwWVCpboTmSUTEbf/tbOA==\n",
    "-----END X509 CRL-----\n",
    NULL
};

/* https://github.com/openssl/openssl/issues/27251 */
static const char *kCrlIDPWrongTag[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICZzCCAU8CAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowJzAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWqB5MHcwGAYDVR0UBBECDxnP/97a\n",
    "dO3y9qRGDM7hQDAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDA6BgNV\n",
    "HRwBAf8EMDAuoCagJKQihiBodHRwOi8vbG9jYWxob3N0OjgwMDAvY2FfY3JsLmRl\n",
    "coEB/4IB/zANBgkqhkiG9w0BAQsFAAOCAQEANovDW2ry+y17K8CgjoD6C1Mwf8Je\n",
    "uJiSw4kZnbtO/+/Benl3nWumMIH9liV6BSJnWZU3staGQaUyk+qou5udzSwh0Tw/\n",
    "iGu/xygDlEBiJ/vFt0Bt6ImHCsNrd7UjNRGRJI7neeJdq6YlMOJ27JvKt9isRJIM\n",
    "KsHBuqBs8G8g6XU0TfgoHYAPxtPF9uuFmC7k0Fs7z142C9/Im8m1CqqYet/kd/Hz\n",
    "IErMxdvr1NfL7WHBIArW0BqjaR1E05ur8fPIHItVJtPV9V5UbRM1eeQiOfDCyZRJ\n",
    "x9A/quodFMH781MsLnTktHqMmbOesiDycl0OehyrfXDEXLWIOH/EvqkyIA==\n",
    "-----END X509 CRL-----\n",
    NULL
};

static const char *kCrlIDPWrongTag2[] = {
    "-----BEGIN X509 CRL-----\n",
    "MIICZzCCAU8CAQEwDQYJKoZIhvcNAQELBQAweTELMAkGA1UEBhMCVVMxEzARBgNV\n",
    "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM\n",
    "Ck15IENvbXBhbnkxEzARBgNVBAMMCk15IFJvb3QgQ0ExEzARBgNVBAsMCk15IFJv\n",
    "b3QgQ0EXDTI1MDEwMTAwMDAwMFoXDTI1MTIwMTAwMDAwMFowJzAlAhQcgAIu+B8k\n",
    "Be6WphLcth/grHAeXhcNMjUwNDE3MTAxNjUxWqB5MHcwGAYDVR0UBBECDxnP/97a\n",
    "dO3y9qRGDM7hQDAfBgNVHSMEGDAWgBTXYYkfk5aLdlQW6eV33Hy3ZRuAJDA6BgNV\n",
    "HRwBAf8EMDAuoCagJKUihiBodHRwOi8vbG9jYWxob3N0OjgwMDAvY2FfY3JsLmRl\n",
    "coEB/4IB/zANBgkqhkiG9w0BAQsFAAOCAQEAyLXs3RfVDDjTvvni2EyKRdnpODpY\n",
    "hH5Q26NtA0S6/hXUOntR3N6jrqZQNo1Eg2iL9v6IzWnHEeWs4jSzMaOdAHW+iASY\n",
    "COMIuNKY51E7dezIyY1Gjl3L9S/laGb0zPsgziAq8PFKP/FBC0uQbLmpbfvFSf0D\n",
    "bZQzB0THvc3OjixEeRQPNkEApHPqmZpvr6ysQBpvzSQJhYaVT2JfUjAGBu1B6iIO\n",
    "bwfzsFriiMUdnHp6I3mQ0LtzcxuzEDVifcE4dkl2PROsgwxiAbKXCYTDYGSTQ3Li\n",
    "4ijLXcQYIZ3ZP6xs6qiYqphBF2ICGtMpD2XUxOSMfO42S2FYs/wZ38lnHg==\n",
    "-----END X509 CRL-----\n",
    NULL
};

/*
static X509 *root1 = NULL;
static X509 *leaf1 = NULL;
static X509 *root2 = NULL;
static X509 *leaf2 = NULL;
*/

/*
 * Verify |leaf| certificate (chained up to |root|).  |crls| if
 * not NULL, is a list of CRLs to include in the verification. It is
 * also free'd before returning, which is kinda yucky but convenient.
 * Returns a value from X509_V_ERR_xxx or X509_V_OK.
 */
static int verify(X509 *leaf, X509 *root, STACK_OF(X509_CRL) *crls,
    unsigned long flags, time_t verification_time)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE *store = X509_STORE_new();
    X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
    STACK_OF(X509) *roots = sk_X509_new_null();
    int status = X509_V_ERR_UNSPECIFIED;

    if (!TEST_ptr(ctx)
        || !TEST_ptr(store)
        || !TEST_ptr(param)
        || !TEST_ptr(roots))
        goto err;

    /* Create a stack; upref the cert because we free it below. */
    if (!TEST_true(X509_up_ref(root)))
        goto err;
    if (!TEST_true(sk_X509_push(roots, root))) {
        X509_free(root);
        goto err;
    }
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;
    X509_STORE_CTX_set0_trusted_stack(ctx, roots);
    X509_STORE_CTX_set0_crls(ctx, crls);
    X509_VERIFY_PARAM_set_time(param, verification_time);
    if (!TEST_long_eq((long)X509_VERIFY_PARAM_get_time(param), (long)verification_time))
        goto err;
    X509_VERIFY_PARAM_set_depth(param, 16);
    if (flags)
        X509_VERIFY_PARAM_set_flags(param, flags);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;

    ERR_clear_error();
    status = X509_verify_cert(ctx) == 1 ? X509_V_OK
                                        : X509_STORE_CTX_get_error(ctx);
err:
    OSSL_STACK_OF_X509_free(roots);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return status;
}

/*
 * Create a stack of CRL's.  Upref each one because we call pop_free on
 * the stack and need to keep the CRL's around until the test exits.
 * Yes this crashes on malloc failure; it forces us to debug.
 */
static STACK_OF(X509_CRL) *make_CRL_stack(X509_CRL *x1, X509_CRL *x2)
{
    STACK_OF(X509_CRL) *sk = sk_X509_CRL_new_null();

    if (x1 != NULL) {
        if (!X509_CRL_up_ref(x1))
            goto err;
        if (!sk_X509_CRL_push(sk, x1)) {
            X509_CRL_free(x1);
            goto err;
        }
    }

    if (x2 != NULL) {
        if (!X509_CRL_up_ref(x2))
            goto err;
        if (!sk_X509_CRL_push(sk, x2)) {
            X509_CRL_free(x2);
            goto err;
        }
    }

    return sk;

err:
    sk_X509_CRL_pop_free(sk, X509_CRL_free);
    return NULL;
}

static int test_crl_basic(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot);
    X509 *leaf = X509_from_strings(kCRLTestLeaf);
    X509_CRL *basic_crl = CRL_from_strings(kBasicCRL);
    X509_CRL *revoked_crl = CRL_from_strings(kRevokedCRL);
    const X509_ALGOR *alg = NULL, *tbsalg;
    int test;

    test = TEST_ptr(root)
        && TEST_ptr(leaf)
        && TEST_ptr(basic_crl)
        && TEST_ptr(revoked_crl)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(basic_crl, NULL),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME),
            X509_V_OK)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(basic_crl, revoked_crl),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME),
            X509_V_ERR_CERT_REVOKED)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(basic_crl, revoked_crl),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME2),
            X509_V_ERR_CRL_HAS_EXPIRED)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(basic_crl, revoked_crl),
                           X509_V_FLAG_CRL_CHECK, 0),
            X509_V_ERR_CRL_NOT_YET_VALID);

    if (test) {
        X509_CRL_get0_signature(basic_crl, NULL, &alg);
        tbsalg = X509_CRL_get0_tbs_sigalg(basic_crl);
        test = TEST_ptr(alg)
            && TEST_ptr(tbsalg)
            && TEST_int_eq(X509_ALGOR_cmp(alg, tbsalg), 0);
    }

    X509_CRL_free(basic_crl);
    X509_CRL_free(revoked_crl);
    X509_free(leaf);
    X509_free(root);
    return test;
}

static int test_no_crl(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot);
    X509 *leaf = X509_from_strings(kCRLTestLeaf);
    int test;

    test = TEST_ptr(root)
        && TEST_ptr(leaf)
        && TEST_int_eq(verify(leaf, root, NULL,
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME),
            X509_V_ERR_UNABLE_TO_GET_CRL);

    X509_free(leaf);
    X509_free(root);
    return test;
}

static int test_crl_bad_issuer(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot);
    X509 *leaf = X509_from_strings(kCRLTestLeaf);
    X509_CRL *crl = CRL_from_strings(kBadIssuerCRL);
    int test;

    test = TEST_ptr(root)
        && TEST_ptr(leaf)
        && TEST_ptr(crl)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(crl, NULL),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME),
            X509_V_ERR_UNABLE_TO_GET_CRL);
    X509_CRL_free(crl);
    X509_free(leaf);
    X509_free(root);
    return test;
}

static int test_crl_empty_idp(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot2);
    X509 *leaf = X509_from_strings(kCRLTestLeaf2);
    X509_CRL *crl = CRL_from_strings(kEmptyIdpCRL);
    int test;

    test = TEST_ptr(root)
        && TEST_ptr(leaf)
        && TEST_ptr(crl)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(crl, NULL),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME2),
            X509_V_ERR_UNABLE_TO_GET_CRL);

    X509_CRL_free(crl);
    X509_free(leaf);
    X509_free(root);
    return test;
}

static int test_crl_critical_known(void)
{
    X509_CRL *crl = CRL_from_strings(kKnownCriticalCRL);
    int test;

    test = TEST_ptr_null(crl)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_TYPE_NOT_PRIMITIVE)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed CRL issuing distribution point");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_critical_unknown1(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot);
    X509 *leaf = X509_from_strings(kCRLTestLeaf);
    X509_CRL *crl = CRL_from_strings(kUnknownCriticalCRL);

    int test;
    test = TEST_ptr(root)
        && TEST_ptr(leaf)
        && TEST_ptr(crl)
        && TEST_int_eq(verify(leaf, root,
                           make_CRL_stack(crl, NULL),
                           X509_V_FLAG_CRL_CHECK, PARAM_TIME),
            X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION);

    X509_CRL_free(crl);
    X509_free(leaf);
    X509_free(root);
    return test;
}

static int test_crl_critical_unknown2(void)
{
    X509_CRL *crl;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kUnknownCriticalCRL2)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_TYPE_NOT_PRIMITIVE)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed CRL issuing distribution point");

    return test;
}

static int test_reuse_crl(int idx)
{
    X509_CRL *result, *reused_crl = CRL_from_strings(kBasicCRL);
    X509_CRL *addref_crl = NULL;
    char *p = NULL;
    BIO *b = NULL;
    int r = 0;

    if (!TEST_ptr(reused_crl))
        goto err;

    if (idx & 1) {
        if (!TEST_true(X509_CRL_up_ref(reused_crl)))
            goto err;
        addref_crl = reused_crl;
    }

    idx >>= 1;
    b = glue2bio(idx == 2 ? kRevokedCRL : kInvalidCRL + idx, &p);

    if (!TEST_ptr(b))
        goto err;

    result = PEM_read_bio_X509_CRL(b, &reused_crl, NULL, NULL);

    switch (idx) {
    case 0: /* valid PEM + invalid DER */
        if (!TEST_ptr_null(result)
            || !TEST_ptr_null(reused_crl))
            goto err;
        break;
    case 1: /* invalid PEM */
        if (!TEST_ptr_null(result)
            || !TEST_ptr(reused_crl))
            goto err;
        break;
    case 2:
        if (!TEST_ptr(result)
            || !TEST_ptr(reused_crl)
            || !TEST_ptr_eq(result, reused_crl))
            goto err;
        break;
    }

    r = 1;

err:
    OPENSSL_free(p);
    BIO_free(b);
    X509_CRL_free(reused_crl);
    X509_CRL_free(addref_crl);
    return r;
}

/*
 * Validation to ensure Certificate Issuer extensions in CRL entries only appear
 * when the Indirect CRL flag is TRUE in the Issuing Distribution Point (IDP)
 * extension, as required by RFC 5280 section 5.3.3.
 */

static int test_crl_cert_issuer_ext(void)
{
    X509_CRL *crl = CRL_from_strings(kCertIssuerNoIDPCRL);
    int test = TEST_ptr_null(crl);

    X509_CRL_free(crl);
    return test;
}

static int test_crl_date_invalid(void)
{
    X509_CRL *tmm = NULL, *tss = NULL, *utc = NULL;
    int test;

    test = TEST_ptr_null((tmm = CRL_from_strings(kInvalidDateMM)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_TIME_VALUE)
        && TEST_err_s("invalidityDate in CRL is not well-formed")
        && TEST_ptr_null((tss = CRL_from_strings(kInvalidDateSS)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_TIME_VALUE)
        && TEST_err_s("invalidityDate in CRL is not well-formed")
        && TEST_ptr_null((utc = CRL_from_strings(kInvalidDateUTC)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_TIME_VALUE)
        && TEST_err_s("invalidityDate in CRL is not well-formed");

    X509_CRL_free(tmm);
    X509_CRL_free(utc);
    X509_CRL_free(tss);
    return test;
}

/*
 * Test to make sure X509_verify_cert sets the issuer, reasons, and
 * CRL score of the CRLs it gets from X509_STORE_CTX->get_crl
 */

static int get_crl_fn(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x)
{
    *crl = CRL_from_strings(kBasicCRL);
    return 1;
}

static int test_crl_get_fn_score(void)
{
    X509 *root = X509_from_strings(kCRLTestRoot);
    X509 *leaf = X509_from_strings(kCRLTestLeaf);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE *store = X509_STORE_new();
    X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
    STACK_OF(X509) *roots = sk_X509_new_null();
    int status = X509_V_ERR_UNSPECIFIED;

    if (!TEST_ptr(ctx)
        || !TEST_ptr(root)
        || !TEST_ptr(leaf)
        || !TEST_ptr(store)
        || !TEST_ptr(param)
        || !TEST_ptr(roots))
        goto err;

    /* Create a stack; upref the cert because we free it below. */
    if (!TEST_true(X509_up_ref(root)))
        goto err;
    if (!TEST_true(sk_X509_push(roots, root))) {
        X509_free(root);
        root = NULL;
        goto err;
    }
    if (!TEST_true(X509_STORE_CTX_init(ctx, store, leaf, NULL)))
        goto err;

    X509_STORE_CTX_set0_trusted_stack(ctx, roots);
    X509_STORE_CTX_set_get_crl(ctx, &get_crl_fn);
    X509_VERIFY_PARAM_set_time(param, PARAM_TIME);
    if (!TEST_long_eq((long)X509_VERIFY_PARAM_get_time(param), (long)PARAM_TIME))
        goto err;
    X509_VERIFY_PARAM_set_depth(param, 16);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
    X509_STORE_CTX_set0_param(ctx, param);
    param = NULL;

    ERR_clear_error();
    status = X509_verify_cert(ctx) == 1 ? X509_V_OK
                                        : X509_STORE_CTX_get_error(ctx);

    TEST_int_eq(status, X509_V_OK);

err:
    OSSL_STACK_OF_X509_free(roots);
    X509_VERIFY_PARAM_free(param);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(root);
    X509_free(leaf);
    return status == X509_V_OK;
}

static int test_crl_delta_indicator(void)
{
    X509_CRL *crl;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlDeltaIndicatorString)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed Delta CRL Indicator");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_number(void)
{
    X509_CRL *crl;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlNumberString)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed CRL number extension");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_idp_asn1_wrong_tag(void)
{
    X509_CRL *crl;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlIDPWrongTag)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed CRL issuing distribution point");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_idp_asn1_wrong_tag2(void)
{
    X509_CRL *crl;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlIDPWrongTag2)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_WRONG_TAG)
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT)
        && TEST_err_s("CRL: malformed CRL issuing distribution point");

    X509_CRL_free(crl);
    return test;
}

/*
 * Verify that the private keys correspond to their certificates. This avoids
 * having unused variables while also ensuring the keys are valid and usable, so
 * they can serve as a basis for additional test cases in the future.
 */
static int test_private_keys(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    EVP_PKEY *root_pkey = NULL;
    EVP_PKEY *leaf_pkey = NULL;
    EVP_PKEY *root_pub = NULL;
    EVP_PKEY *leaf_pub = NULL;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr(root_pkey = EVP_PKEY_from_strings(kRootPrivateKey))
        && TEST_ptr(leaf_pkey = EVP_PKEY_from_strings(kLeafPrivateKey))
        && TEST_ptr(root_pub = X509_get_pubkey(root))
        && TEST_ptr(leaf_pub = X509_get_pubkey(leaf))
        && TEST_int_eq(EVP_PKEY_eq(root_pub, root_pkey), 1)
        && TEST_int_eq(EVP_PKEY_eq(leaf_pub, leaf_pkey), 1);

    EVP_PKEY_free(root_pkey);
    EVP_PKEY_free(leaf_pkey);
    EVP_PKEY_free(root_pub);
    EVP_PKEY_free(leaf_pub);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_idp_onlyca_onlyattr(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_UNABLE_TO_GET_CRL;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlIDPOnlyCaOnlyAttr)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_idp_onlyuser_onlyattr(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_UNABLE_TO_GET_CRL;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlIDPOnlyUserOnlyAttr)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_idp_onlyuser_onlyca(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_UNABLE_TO_GET_CRL;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlIDPOnlyUserOnlyCA)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_idp_onlyuser_onlyca_onlyattr(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_UNABLE_TO_GET_CRL;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlIDPOnlyUserOnlyCAOnlyAttr)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_idp_cert_issuer_no_indirect_flag(void)
{
    X509_CRL *crl = NULL;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlCINoIndirectFlag)))
        && TEST_err_r(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE)
        && TEST_err_s("CRL Certificate Issuer extension requires Indirect CRL flag to be set");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_revocation(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlRecovated)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), X509_V_OK);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_extension_duplicate(void)
{
    X509_CRL *crl = NULL;
    int test;

    test = TEST_ptr_null((crl = CRL_from_strings(kCrlExtensionDuplicate)))
        && TEST_err_s("CRL: malformed CRL number extension");

    X509_CRL_free(crl);
    return test;
}

static int test_crl_extension_duplicate_entry(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_CERT_REVOKED;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlExtensionDuplicateEntry)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

static int test_crl_extension_duplicate_serial(void)
{
    X509 *root = NULL;
    X509 *leaf = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls;
    unsigned int flags = X509_V_FLAG_CRL_CHECK;
    unsigned int expect = X509_V_ERR_CERT_REVOKED;
    int test;

    test = TEST_ptr(root = X509_from_strings(kRoot))
        && TEST_ptr(leaf = X509_from_strings(kLeaf))
        && TEST_ptr((crl = CRL_from_strings(kCrlExtensionDuplicateSerial)))
        && TEST_ptr((crls = make_CRL_stack(crl, NULL)))
        && TEST_int_eq(verify(leaf, root, crls, flags, kVerify), expect);

    X509_CRL_free(crl);
    X509_free(root);
    X509_free(leaf);
    return test;
}

int setup_tests(void)
{
    ADD_TEST(test_private_keys);
    ADD_TEST(test_no_crl);
    ADD_TEST(test_crl_basic);
    ADD_TEST(test_crl_bad_issuer);
    ADD_TEST(test_crl_empty_idp);
    ADD_TEST(test_crl_critical_known);
    ADD_TEST(test_crl_cert_issuer_ext);
    ADD_TEST(test_crl_date_invalid);
    ADD_TEST(test_crl_get_fn_score);
    ADD_TEST(test_crl_delta_indicator);
    ADD_TEST(test_crl_number);
    ADD_TEST(test_crl_idp_asn1_wrong_tag);
    ADD_TEST(test_crl_idp_asn1_wrong_tag2);
    ADD_TEST(test_crl_idp_onlyca_onlyattr);
    ADD_TEST(test_crl_idp_onlyuser_onlyattr);
    ADD_TEST(test_crl_idp_onlyuser_onlyca);
    ADD_TEST(test_crl_idp_onlyuser_onlyca_onlyattr);
    ADD_TEST(test_crl_idp_cert_issuer_no_indirect_flag);
    ADD_TEST(test_crl_critical_unknown1);
    ADD_TEST(test_crl_critical_unknown2);
    ADD_TEST(test_crl_revocation);
    ADD_TEST(test_crl_extension_duplicate);
    ADD_TEST(test_crl_extension_duplicate_entry);
    ADD_TEST(test_crl_extension_duplicate_serial);
    ADD_ALL_TESTS(test_reuse_crl, 6);
    return 1;
}

void cleanup_tests(void)
{
}
