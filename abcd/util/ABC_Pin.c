#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "ABC_Pin.h"
#include "ABC.h"
#include "ABC_Util.h"

/* Certificate Pinning
 * Code based off the openssl example at:
 * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
 */

#define PIN_ASSERT(assert, err, desc) \
    { \
        if (!(assert)) \
        { \
            ok = 1; \
            ABC_LOG_ERROR(err, desc); \
            goto exit; \
        } \
    } \

/* PubKey for app.auth.airbitz.co */
const char *AUTH_PUB_KEY =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3a+bHSWReaTsxDj6/5BN\n"
    "ulBWlFRDBBWots7tsba0X7uekvY36CqwOUqrfj3gOUySyTRDvhQts7G+WF8qu0VS\n"
    "eTJGUG/yvpvrRZPRo4fXwtsqzYfeivi46cjZElAgsp1fx459FCvBnAgOJvqxuIEr\n"
    "QADnLs9QHE66a5ssI/KYMu1w05IwR1qJuZcnjBuq6D+a1svMUF6Rp2ygymmoSbko\n"
    "mEYFmVDdReLMvmUHBqjVMSd+ZeOsOZPrQhpW/aMO8MfKycia6bAO1IGd99bwCkon\n"
    "UUtDMYaZxC4tM9ir27gQ7lE2A0Da6MuXr4ovF6iLvGoMUJgbdontqfsJzWTXz4fh\n"
    "VwIDAQAB";

const char *CA_CERTIFICATE =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDuzCCAqOgAwIBAgIJAPMXB5xlUjQSMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTYW4gRGllZ28x\n"
    "FDASBgNVBAoMC0FpcmJpdHogSW5jMSYwJAYDVQQDDB1BaXJiaXR6IENlcnRpZmlj\n"
    "YXRlIEF1dGhvcml0eTAeFw0xNDA3MzAwMDUwNTJaFw0xNzA1MTkwMDUwNTJaMHQx\n"
    "CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTYW4g\n"
    "RGllZ28xFDASBgNVBAoMC0FpcmJpdHogSW5jMSYwJAYDVQQDDB1BaXJiaXR6IENl\n"
    "cnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
    "ggEBAKpSTCS4GAaTmBz1HBLZVwSBQ4M3Y0czgH8jbweGyitqFOhhA/yro2t2bgXY\n"
    "NsNZneM/nDwXcjiosU5ZRoupgf2kRNpfeTjfZtDkBtCE7BPxlFZBo6tZDxCZJlTQ\n"
    "BzBCzPOsukseEYZYGgW1MAKOUzLWg5NNXObr2iDZeA81hnjiGa/a1aPzekeahndC\n"
    "dGlQG6ytfpU/75ucN7f3GRWUHMTHkptj9VHRyZQl+p4Ju39e+pt9wZMpEGXABtDm\n"
    "8BSTSKLBH875pegwenE6rEsTvyKz4F62H9KPc9hPGzestz7eS00L99dFKtw9BYq9\n"
    "xro6VRwTULvaIAMaDvuxfydSejcCAwEAAaNQME4wHQYDVR0OBBYEFBOiP5bbSlRX\n"
    "DkltoA+CHDp1m0rIMB8GA1UdIwQYMBaAFBOiP5bbSlRXDkltoA+CHDp1m0rIMAwG\n"
    "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFHRv1yPh2ORlqe57zvGT6wx\n"
    "OtAeYnu1rvo+4k7V8zkVCb9A3tEboDeC0h71/S+4Cq2Vr6h6QtMFmfNNFbVMIro6\n"
    "FzeDJ27xyLcMqIY6x1GQiBBzzMhDDdK4MotNNrc/McPt4be8I1b1wVdmDEvonfEj\n"
    "UMKK8XHiwIVZJIKlyCMNWDvlRhdgenfocZJQmwwrfpTdMOdP/kaDRUNQcLGsU+wz\n"
    "TtGMn/1UeGxijct0sQpQ9PCHRc1+8kETDTMKAB/F1zBUvMCivtMYZ+j3bnq7llVh\n"
    "FRphU1/lkdwUh7+d9balfXUHn9Jk7T67mhwvJUDo7FY6FScsZ4wZB2HPmbjhdGw=\n"
    "-----END CERTIFICATE-----\n";

const char *AUTH_CERTIFICATE =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWDCCAkACCQDakf2Qe9pwfDANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJV\n"
    "UzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU2FuIERpZWdvMRQwEgYD\n"
    "VQQKDAtBaXJiaXR6IEluYzEmMCQGA1UEAwwdQWlyYml0eiBDZXJ0aWZpY2F0ZSBB\n"
    "dXRob3JpdHkwHhcNMTQwOTEwMTUzMTIwWhcNMTYwMTIzMTUzMTIwWjBoMQswCQYD\n"
    "VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU2FuIERpZWdv\n"
    "MRQwEgYDVQQKDAtBaXJiaXR6IEluYzEaMBgGA1UEAwwRKi5hdXRoLmFpcmJpdHou\n"
    "Y28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdr5sdJZF5pOzEOPr/\n"
    "kE26UFaUVEMEFai2zu2xtrRfu56S9jfoKrA5Sqt+PeA5TJLJNEO+FC2zsb5YXyq7\n"
    "RVJ5MkZQb/K+m+tFk9Gjh9fC2yrNh96K+LjpyNkSUCCynV/Hjn0UK8GcCA4m+rG4\n"
    "gStAAOcuz1AcTrprmywj8pgy7XDTkjBHWom5lyeMG6roP5rWy8xQXpGnbKDKaahJ\n"
    "uSiYRgWZUN1F4sy+ZQcGqNUxJ35l46w5k+tCGlb9ow7wx8rJyJrpsA7UgZ331vAK\n"
    "SidRS0MxhpnELi0z2KvbuBDuUTYDQNroy5evii8XqIu8agxQmBt2ie2p+wnNZNfP\n"
    "h+FXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABRd3m6ZhutEt/FzLlQHFHX+Wo0Y\n"
    "ny7YEXzTWkK2gTOScDJ8Ej6ukJzRgGCeTon1QRuzDxnx6EUx6hJUkuIQmv+6X+26\n"
    "KzBkAIEC9el0mR/NEaCrc4TYeiaDs00DVoq928cjXHIEXRX/Rbi7pEEiFLZAXW/U\n"
    "x+9J64cv+9aLZ01iljYhdMm5Kj0v7l5RrzG8FmjamayoqPQh7O498SQOQCYtmqEX\n"
    "3u0tuFme7mX8bMWfMXiaLyxf+Ra6Ynl/I8GzFAy4aOz8m9guY33012V/gC0i7/d9\n"
    "AEhCYWQ4tLZOTiJI3YTG9i5jhbzfwWVVLS8g3LXfyq71V3AzjAb6amhUZ4Y=\n"
    "-----END CERTIFICATE-----\n";


static char *ABC_PinSSLBase64(const unsigned char *input, int length);

int ABC_PinCertCallback(int pok, X509_STORE_CTX *ctx)
{
    int ok = pok;

    X509 *cert = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr = NULL;
    char *szDer = NULL;

    PIN_ASSERT((cert = ctx->current_cert) != NULL,
        ABC_CC_Error, "Unable to retrieve certificate");
    PIN_ASSERT((b64 = BIO_new(BIO_s_mem())) != NULL,
        ABC_CC_Error, "Unable to alloc BIO");
    PIN_ASSERT(1 == PEM_write_bio_X509(b64, cert),
        ABC_CC_Error, "Unable to write bio");

    BIO_get_mem_ptr(b64, &bptr);

    PIN_ASSERT(NULL != (szDer = malloc(bptr->length + 1)),
        ABC_CC_Error, "Unable to malloc");
    PIN_ASSERT(0 < BIO_read(b64, szDer, bptr->length),
        ABC_CC_Error, "Unable to read into bio to char *");

    PIN_ASSERT(strncmp(szDer, AUTH_CERTIFICATE, strlen(AUTH_CERTIFICATE)) == 0
        || strncmp(szDer, CA_CERTIFICATE, strlen(CA_CERTIFICATE)) == 0,
        ABC_CC_Error, "Pinned certificate mismatch");
exit:
    ABC_FREE(szDer);
    if (b64)
        BIO_free(b64);
    return ok;
}

int ABC_PinPubkeyCallback(int pok, X509_STORE_CTX *ctx)
{
    int ok = pok;

    char buf[256];
    X509 *cert;
    X509_PUBKEY *pkey;
    int len1 = 0, len2 = 0;
    unsigned char *szDer = NULL;
    char *szEncoded = NULL;

    PIN_ASSERT((cert = ctx->current_cert) != NULL,
        ABC_CC_Error, "Unable to retrieve certificate");

    /* These are just for debugging, they can come when this works */
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
    ABC_DebugLog("%s\n", buf);

    X509_NAME_oneline(X509_get_issuer_name(cert), buf, 256);
    ABC_DebugLog("issuer= %s\n", buf);

    // Extract pubkey in der format from the certificate
    // https://www.openssl.org/docs/crypto/d2i_X509.html
    pkey = X509_get_X509_PUBKEY(cert);
    len1 = i2d_X509_PUBKEY(pkey, NULL);
    szDer = OPENSSL_malloc(len1);
    PIN_ASSERT(szDer != NULL, ABC_CC_Error, "Unable to OPENSSL_malloc");
    // XXX: this is causing issues. something is corrupting szDer!!!
    len2 = i2d_X509_PUBKEY(pkey, &szDer);

    // make sure lengths match
    PIN_ASSERT(len1 == len2, ABC_CC_Error, "Problem when fetching the pubkey.");

    // encode it to compare against AUTH_PUB_KEY
    PIN_ASSERT((szEncoded = ABC_PinSSLBase64(szDer, len1)) != NULL,
        ABC_CC_Error, "Unable to encode certificate");

    // Debug, base64 szEncoded it should look like AUTH_PUB_KEY
    PIN_ASSERT(strlen(szEncoded) == strlen(AUTH_PUB_KEY),
        ABC_CC_Error, "Encoded keys length do not match");

    ABC_DebugLog("Pub Key Encoded: %s\n", szEncoded);

    PIN_ASSERT(strncmp(AUTH_PUB_KEY, szEncoded, len1) != 0,
        ABC_CC_Error, "Public key mismatch");
exit:
    if (szEncoded)
        ABC_FREE_STR(szEncoded);
    if (szDer)
        OPENSSL_free(szDer);
    return ok;
}

static
char *ABC_PinSSLBase64(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *) malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length - 1);
    buff[bptr->length - 1] = 0;

    BIO_free_all(b64);

    return buff;
}
