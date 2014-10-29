#include "common.h"
#include "ABC_LoginPassword.h"
#include "ABC_LoginServer.h"
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    tABC_CC cc;
    tABC_Error error;
    unsigned char seed[] = {1, 2, 3};
    tABC_Login *pLogin   = NULL;
    tABC_SyncKeys *pKeys = NULL;
    tABC_U08Buf L1       = ABC_BUF_NULL;
    tABC_U08Buf LP1      = ABC_BUF_NULL;
    const char *szPin = "3060";
    char *szPinPackage = NULL;

    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <dir> <user> <pass>\n", argv[0]);
        return 1;
    }
    MAIN_CHECK(ABC_Initialize(argv[1], CA_CERT, seed, sizeof(seed), &error));

    MAIN_CHECK(ABC_LoginPassword(&pLogin, argv[2], argv[3], &error));
    MAIN_CHECK(ABC_LoginGetSyncKeys(pLogin, &pKeys, &error));
    MAIN_CHECK(ABC_LoginGetServerKeys(pLogin, &L1, &LP1, &error));

    tABC_U08Buf LPIN1;
    ABC_BUF_SET_PTR(LPIN1, (unsigned char *)szPin, strlen(szPin));

    time_t expires = time(NULL);
    expires += 60 * 5; // Added 5 minutes

    MAIN_CHECK(ABC_LoginServerUpdatePinPackage(
                L1, LP1, L1/*DID*/, LPIN1, "pin_package",
                expires, &error));
    MAIN_CHECK(ABC_LoginServerGetPinPackage(L1, LPIN1, &szPinPackage, &error));
    printf("%s\n", szPinPackage);

    if (pKeys)          ABC_SyncFreeKeys(pKeys);
    ABC_BUF_FREE(L1);
    ABC_BUF_FREE(LP1);
    ABC_FREE_STR(szPinPackage);

    return 0;
}
