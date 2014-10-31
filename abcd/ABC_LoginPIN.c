/**
 * @file
 * PIN-based re-login logic.
 */

#include "ABC_LoginPin.h"
#include "ABC_Login.h"
#include "ABC_LoginDir.h"
#include "ABC_LoginServer.h"

#define PIN_FILENAME                            "PinPackage.json"

/**
 * Determines whether or not the given user can log in via PIN on this
 * device.
 */
tABC_CC ABC_LoginPinExists(const char *szUserName,
                           bool *pbExists,
                           tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;
    char *szFixed = NULL;
    int AccountNum;

    ABC_CHECK_RET(ABC_LoginFixUserName(szUserName, &szFixed, pError));
    ABC_CHECK_RET(ABC_LoginDirGetNumber(szFixed, &AccountNum, pError));
    ABC_CHECK_RET(ABC_LoginDirFileExists(pbExists, AccountNum, PIN_FILENAME, pError));

exit:
    return cc;
}

/**
 * Assuming a PIN-based login pagage exits, log the user in.
 */
tABC_CC ABC_LoginPin(tABC_Login **ppSelf,
                     const char *szUserName,
                     const char *szPIN,
                     tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;

    tABC_Login          *pSelf          = NULL;
    tABC_CarePackage    *pCarePackage   = NULL;
    tABC_LoginPackage   *pLoginPackage  = NULL;
    tABC_U08Buf         LP2             = ABC_BUF_NULL;

    // Allocate self:
    ABC_CHECK_RET(ABC_LoginNew(&pSelf, szUserName, pError));

    // Load the packages:
    ABC_CHECK_RET(ABC_LoginDirLoadPackages(pSelf->AccountNum, &pCarePackage, &pLoginPackage, pError));

#if 0
    // Load the PIN package:

    // Send the PIN to the server:

    // Decrypt MK:
    ABC_CHECK_RET(ABC_CryptoDecryptJSONObject(pPinPackage->EMK, LP2, &pSelf->MK, pError));
#endif

    // Decrypt SyncKey:
    ABC_CHECK_RET(ABC_LoginPackageGetSyncKey(pLoginPackage, pSelf->MK, &pSelf->szSyncKey, pError));

    // Assign the final output:
    *ppSelf = pSelf;
    pSelf = NULL;

exit:
    ABC_LoginFree(pSelf);
    ABC_CarePackageFree(pCarePackage);
    ABC_LoginPackageFree(pLoginPackage);
    ABC_BUF_FREE(LP2);

    return cc;
}

/**
 * Sets up a PIN login package, both on-disk and on the server.
 */
tABC_CC ABC_LoginPinSetup(tABC_Login *pSelf,
                          const char *szPIN,
                          tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;

exit:
    return cc;
}
