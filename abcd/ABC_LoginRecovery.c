/**
 * @file
 * Password-based login logic.
 */

#include "ABC_LoginRecovery.h"
#include "ABC_Login.h"
#include "ABC_LoginDir.h"
#include "ABC_LoginServer.h"

/**
 * Obtains the recovery questions for a user.
 *
 * @param pszRecoveryQuestions The returned questions. The caller frees this.
 */
tABC_CC ABC_LoginGetRQ(const char *szUserName,
                       char **pszRecoveryQuestions,
                       tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;

    tABC_Login *pSelf = NULL;
    tABC_CarePackage *pCarePackage = NULL;
    tABC_U08Buf L1 = ABC_BUF_NULL;
    tABC_U08Buf L4 = ABC_BUF_NULL;
    tABC_U08Buf RQ = ABC_BUF_NULL;

    // This is the easiest way to get L1:
    ABC_CHECK_RET(ABC_LoginNew(&pSelf, szUserName, pError));

    // Load CarePackage:
    ABC_CHECK_RET(ABC_LoginServerGetCarePackage(pSelf->L1, &pCarePackage, pError));

    // Verify that the questions exist:
    ABC_CHECK_ASSERT(pCarePackage->ERQ, ABC_CC_NoRecoveryQuestions, "No recovery questions");

    // Create L4:
    tABC_U08Buf L = ABC_BUF_NULL;
    ABC_BUF_SET_PTR(L, (unsigned char *)szUserName, strlen(szUserName));
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(L, pCarePackage->pSNRP4, &L4, pError));

    // Decrypt:
    ABC_CryptoDecryptJSONObject(pCarePackage->ERQ, L4, &RQ, pError);
    ABC_STRDUP(*pszRecoveryQuestions, (char *)ABC_BUF_PTR(RQ));

exit:
    ABC_LoginFree(pSelf);
    ABC_CarePackageFree(pCarePackage);
    ABC_BUF_FREE(L1);
    ABC_BUF_FREE(L4);
    ABC_BUF_FREE(RQ);

    return cc;
}

/**
 * Loads an existing login object, either from the server or from disk.
 * Uses recovery answers rather than a password.
 *
 * @param ppSelf        The returned login object.
 */
tABC_CC ABC_LoginRecovery(tABC_Login **ppSelf,
                          const char *szUserName,
                          const char *szRecoveryAnswers,
                          tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;

    tABC_Login          *pSelf          = NULL;
    tABC_CarePackage    *pCarePackage   = NULL;
    tABC_LoginPackage   *pLoginPackage  = NULL;
    tABC_U08Buf         LRA             = ABC_BUF_NULL;
    tABC_U08Buf         LP1             = ABC_BUF_NULL;
    tABC_U08Buf         LRA1            = ABC_BUF_NULL;
    tABC_U08Buf         LRA3            = ABC_BUF_NULL;

    // Allocate self:
    ABC_CHECK_RET(ABC_LoginNew(&pSelf, szUserName, pError));

    // Get the CarePackage:
    ABC_CHECK_RET(ABC_LoginServerGetCarePackage(pSelf->L1, &pCarePackage, pError));

    // LRA = L + RA:
    ABC_BUF_STRCAT(LRA, pSelf->szUserName, szRecoveryAnswers);

    // Get the LoginPackage:
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(LRA, pCarePackage->pSNRP1, &LRA1, pError));
    ABC_CHECK_RET(ABC_LoginServerGetLoginPackage(pSelf->L1, LP1, LRA1, &pLoginPackage, pError));

    // Decrypt MK:
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(LRA, pCarePackage->pSNRP3, &LRA3, pError));
    ABC_CHECK_RET(ABC_CryptoDecryptJSONObject(pLoginPackage->EMK_LRA3, LRA3, &pSelf->MK, pError));

    // Decrypt SyncKey:
    ABC_CHECK_RET(ABC_LoginPackageGetSyncKey(pLoginPackage, pSelf->MK, &pSelf->szSyncKey, pError));

    // Set up the on-disk login:
    ABC_CHECK_RET(ABC_LoginDirCreate(&pSelf->AccountNum, pSelf->szUserName, pError));
    ABC_CHECK_RET(ABC_LoginDirSavePackages(pSelf->AccountNum, pCarePackage, pLoginPackage, pError));

    // Assign the final output:
    *ppSelf = pSelf;
    pSelf = NULL;

exit:
    ABC_LoginFree(pSelf);
    ABC_CarePackageFree(pCarePackage);
    ABC_LoginPackageFree(pLoginPackage);
    ABC_BUF_FREE(LRA);
    ABC_BUF_FREE(LRA1);
    ABC_BUF_FREE(LRA3);

    return cc;
}

/**
 * Changes the recovery questions and answers on an existing login object.
 * @param pSelf         An already-loaded login object.
 */
tABC_CC ABC_LoginRecoverySet(tABC_Login *pSelf,
                             const char *szRecoveryQuestions,
                             const char *szRecoveryAnswers,
                             tABC_Error *pError)
{
    tABC_CC cc = ABC_CC_Ok;

    tABC_CarePackage *pCarePackage = NULL;
    tABC_LoginPackage *pLoginPackage = NULL;
    tABC_U08Buf oldL1       = ABC_BUF_NULL;
    tABC_U08Buf oldLP1      = ABC_BUF_NULL;
    tABC_U08Buf L4          = ABC_BUF_NULL;
    tABC_U08Buf RQ          = ABC_BUF_NULL;
    tABC_U08Buf LRA         = ABC_BUF_NULL;
    tABC_U08Buf LRA1        = ABC_BUF_NULL;
    tABC_U08Buf LRA3        = ABC_BUF_NULL;

    // Load the packages:
    ABC_CHECK_RET(ABC_LoginDirLoadPackages(pSelf->AccountNum, &pCarePackage, &pLoginPackage, pError));

    // Load the old keys:
    ABC_CHECK_RET(ABC_LoginGetServerKeys(pSelf, &oldL1, &oldLP1, pError));

    // Update scrypt parameters:
    ABC_CryptoFreeSNRP(&pCarePackage->pSNRP3);
    ABC_CryptoFreeSNRP(&pCarePackage->pSNRP4);
    ABC_CHECK_RET(ABC_CryptoCreateSNRPForClient(&pCarePackage->pSNRP3, pError));
    ABC_CHECK_RET(ABC_CryptoCreateSNRPForClient(&pCarePackage->pSNRP4, pError));

    // L4  = Scrypt(L, SNRP4):
    tABC_U08Buf L = ABC_BUF_NULL;
    ABC_BUF_SET_PTR(L, (unsigned char *)pSelf->szUserName, strlen(pSelf->szUserName));
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(L, pCarePackage->pSNRP4, &L4, pError));

    // Update ERQ:
    if (pCarePackage->ERQ) json_decref(pCarePackage->ERQ);
    ABC_BUF_DUP_PTR(RQ, (unsigned char *)szRecoveryQuestions, strlen(szRecoveryQuestions) + 1);
    ABC_CHECK_RET(ABC_CryptoEncryptJSONObject(RQ, L4,
        ABC_CryptoType_AES256, &pCarePackage->ERQ, pError));

    // LRA = L + RA:
    ABC_BUF_STRCAT(LRA, pSelf->szUserName, szRecoveryAnswers);

    // Update EMK_LRA3:
    if (pLoginPackage->EMK_LRA3) json_decref(pLoginPackage->EMK_LRA3);
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(LRA, pCarePackage->pSNRP3, &LRA3, pError));
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(LRA, pCarePackage->pSNRP3, &LRA3, pError));
    ABC_CHECK_RET(ABC_CryptoEncryptJSONObject(pSelf->MK, LRA3,
        ABC_CryptoType_AES256, &pLoginPackage->EMK_LRA3, pError));

    // Update ELRA1:
    if (pLoginPackage->ELRA1) json_decref(pLoginPackage->ELRA1);
    ABC_CHECK_RET(ABC_CryptoScryptSNRP(LRA, pCarePackage->pSNRP1, &LRA1, pError));
    ABC_CHECK_RET(ABC_CryptoEncryptJSONObject(LRA1, pSelf->MK,
        ABC_CryptoType_AES256, &pLoginPackage->ELRA1, pError));

    // Change the server login:
    ABC_CHECK_RET(ABC_LoginServerChangePassword(oldL1, oldLP1,
        oldLP1, LRA1, pCarePackage, pLoginPackage, pError));

    // Change the on-disk login:
    ABC_CHECK_RET(ABC_LoginDirSavePackages(pSelf->AccountNum, pCarePackage, pLoginPackage, pError));

exit:
    ABC_CarePackageFree(pCarePackage);
    ABC_LoginPackageFree(pLoginPackage);
    ABC_BUF_FREE(oldL1);
    ABC_BUF_FREE(oldLP1);
    ABC_BUF_FREE(L4);
    ABC_BUF_FREE(RQ);
    ABC_BUF_FREE(LRA);
    ABC_BUF_FREE(LRA1);
    ABC_BUF_FREE(LRA3);

    return cc;
}
