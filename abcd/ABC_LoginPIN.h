/**
 * @file
 * PIN-based re-login logic.
 */

#ifndef ABC_LoginPin_h
#define ABC_LoginPin_h

#include "ABC.h"
#include "ABC_Login.h"

#ifdef __cplusplus
extern "C" {
#endif

    tABC_CC ABC_LoginPinExists(const char *szUserName,
                               bool *pbExists,
                               tABC_Error *pError);

    tABC_CC ABC_LoginPin(tABC_Login **ppSelf,
                         const char *szUserName,
                         const char *szPIN,
                         tABC_Error *pError);

    tABC_CC ABC_LoginPinSetup(tABC_Login *pSelf,
                              const char *szPIN,
                              tABC_Error *pError);

#ifdef __cplusplus
}
#endif

#endif
