#include "common.h"
#include <stdio.h>

#include "util/ABC_Util.h"

int main(int argc, char *argv[])
{
    tABC_CC cc;
    tABC_Error error;
    unsigned char seed[] = {1, 2, 3};

    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <dir> <user> <pass>\n", argv[0]);
        return 1;
    }

    MAIN_CHECK(ABC_Initialize(argv[1], CA_CERT, seed, sizeof(seed), &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3],
                                CURRENCY_NUM_USD, NULL, NULL, &error));

    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_AUD, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_CAD, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_CNY, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_CUP, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_HKD, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_MXN, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_NZD, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_PHP, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_GBP, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_USD, NULL, NULL, &error));
    MAIN_CHECK(ABC_RequestExchangeRateUpdate(argv[2], argv[3], CURRENCY_NUM_EUR, NULL, NULL, &error));

    return 0;
}
