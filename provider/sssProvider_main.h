/**
 * @file sssProvider_main.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef SSS_PROVIDER_MAIN_H
#define SSS_PROVIDER_MAIN_H

/* ********************** Include files ********************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include <limits.h>
/* Openssl includes */
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
/* PnT includes */
#include <fsl_sss_api.h>
#include <se05x_APDU.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include "ex_sss_boot.h"

/* ********************** Constants ************************** */
/* Debug macros */
#define LOG_FLOW_MASK 0x01
#define LOG_DBG_MASK 0x02
#define LOG_ERR_MASK 0x04

#define LOG_FLOW_ON 0x01
#define LOG_DBG_ON 0x02
#define LOG_ERR_ON 0x04

// Signature to indicate that the RSA/ECC key is a reference to a key stored in the Secure Element
#define SIGNATURE_REFKEY_ID 0xA5A6B5B6

typedef struct sss_type_key_mapping_st
{
    uint32_t cipherType;
    uint32_t keyBitLen;
    char *curve_name;
} SSS_TYPE_KEY_MAP_ST;

#define MAX_SSS_TYPE_KEY_MAP_ENTRIES 32
static const SSS_TYPE_KEY_MAP_ST sss_type_key_map[MAX_SSS_TYPE_KEY_MAP_ENTRIES] = {
    {kSSS_CipherType_EC_NIST_P, 192, "prime192v1"},
    {kSSS_CipherType_EC_NIST_P, 224, "secp224r1"},
    {kSSS_CipherType_EC_NIST_P, 256, "prime256v1"},
    {kSSS_CipherType_EC_NIST_P, 384, "secp384r1"},
    {kSSS_CipherType_EC_NIST_P, 528, "secp521r1"},

    {kSSS_CipherType_EC_NIST_K, 160, "secp160k1"},
    {kSSS_CipherType_EC_NIST_K, 192, "secp192k1"},
    {kSSS_CipherType_EC_NIST_K, 224, "secp224k1"},
    {kSSS_CipherType_EC_NIST_K, 256, "secp256k1"},

    {kSSS_CipherType_EC_BRAINPOOL, 160, "brainpoolP160r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 192, "brainpoolP192r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 224, "brainpoolP224r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 256, "brainpoolP256r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 320, "brainpoolP320r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 384, "brainpoolP384r1"},
    {kSSS_CipherType_EC_BRAINPOOL, 512, "brainpoolP512r1"},

    {kSSS_CipherType_RSA, 1024, "rsa1024"},
    {kSSS_CipherType_RSA, 2048, "rsa2048"},
    {kSSS_CipherType_RSA, 3072, "rsa3072"},
    {kSSS_CipherType_RSA, 4096, "rsa4096"},

    /* This has to be the last */
    {0, 0, ""},
};

/* Algorith identifiers */

/* clang-format off */
#define AID_ECDSA_WITH_SHA256 \
{ \
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 \
}
/* clang-format on */

/* ********************** structure definition *************** */

typedef struct
{
    const OSSL_CORE_HANDLE *core;
    ex_sss_boot_ctx_t *p_ex_sss_boot_ctx;
    void *pKeyGen;
} sss_provider_context_t;

typedef struct
{
    uint32_t keyid;
    uint16_t key_len;
    int maxSize;
    sss_object_t object;
    bool isFile;
    FILE *pFile;
    EVP_PKEY *pEVPPkey;
    sss_provider_context_t *pProvCtx;
    bool isPrivateKey;
    /* For rsa key gen */
    int primes;
    BIGNUM *rsa_e;
} sss_provider_store_obj_t;

/* ********************** Function Prototypes **************** */

void sssProv_Print(int flag, const char *format, ...);

int SSS_CMP_STR(const char *s1, const char *s2);

#endif /* SSS_PROVIDER_H */