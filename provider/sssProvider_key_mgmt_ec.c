/**
 * @file sssProvider_key_mgmt_ec.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for EC key management
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ECC

/* ********************** Include files ********************** */
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>
#include "sssProvider_main.h"
#include <limits.h>
#include <string.h>

/* ********************** Defines **************************** */

#define SSS_DEFAULT_EC_KEY_ID 0xEF000001
#define SE05x_MAGIC_NUM_SIZE 8
#define SECP521R1_KEY_BIT_LEN 521
#define SE05x_MAGIC_NUM                                \
    {                                                  \
        0xB6, 0xB5, 0xA6, 0xA5, 0xB6, 0xB5, 0xA6, 0xA5 \
    }

/* ********************** Private funtions ******************* */

static int sss_type_key_map_index(uint32_t cipherType, uint32_t keyBitLen)
{
    int i = 0;
    while ((sss_type_key_map[i].cipherType != 0) && (i < MAX_SSS_TYPE_KEY_MAP_ENTRIES)) {
        if ((sss_type_key_map[i].cipherType == cipherType) && (sss_type_key_map[i].keyBitLen == keyBitLen)) {
            return i;
        }
        i++;
    }
    return -1;
}

static int sss_get_key_len_cipher_type(char *curve_name, uint32_t *cipherType, uint16_t *keyBitLen)
{
    int i = 0;
    for (i = 0; i < MAX_SSS_TYPE_KEY_MAP_ENTRIES; i++) {
        if (0 == SSS_CMP_STR(sss_type_key_map[i].curve_name, curve_name)) {
            *cipherType = sss_type_key_map[i].cipherType;
            if ((sss_type_key_map[i].keyBitLen / 8U) > UINT16_MAX) {
                return -1;
            }
            *keyBitLen = sss_type_key_map[i].keyBitLen / 8U;
            return i;
        }
    }
    return -1;
}

static void *sss_ec_keymgmt_load(const void *reference, size_t reference_sz)
{
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (!reference || reference_sz != sizeof(pStoreCtx)) {
        return NULL;
    }

    pStoreCtx                               = *(sss_provider_store_obj_t **)reference;
    *(sss_provider_store_obj_t **)reference = NULL;
    return pStoreCtx;
}

static void sss_ec_keymgmt_free(void *keydata)
{
    sss_provider_store_obj_t *pStoreCtx     = (sss_provider_store_obj_t *)keydata;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx != NULL) {
        if (pStoreCtx->pEVPPkey != NULL) {
            EVP_PKEY_free(pStoreCtx->pEVPPkey);
            pStoreCtx->pEVPPkey = NULL;
        }
    }

    if (keydata != NULL) {
        OPENSSL_free(keydata);
    }
    return;
}

static int sss_ec_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    smStatus_t status                       = SM_NOT_OK;
    sss_provider_store_obj_t *pStoreCtx     = (sss_provider_store_obj_t *)keydata;
    sss_se05x_session_t *pSession           = NULL;
    OSSL_PARAM *p                           = NULL;
    int ret                                 = 0;
    int keylen_bits                         = 0;
    smStatus_t sm_status                    = SM_NOT_OK;
    uint8_t public_key[256]                 = {0};
    size_t public_key_len                   = sizeof(public_key);
    unsigned char privkey[66]               = {0}; /*max key bitLen 521 */
    int index                               = 0;
    BIGNUM *bn_priv_key                     = NULL;
    uint8_t magic_num[SE05x_MAGIC_NUM_SIZE] = SE05x_MAGIC_NUM;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    if (pStoreCtx->isFile) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        /* EVP_PKEY_size() returns the maximum suitable size for the output buffers
        for almost all operations that can be done with pkey */
        pStoreCtx->maxSize = EVP_PKEY_size(pStoreCtx->pEVPPkey);

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL && !OSSL_PARAM_set_int(p, EVP_PKEY_bits(pStoreCtx->pEVPPkey))) {
            goto cleanup;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL && !OSSL_PARAM_set_int(p, pStoreCtx->maxSize)) { /* Signature size */
            goto cleanup;
        }
        p =  OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL && !EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params)) {
            goto cleanup;
        }
    }
    else {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;

        //Get the size of the key
        status = Se05x_API_ReadSize(&(pSession->s_ctx), pStoreCtx->keyid, &(pStoreCtx->key_len));
        ENSURE_OR_GO_CLEANUP(status == SM_OK);

        keylen_bits = pStoreCtx->key_len * 8;

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            index = sss_type_key_map_index(pStoreCtx->object.cipherType, keylen_bits);
            ENSURE_OR_GO_CLEANUP(index != -1);

            if ((!OSSL_PARAM_set_utf8_string(p, sss_type_key_map[index].curve_name))) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, keylen_bits))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, (((pStoreCtx->key_len) * 2) + 8)))) { /* Signature size */
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            BIGNUM *bn_pub_key = NULL;
            sm_status =
                Se05x_API_ReadObject(&pSession->s_ctx, pStoreCtx->object.keyId, 0, 0, public_key, &public_key_len);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
            bn_pub_key   = BN_bin2bn(public_key, public_key_len, NULL);
            p->data_size = public_key_len;
            if (!OSSL_PARAM_set_BN(p, bn_pub_key)) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            ENSURE_OR_GO_CLEANUP(sizeof(privkey) >= pStoreCtx->key_len);
            ENSURE_OR_GO_CLEANUP(pStoreCtx->key_len > 0);
            privkey[pStoreCtx->key_len - 1] = 0x10;                            /* Start pattern */
            memcpy(&privkey[2], magic_num, sizeof(magic_num));                 /* Magic number */
            memcpy(&privkey[10], &pStoreCtx->keyid, sizeof(pStoreCtx->keyid)); /* Key id information */
            privkey[1] = 0x10;                                                 /* Indicate a private key */
            privkey[2] = 0x00;                                                 /* Reserved */

            bn_priv_key = BN_bin2bn(privkey, pStoreCtx->key_len, NULL);

            p->data_size = pStoreCtx->key_len;
            if (!OSSL_PARAM_set_BN(p, bn_priv_key)) {
                goto cleanup;
            }
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }

        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "SHA256"))) {
            goto cleanup;
        }

        p =  OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL && !EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params)) {
            goto cleanup;
        }
    }

    ret = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM ec_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static int sss_ec_keymgmt_set_params(void *keydata, OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx     = (sss_provider_store_obj_t *)keydata;
    OSSL_PARAM *p                           = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (params == NULL) {
        return 1;
    }

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

    p =  OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && !EVP_PKEY_set_params(pStoreCtx->pEVPPkey, params)) {
        goto cleanup;
    }
    return 1;

cleanup:
    return 0;
}

static const OSSL_PARAM *sss_ec_keymgmt_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END};

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(provctx);
    return gettable;
}

static const OSSL_PARAM *sss_ec_keymgmt_settable_params(void *provctx)
{
    return ec_settable_params;
}

static const char *sss_ec_keymgmt_query_operation_name(int operation_id)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    default:
        return NULL;
    }
}

static int sss_ec_keymgmt_has(const void *keydata, int selection)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    int ok                              = 1;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx == NULL) {
        return 0;
    }

    if (pStoreCtx->isFile) {
        if (pStoreCtx->pEVPPkey == NULL) {
            return 0;
        }

        if (EVP_PKEY_id(pStoreCtx->pEVPPkey) == EVP_PKEY_EC) {
            if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (ok) : (0);
                return ret;
            }
            else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                int ret = (pStoreCtx->isPrivateKey) ? (0) : (ok);
                return ret;
            }
            else {
                // Any other - return 0.
                return 0;
            }
        }
        else {
            // Control should not have come here.
            return 0;
        }
    }
    else {
        if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Pair ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Private) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (pStoreCtx->object.objectType == kSSS_KeyPart_Public ||
                pStoreCtx->object.objectType == kSSS_KeyPart_Pair) {
                return ok;
            }
            else {
                return 0;
            }
        }
        else {
            // Any other - return 0.
            return 0;
        }
    }
}

static int sss_ec_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    sss_provider_store_obj_t *pStoreCtx     = (sss_provider_store_obj_t *)keydata;
    OSSL_PARAM params[8]                    = {0};
    uint8_t i                               = 0;
    uint8_t public_key[256]                 = {0};
    size_t public_key_len                   = sizeof(public_key);
    unsigned char privkey[66]               = {0}; /*max key bits 521 */
    size_t private_key_len                  = sizeof(privkey);
    char group_name[32]                     = {0};
    smStatus_t sm_status                    = SM_NOT_OK;
    sss_se05x_session_t *pSession           = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;
    int keylen_bits                         = 0;
    int index                               = 0;
    uint8_t magic_num[SE05x_MAGIC_NUM_SIZE] = SE05x_MAGIC_NUM;
    OSSL_PARAM params_tmp[2]                = {
        0,
    };

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    if (pStoreCtx->isFile == 1) {
        ENSURE_OR_GO_CLEANUP(pStoreCtx->pEVPPkey != NULL);

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            params_tmp[0] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &public_key[0], sizeof(public_key));
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            public_key_len = params_tmp[0].return_size;
            params[i++]    = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, &public_key[0], public_key_len);
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            params_tmp[0] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, &group_name[0], sizeof(group_name));
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, &group_name[0], 0);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            params_tmp[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], sizeof(privkey));
            params_tmp[1] = OSSL_PARAM_construct_end();
            ENSURE_OR_GO_CLEANUP(EVP_PKEY_get_params(pStoreCtx->pEVPPkey, params_tmp) == 1);
            private_key_len = params_tmp[0].return_size;
            params[i++]     = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], private_key_len);
        }

        params[i++] = OSSL_PARAM_construct_end();
    }
    else {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            sm_status =
                Se05x_API_ReadObject(&pSession->s_ctx, pStoreCtx->object.keyId, 0, 0, public_key, &public_key_len);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
            params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, &public_key[0], public_key_len);
        }

        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            keylen_bits = pStoreCtx->key_len * 8;

            index = sss_type_key_map_index(pStoreCtx->object.cipherType, keylen_bits);
            ENSURE_OR_GO_CLEANUP(index != -1);
            params[i++] =
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, sss_type_key_map[index].curve_name, 0);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            //create reference key
            ENSURE_OR_GO_CLEANUP(sizeof(privkey) >= pStoreCtx->key_len);
            ENSURE_OR_GO_CLEANUP(pStoreCtx->key_len > 0);
            privkey[pStoreCtx->key_len - 1] = 0x10;                            /* start Pattern */
            privkey[1]                      = 0x10;                            /* Indicate Private Key */
            privkey[2]                      = 0x00;                            /* Reserved*/
            memcpy(&privkey[2], magic_num, sizeof(magic_num));                 /* Magic Number */
            memcpy(&privkey[10], &pStoreCtx->keyid, sizeof(pStoreCtx->keyid)); /* key id Information */

            if (pStoreCtx->pProvCtx->pKeyGen == NULL)
            {
                params[i++] =
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PRIV_KEY, (char*)&privkey[0], pStoreCtx->key_len);
            }
            params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, &privkey[0], pStoreCtx->key_len);

        }

        params[i++] = OSSL_PARAM_construct_end();
    }

    return param_cb(params, cbarg);
cleanup:
    return 0;
}

static const OSSL_PARAM *sss_ec_keymgmt_export_types(int selection)
{
    static OSSL_PARAM exportable_params[3] = {0};
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(selection);
    exportable_params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 0, 0);
    exportable_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0);
    exportable_params[2] = OSSL_PARAM_construct_end();
    return exportable_params;
}

static void *sss_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    sss_provider_context_t *sssProvCtx  = (sss_provider_context_t *)provctx;
    sss_provider_store_obj_t *pStoreCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);
    (void)(selection);

    if ((pStoreCtx = OPENSSL_zalloc(sizeof(sss_provider_store_obj_t))) == NULL) {
        return NULL;
    }

    pStoreCtx->isFile   = 0;
    pStoreCtx->pProvCtx = provctx;
    if (sssProvCtx->pKeyGen == NULL) {
        sssProvCtx->pKeyGen = pStoreCtx;
    }
    return pStoreCtx;
}

static int sss_keymgmt_ec_gen_set_params(void *keydata, const OSSL_PARAM params[])
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    const OSSL_PARAM *p;
    int ret           = 0;
    char grp_name[32] = {
        0,
    };
    char *pgrp_name     = &grp_name[0];
    char *grp_name_tmp  = NULL;
    char *keyId_str     = NULL;
    int index           = 0;
    long int strtol_ret = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(keydata);

    ENSURE_OR_GO_CLEANUP(params != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    ENSURE_OR_GO_CLEANUP(p != NULL);
    ENSURE_OR_GO_CLEANUP(OSSL_PARAM_get_utf8_string(p, &pgrp_name, sizeof(grp_name)));

    grp_name_tmp = OPENSSL_strdup(pgrp_name);
    ENSURE_OR_GO_CLEANUP(grp_name_tmp != NULL);

    keyId_str = strtok(grp_name_tmp, ":");
    keyId_str = strtok(NULL, ":");

    if (keyId_str == NULL) {
        sssProv_Print(LOG_DBG_ON, "No key id found. Default id will be used \n");
        pStoreCtx->keyid = SSS_DEFAULT_EC_KEY_ID;
    }
    else {
        strtol_ret = strtol(keyId_str, NULL, 0);
        if ((strtol_ret > 0) && ((uint32_t)strtol_ret < UINT32_MAX)) {
            pStoreCtx->keyid = strtol_ret;
        }
        else {
            goto cleanup;
        }
    }

    index = sss_get_key_len_cipher_type(grp_name, &pStoreCtx->object.cipherType, &pStoreCtx->key_len);
    ENSURE_OR_GO_CLEANUP(index != -1);

    ret = 1;
cleanup:

    if (grp_name_tmp != NULL) {
        OPENSSL_free(grp_name_tmp);
    }
    return ret;
}

static const OSSL_PARAM *sss_keymgmt_ec_gen_settable_params(void *keydata, void *vprovctx)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    (void)(vprovctx);
    return NULL;
}

static void *sss_keymgmt_ec_gen(void *keydata, OSSL_CALLBACK *osslcb, void *cbarg)
{
    sss_status_t status                 = kStatus_SSS_Fail;
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    uint32_t cipherType                 = 0;
    smStatus_t smStatus                 = SM_NOT_OK;
    sss_se05x_session_t *pSession       = NULL;
    SE05x_Result_t exists               = kSE05x_Result_NA;
    int keyLen                          = 0;
    sss_provider_context_t *sssProvCtx  = (sss_provider_context_t *)pStoreCtx->pProvCtx;
    sss_provider_store_obj_t *tmp       = (sss_provider_store_obj_t *)sssProvCtx->pKeyGen;
    uint8_t publicKey[521] = {0};
    size_t publicKeyLen    = sizeof(publicKey);
    size_t publicKeyBitLen = sizeof(publicKey) * 8;
    EVP_PKEY *pKey = NULL;
    BIO *bio = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(osslcb);
    (void)(cbarg);

    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);
    ENSURE_OR_GO_CLEANUP(tmp != NULL);

    cipherType = pStoreCtx->object.cipherType;

    pSession = (sss_se05x_session_t *)&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->session;

    smStatus = Se05x_API_CheckObjectExists(&(pSession->s_ctx), pStoreCtx->keyid, &exists);
    if (exists == kSE05x_Result_SUCCESS) {
        sssProv_Print(LOG_DBG_ON, "Delete key at location - 0x%X from SE05x) \n", pStoreCtx->keyid);
        smStatus = Se05x_API_DeleteSecureObject(&(pSession->s_ctx), pStoreCtx->keyid);
        ENSURE_OR_GO_CLEANUP(smStatus == SM_OK);
    }

    status = sss_key_object_init(&pStoreCtx->object, &pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    if (pStoreCtx->key_len == 66) { /* secp521r1 key bit length */
        keyLen = SECP521R1_KEY_BIT_LEN;
    }
    else {
        keyLen = pStoreCtx->key_len * 8;
    }

    status = sss_key_object_allocate_handle(
        &pStoreCtx->object, pStoreCtx->keyid, kSSS_KeyPart_Pair, cipherType, keyLen, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    sssProv_Print(LOG_FLOW_ON, "Generate ECC key inside SE05x \n");
    sssProv_Print(LOG_DBG_ON, "(At key id 0x%X from SE05x) \n", pStoreCtx->keyid);

    status = sss_key_store_generate_key(&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks, &pStoreCtx->object, keyLen, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status                 = sss_key_store_get_key(&pStoreCtx->pProvCtx->p_ex_sss_boot_ctx->ks, &pStoreCtx->object, publicKey, &publicKeyLen, &publicKeyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    bio = BIO_new_mem_buf(publicKey, (int)publicKeyLen);
    if (bio == NULL) {
        LOG_E("Unable to initialize BIO");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    pKey = d2i_PUBKEY_bio(bio, NULL);
    if (!pKey) {
        LOG_E("Failed to load public key");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    pStoreCtx->pEVPPkey = pKey;

cleanup:
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (status == kStatus_SSS_Fail) {
        return NULL;
    }
    return keydata;
}

static void sss_keymgmt_gen_cleanup(void *keydata)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(keydata);
    return;
}

static int sss_ec_keymgmt_gen_set_template(void *genctx, void *keydata)
{
    sss_provider_store_obj_t *pStoreCtx = (sss_provider_store_obj_t *)keydata;
    sss_provider_store_obj_t *gStoreCtx = (sss_provider_store_obj_t *)genctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    gStoreCtx->object       = pStoreCtx->object;
    gStoreCtx->keyid        = pStoreCtx->keyid;
    gStoreCtx->key_len      = pStoreCtx->key_len;
    genctx                  = gStoreCtx;

    return 1;
}

const OSSL_DISPATCH sss_ec_keymgmt_functions[] = {{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sss_ec_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sss_ec_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sss_ec_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))sss_ec_keymgmt_gen_set_template},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))sss_ec_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))sss_ec_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))sss_ec_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))sss_ec_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sss_ec_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sss_ec_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))sss_ec_keymgmt_export_types},
    /* To generate the key in SE */
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sss_ec_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))sss_keymgmt_ec_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))sss_keymgmt_ec_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sss_keymgmt_ec_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))sss_keymgmt_gen_cleanup},
    {0, NULL}};

#endif //#if SSS_HAVE_ECC
