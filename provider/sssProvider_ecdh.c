/**
 * @file sssProvider_ecdh.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022,2024,2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for ECDH using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_ECC

/* ********************** Include files ********************** */
#include "sssProvider_main.h"
#include <string.h>
#include <openssl/kdf.h>

/* ********************** structure definition *************** */
typedef struct
{
    EVP_PKEY *pPeerEVPPkey;
    sss_provider_store_obj_t *pStoreObjCtx; // Host key object
    sss_provider_context_t *pProvCtx;
    int useX963KDF;
    EVP_MD *kdfMd;
    unsigned long kdfOutLen;
    unsigned char *kdfUkm;
    unsigned long kdfUkmLen;
} sss_provider_ecdh_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_ecdh_keyexch_newctx(void *provctx)
{
    sss_provider_ecdh_ctx_st *pEcdhCtx = OPENSSL_zalloc(sizeof(sss_provider_ecdh_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pEcdhCtx != NULL) {
        pEcdhCtx->pProvCtx = provctx;
    }
    return pEcdhCtx;
}

static void sss_ecdh_keyexch_freectx(void *ctx)
{
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (pEcdhctx != NULL) {
        if (pEcdhctx->pPeerEVPPkey != NULL) {
            EVP_PKEY_free(pEcdhctx->pPeerEVPPkey);
            pEcdhctx->pPeerEVPPkey = NULL;
        }
        OPENSSL_clear_free(pEcdhctx, sizeof(sss_provider_ecdh_ctx_st));
    }
    return;
}

static int sss_ecdh_keyexch_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                             = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(params);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pStoreObjCtx = pStoreCtx;
    ret                    = 1;
cleanup:
    return ret;
}

static int sss_ecdh_keyexch_set_peer(void *ctx, void *provkey)
{
    int ret                             = 0;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sss_provider_ecdh_ctx_st *pEcdhctx  = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL && pStoreCtx != NULL);
    pEcdhctx->pPeerEVPPkey = EVP_PKEY_dup(pStoreCtx->pEVPPkey);
    ret                    = 1;
cleanup:
    return ret;
}

static const OSSL_PARAM *sss_ecdh_keyexch_settable_ctx_params(void *ctx, void *provctx)
{
    static OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static int sss_ecdh_keyexch_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    sss_provider_ecdh_ctx_st * pEcdhctx = ctx;
    if (ctx == NULL) {
        return 0;
    }
    for (const OSSL_PARAM* p = params; p->key; ++p) {
        int ret;

        if (strcmp(p->key, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE) == 0) {
            int mod;

            ret = OSSL_PARAM_get_int(p, &mod);
            if (ret != 1) {
                return ret;
            }
            if (mod != 0) {
                sssProv_Print(LOG_DBG_ON, "enable EC_ECDH_COFACTOR_MODE is not supported.\n");
                return 0;
            }
        } else if (strcmp(p->key, OSSL_EXCHANGE_PARAM_KDF_TYPE) == 0) {
            const char *name = NULL;

            ret = OSSL_PARAM_get_utf8_string_ptr(p, &name);
            if (ret != 1) {
                return ret;
            }
            if (name[0] == '\0') {
                sssProv_Print(LOG_DBG_ON, "KDF_TYPE is NULL.\n");
            } else if (strcmp(name, "X963KDF") == 0) {
                pEcdhctx->useX963KDF = 1;
            } else {
                sssProv_Print(LOG_DBG_ON, "KDF_TYPE '%s' is not supported.\n", name);
                return 0;
            }
        } else if (strcmp(p->key, OSSL_EXCHANGE_PARAM_KDF_DIGEST) == 0) {
            const char *digest = NULL;

            ret = OSSL_PARAM_get_utf8_string_ptr(p, &digest);
            if (ret != 1) {
                return ret;
            }
            pEcdhctx->kdfMd = EVP_MD_fetch(NULL, digest, "provider=default");
        } else if (strcmp(p->key, OSSL_EXCHANGE_PARAM_KDF_OUTLEN) == 0) {
            size_t outLen;

            ret = OSSL_PARAM_get_size_t(p, &outLen);
            if (ret != 1) {
                return ret;
            }
            pEcdhctx->kdfOutLen = outLen;
        } else if (strcmp(p->key, OSSL_EXCHANGE_PARAM_KDF_UKM) == 0) {
            void *ukm = NULL;
            size_t ukmLen;

            ret = OSSL_PARAM_get_octet_string(p, &ukm, 0, &ukmLen);
            if (ret != 1) {
                return ret;
            }
            OPENSSL_free(pEcdhctx->kdfUkm);
            pEcdhctx->kdfUkm = ukm;
            pEcdhctx->kdfUkmLen = ukmLen;
        } else {
            sssProv_Print(LOG_DBG_ON, "parameter '%s' is not supported.\n", p->key);
            return 0;
        }
    }
    return 1;
}

static int sss_ecdh_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    int ret                            = 0;
    sss_provider_ecdh_ctx_st *pEcdhctx = ctx;
    sss_se05x_session_t *pSession      = NULL;
    EVP_PKEY_CTX *evpCtx               = NULL;
    int openssl_ret                    = 0;
    int evp_secretLen;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    ENSURE_OR_GO_CLEANUP(pEcdhctx != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(secretlen != NULL);
    ENSURE_OR_GO_CLEANUP(pEcdhctx->pPeerEVPPkey != NULL);

    if (pEcdhctx->pStoreObjCtx->isEVPKey == 0) {
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        pSession = (sss_se05x_session_t *)&(pEcdhctx->pProvCtx->p_ex_sss_boot_ctx->session);
        ENSURE_OR_GO_CLEANUP(pSession != NULL);

        if (secret == NULL) {
            if (pEcdhctx->useX963KDF) {
                *secretlen = pEcdhctx->kdfOutLen;
            } else {
                evp_secretLen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
                if (evp_secretLen < 0) {
                    return 0;
                }
                *secretlen = (size_t)evp_secretLen;
            }
            return (*secretlen > 0);
        }
        else {
            smStatus_t sm_status;
            uint8_t pubBuf[256] = {
                0,
            };
            size_t pubBufLen         = 0;
            unsigned char *pubKeyPtr = pubBuf;
            /* Get the public key from the peer key */
            openssl_ret = i2d_PublicKey(pEcdhctx->pPeerEVPPkey, &pubKeyPtr);
            if (openssl_ret > 0) {
                pubBufLen = openssl_ret;
            }
            else {
                goto cleanup;
            }

            sssProv_Print(LOG_FLOW_ON, "Performing ECDH on SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pEcdhctx->pStoreObjCtx->keyid);

            sm_status = Se05x_API_ECDHGenerateSharedSecret(
                &(pSession->s_ctx), pEcdhctx->pStoreObjCtx->keyid, pubBuf, pubBufLen, secret, secretlen);
            ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
            if (pEcdhctx->useX963KDF) {
                OSSL_PARAM params[4], *p = params;
                const char* mdname = EVP_MD_get0_name(pEcdhctx->kdfMd);
                EVP_KDF *kdf = EVP_KDF_fetch(NULL, "X963KDF", "provider=default");
                EVP_KDF_CTX *kdfCtx = EVP_KDF_CTX_new(kdf);

                *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)mdname, 0);
                *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret, *secretlen);
                if (pEcdhctx->kdfUkm != NULL && pEcdhctx->kdfUkmLen > 0) {
                    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, pEcdhctx->kdfUkm, pEcdhctx->kdfUkmLen);
                }
                *p = OSSL_PARAM_construct_end();
                if (EVP_KDF_derive(kdfCtx, secret, pEcdhctx->kdfOutLen, params) <= 0) {
                    sssProv_Print(LOG_DBG_ON, "failed to EVP_KDF_derive().\n");
                    EVP_KDF_CTX_free(kdfCtx);
                    EVP_KDF_free(kdf);
                    return 0;
                }
                *secretlen = pEcdhctx->kdfOutLen;
                EVP_KDF_CTX_free(kdfCtx);
                EVP_KDF_free(kdf);
            }
        }
    }
    else {
        /* Roll back to software implementation */
        if (secret == NULL) {
            evp_secretLen = EVP_PKEY_size(pEcdhctx->pPeerEVPPkey);
            if (evp_secretLen < 0) {
                return 0;
            }
            *secretlen = (size_t)evp_secretLen;
            return (*secretlen > 0);
        }
        else {
            size_t secret_len = outlen;

            ENSURE_OR_GO_CLEANUP(pEcdhctx->pStoreObjCtx->pEVPPkey != NULL);

            sssProv_Print(LOG_FLOW_ON, "Not a key in secure element. Performing ECDH on host software \n");

            evpCtx = EVP_PKEY_CTX_new_from_pkey(NULL, pEcdhctx->pStoreObjCtx->pEVPPkey, "provider!=nxp_prov");
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_derive_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_derive_set_peer(evpCtx, pEcdhctx->pPeerEVPPkey);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_derive(evpCtx, secret, &secret_len);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            *secretlen = secret_len;
        }
    }

    ret = 1;
cleanup:
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

const OSSL_DISPATCH sss_ecdh_keyexch_functions[] = {{OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sss_ecdh_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sss_ecdh_keyexch_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))sss_ecdh_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sss_ecdh_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sss_ecdh_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))sss_ecdh_keyexch_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))sss_ecdh_keyexch_set_ctx_params},
    {0, NULL}};

#endif //#if SSS_HAVE_ECC
