/**
 * @file sssProvider_rsa.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Provider implementation for RSA sign / verify using SSS API's
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_RSA

/* ********************** Include files ********************** */
#include <string.h>
#include <openssl/core_names.h>
#include "sssProvider_main.h"

/* ********************** Constants ************************** */
#define MAX_DIGEST_INPUT_DATA 512

/* ********************** structure definition *************** */
typedef struct
{
    sss_algorithm_t sha_algorithm;
    sss_algorithm_t sign_algorithm;
    uint8_t digest[64]; /* MAX SHA512 */
    size_t digestLen;
    sss_provider_store_obj_t *pStoreObjCtx;
    sss_provider_context_t *pProvCtx;
    sss_digest_t digestCtx;
} sss_provider_rsa_ctx_st;

/* ********************** Private funtions ******************* */

static void *sss_rsa_signature_newctx(void *provctx, const char *propq)
{
    sss_provider_rsa_ctx_st *pRSACtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_ctx_st));
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    (void)(propq);
    if (pRSACtx != NULL) {
        pRSACtx->pProvCtx = provctx;
    }
    return pRSACtx;
}

static void sss_rsa_signature_freectx(void *ctx)
{
    sss_provider_rsa_ctx_st *sctx = ctx;
    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);
    if (sctx != NULL) {
        if (sctx->pStoreObjCtx->pEVPPkey != NULL) {
            EVP_PKEY_free(sctx->pStoreObjCtx->pEVPPkey);
            sctx->pStoreObjCtx->pEVPPkey = NULL;
        }
        OPENSSL_clear_free(sctx, sizeof(sss_provider_rsa_ctx_st));
    }
    return;
}

static void *sss_rsa_signature_dupctx(void *ctx)
{
    sss_provider_rsa_ctx_st *pRsaCtx    = (sss_provider_rsa_ctx_st *)ctx;
    sss_provider_rsa_ctx_st *pRsaDupCtx = OPENSSL_zalloc(sizeof(sss_provider_rsa_ctx_st));

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaDupCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);

    pRsaDupCtx->digestLen = pRsaCtx->digestLen;
    if (pRsaCtx->digestLen > 0) {
        memcpy(pRsaDupCtx->digest, pRsaCtx->digest, pRsaCtx->digestLen);
    }
    pRsaDupCtx->pProvCtx       = pRsaCtx->pProvCtx;
    pRsaDupCtx->pStoreObjCtx   = pRsaCtx->pStoreObjCtx;
    pRsaDupCtx->sha_algorithm  = pRsaCtx->sha_algorithm;
    pRsaDupCtx->sign_algorithm = pRsaCtx->sign_algorithm;
    memcpy(&pRsaDupCtx->digestCtx, &pRsaCtx->digestCtx, sizeof(pRsaCtx->digestCtx));
    return pRsaDupCtx;

cleanup:
    if (pRsaDupCtx != NULL) {
        OPENSSL_clear_free(pRsaDupCtx, sizeof(sss_provider_rsa_ctx_st));
    }
    return NULL;
}

static int sss_rsa_signature_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    pRsaCtx->pStoreObjCtx = provkey;

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        if (sig == NULL) {
            *siglen = pRsaCtx->pStoreObjCtx->key_len;
            return 1;
        }
        else {
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
            ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)tbs, tbslen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(
                LOG_FLOW_ON, "Not a key in secure element. Performing RSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new(pRsaCtx->pStoreObjCtx->pEVPPkey, NULL);
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, tbs, tbslen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[])
{
    int ret                             = 0;
    sss_provider_store_obj_t *pStoreCtx = provkey;
    sss_provider_rsa_ctx_st *pRsaCtx    = ctx;
    sss_status_t status;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(params);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pStoreCtx != NULL);

    pRsaCtx->pStoreObjCtx = pStoreCtx;
    pRsaCtx->digestLen    = sizeof(pRsaCtx->digest);

    if (mdname == NULL) {
        pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA256;
        pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
    }
    else {
        if ((0 == SSS_CMP_STR(mdname, "sha1")) || (0 == SSS_CMP_STR(mdname, "SHA1"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA1;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA1;
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha224")) || (0 == SSS_CMP_STR(mdname, "SHA224")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-224"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA224;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA224;
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha256")) || (0 == SSS_CMP_STR(mdname, "SHA256")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-256"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA256;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256;
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha384")) || (0 == SSS_CMP_STR(mdname, "SHA384")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-384"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA384;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA384;
        }
        else if ((0 == SSS_CMP_STR(mdname, "sha512")) || (0 == SSS_CMP_STR(mdname, "SHA512")) ||
                 (0 == SSS_CMP_STR(mdname, "SHA2-512"))) {
            pRsaCtx->sha_algorithm  = kAlgorithm_SSS_SHA512;
            pRsaCtx->sign_algorithm = kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA512;
        }
        else {
            sssProv_Print(LOG_DBG_ON, "sha_algorithm does not match \n");
            goto cleanup;
        }
    }

#if SSS_HAVE_HOSTCRYPTO_ANY
    /* digest context initialization */
    status = sss_digest_context_init(&pRsaCtx->digestCtx,
        &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session,
        pRsaCtx->sha_algorithm,
        kMode_SSS_Digest);
#else
    /* Digest of the message is always done on host */
    status = kStatus_SSS_Fail;
    sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_digest_init(&pRsaCtx->digestCtx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_digest_update(void *ctx, const unsigned char *data, size_t datalen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    int ret                          = 0;
    sss_status_t status;
    size_t datalenTmp = datalen;
    size_t offset     = 0;
    size_t templen    = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

    while (datalenTmp > 0) {
        templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

        status = sss_digest_update(&pRsaCtx->digestCtx, data + offset, templen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        datalenTmp = datalenTmp - templen;
        ENSURE_OR_GO_CLEANUP((UINT_MAX - offset) >= templen);
        offset = offset + templen;
    }

    ret = 1;
cleanup:
    return ret;
}

static int sss_rsa_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    sss_status_t status;
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    sss_asymmetric_t asymmCtx        = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(siglen != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            *siglen = pRsaCtx->pStoreObjCtx->key_len;
            return (*siglen > 0);
        }
        else {
            status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            status = sss_asymmetric_context_init(&asymmCtx,
                &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->sign_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            status = sss_asymmetric_sign_digest(&asymmCtx, pRsaCtx->digest, pRsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(
                LOG_FLOW_ON, "Not a key in secure element. Performing RSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new(pRsaCtx->pStoreObjCtx->pEVPPkey, NULL);
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pRsaCtx->sha_algorithm) {
            case kAlgorithm_SSS_SHA1: {
                md = EVP_sha1();
                break;
            }
            case kAlgorithm_SSS_SHA224: {
                md = EVP_sha224();
                break;
            }
            case kAlgorithm_SSS_SHA256: {
                md = EVP_sha256();
                break;
            }
            case kAlgorithm_SSS_SHA384: {
                md = EVP_sha384();
                break;
            }
            case kAlgorithm_SSS_SHA512: {
                md = EVP_sha512();
                break;
            }
            default: {
                md = NULL;
            }
            }

            status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_sign(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
    sss_status_t status;
    sss_digest_t digestCtx    = {0};
    sss_asymmetric_t asymmCtx = {
        0,
    };
    size_t datalenTmp    = datalen;
    size_t offset        = 0;
    size_t templen       = 0;
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;
    int maxSize          = 0;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    (void)(sigsize);

    ENSURE_OR_GO_CLEANUP(data != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        if (sig == NULL) {
            *siglen = (((pRsaCtx->pStoreObjCtx->key_len) * 2) + 8);
            return 1;
        }
        else {
#if SSS_HAVE_HOSTCRYPTO_ANY
            /* digest context initialization */
            status = sss_digest_context_init(&digestCtx,
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pRsaCtx->sha_algorithm,
                kMode_SSS_Digest);
#else
            /* Digest of the message is always done on host */
            status = kStatus_SSS_Fail;
            sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            //performing digest on the input data
            status = sss_digest_init(&digestCtx);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            while (datalenTmp > 0) {
                templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

                status = sss_digest_update(&digestCtx, data + offset, templen);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                datalenTmp = datalenTmp - templen;
                ENSURE_OR_GO_CLEANUP((UINT_MAX - offset) >= templen);
                offset = offset + templen;
            }

            status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            // asymmetric context initialization
            status = sss_asymmetric_context_init(&asymmCtx,
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
                &pRsaCtx->pStoreObjCtx->object,
                pRsaCtx->sign_algorithm,
                kMode_SSS_Sign);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            sssProv_Print(LOG_FLOW_ON, "Performing RSA sign using SE05x \n");
            sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
            // sign digest
            status = sss_asymmetric_sign_digest(&asymmCtx, (uint8_t *)pRsaCtx->digest, pRsaCtx->digestLen, sig, siglen);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        }
    }
    else {
        /* Roll back to software implementation */

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        if (sig == NULL) {
            maxSize = EVP_PKEY_size(pRsaCtx->pStoreObjCtx->pEVPPkey);
            if (maxSize > 0) {
                *siglen = maxSize;
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            int openssl_ret = 0;

            sssProv_Print(
                LOG_FLOW_ON, "Not a key in secure element. Performing RSA sign operation using host software \n");

            evpCtx = EVP_PKEY_CTX_new(pRsaCtx->pStoreObjCtx->pEVPPkey, NULL);
            ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

            openssl_ret = EVP_PKEY_sign_init(evpCtx);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            switch (pRsaCtx->sha_algorithm) {
            case kAlgorithm_SSS_SHA1: {
                md = EVP_sha1();
                break;
            }
            case kAlgorithm_SSS_SHA224: {
                md = EVP_sha224();
                break;
            }
            case kAlgorithm_SSS_SHA256: {
                md = EVP_sha256();
                break;
            }
            case kAlgorithm_SSS_SHA384: {
                md = EVP_sha384();
                break;
            }
            case kAlgorithm_SSS_SHA512: {
                md = EVP_sha512();
                break;
            }
            default: {
                md = NULL;
            }
            }

#if SSS_HAVE_HOSTCRYPTO_ANY
            /* digest context initialization */
            status = sss_digest_context_init(&digestCtx,
                &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->host_session),
                pRsaCtx->sha_algorithm,
                kMode_SSS_Digest);
#else
            /* Digest of the message is always done on host */
            status = kStatus_SSS_Fail;
            sssProv_Print(LOG_ERR_ON, "Enable host crypto support");
#endif
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            //performing digest on the input data
            status = sss_digest_init(&digestCtx);
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            while (datalenTmp > 0) {
                templen = (datalenTmp > MAX_DIGEST_INPUT_DATA) ? MAX_DIGEST_INPUT_DATA : datalenTmp;

                status = sss_digest_update(&digestCtx, data + offset, templen);
                ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

                datalenTmp = datalenTmp - templen;
                ENSURE_OR_GO_CLEANUP((UINT_MAX - offset) >= templen);
                offset = offset + templen;
            }

            status = sss_digest_finish(&digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
            ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

            openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

            openssl_ret = EVP_PKEY_sign(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
            ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
        }
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_verify(
    void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)
{
    sss_provider_rsa_ctx_st *pRsaCtx = (sss_provider_rsa_ctx_st *)ctx;
    int ret                          = 0;
    sss_status_t status;
    sss_asymmetric_t asymmCtx = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(sig != NULL);
    ENSURE_OR_GO_CLEANUP(tbs != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        //Asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session),
            &pRsaCtx->pStoreObjCtx->object,
            kAlgorithm_SSS_RSASSA_PKCS1_V1_5_NO_HASH,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing RSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, (uint8_t *)tbs, tbslen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(
            LOG_FLOW_ON, "Not a key in secure element. Performing RSA verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new(pRsaCtx->pStoreObjCtx->pEVPPkey, NULL);
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, tbs, tbslen);
        if (openssl_ret == 0) {
            sssProv_Print(LOG_ERR_ON, "Verification failed \n");
        }
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_verify_final(void *ctx, const unsigned char *sig, size_t siglen)
{
    sss_status_t status;
    int ret                          = 0;
    sss_provider_rsa_ctx_st *pRsaCtx = ctx;
    sss_asymmetric_t asymmCtx        = {
        0,
    };
    EVP_PKEY_CTX *evpCtx = NULL;
    const EVP_MD *md     = NULL;

    sssProv_Print(LOG_DBG_ON, "Enter - %s \n", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(pRsaCtx != NULL);
    ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx != NULL);
    ENSURE_OR_GO_CLEANUP(sig != NULL);

    if (pRsaCtx->pStoreObjCtx->object.keyId != 0) {
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx != NULL);
        ENSURE_OR_GO_CLEANUP(pRsaCtx->pProvCtx->p_ex_sss_boot_ctx != NULL);

        status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        //Asymmetric context initialization
        status = sss_asymmetric_context_init(&asymmCtx,
            &pRsaCtx->pProvCtx->p_ex_sss_boot_ctx->session,
            &pRsaCtx->pStoreObjCtx->object,
            pRsaCtx->sign_algorithm,
            kMode_SSS_Verify);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        sssProv_Print(LOG_FLOW_ON, "Performing RSA verify using SE05x \n");
        sssProv_Print(LOG_DBG_ON, "(Using key id 0x%X from SE05x) \n", pRsaCtx->pStoreObjCtx->object.keyId);
        status = sss_asymmetric_verify_digest(&asymmCtx, pRsaCtx->digest, pRsaCtx->digestLen, (uint8_t *)sig, siglen);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }
    else {
        /* Roll back to software implementation */

        int openssl_ret = 0;

        sssProv_Print(
            LOG_FLOW_ON, "Not a key in secure element. Performing RSA verify operation using host software \n");

        ENSURE_OR_GO_CLEANUP(pRsaCtx->pStoreObjCtx->pEVPPkey != NULL);

        evpCtx = EVP_PKEY_CTX_new(pRsaCtx->pStoreObjCtx->pEVPPkey, NULL);
        ENSURE_OR_GO_CLEANUP(evpCtx != NULL);

        openssl_ret = EVP_PKEY_verify_init(evpCtx);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        switch (pRsaCtx->sha_algorithm) {
        case kAlgorithm_SSS_SHA1: {
            md = EVP_sha1();
            break;
        }
        case kAlgorithm_SSS_SHA224: {
            md = EVP_sha224();
            break;
        }
        case kAlgorithm_SSS_SHA256: {
            md = EVP_sha256();
            break;
        }
        case kAlgorithm_SSS_SHA384: {
            md = EVP_sha384();
            break;
        }
        case kAlgorithm_SSS_SHA512: {
            md = EVP_sha512();
            break;
        }
        default: {
            md = NULL;
        }
        }

        status = sss_digest_finish(&pRsaCtx->digestCtx, pRsaCtx->digest, &(pRsaCtx->digestLen));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        openssl_ret = EVP_PKEY_CTX_set_signature_md(evpCtx, md);
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);

        openssl_ret = EVP_PKEY_verify(evpCtx, sig, siglen, pRsaCtx->digest, pRsaCtx->digestLen);
        if (openssl_ret == 0) {
            sssProv_Print(LOG_ERR_ON, "Verification failed \n");
        }
        ENSURE_OR_GO_CLEANUP(openssl_ret == 1);
    }

    ret = 1;
cleanup:
    if (asymmCtx.session != NULL) {
        sss_asymmetric_context_free(&asymmCtx);
    }
    if (pRsaCtx != NULL) {
        if (pRsaCtx->digestCtx.session != NULL) {
            sss_digest_context_free(&pRsaCtx->digestCtx);
        }
    }
    if (evpCtx != NULL) {
        EVP_PKEY_CTX_free(evpCtx);
    }
    return ret;
}

static int sss_rsa_signature_digest_verify(
    void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *data, size_t datalen)
{
    sssProv_Print(LOG_DBG_ON, "Enter - %s (NOT IMPLEMENTED) \n", __FUNCTION__);
    (void)(ctx);
    (void)(sig);
    (void)(siglen);
    (void)(sigsize);
    (void)(data);
    (void)(datalen);
    return 0;
}

const OSSL_DISPATCH sss_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sss_rsa_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sss_rsa_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sss_rsa_signature_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sss_rsa_signature_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sss_rsa_signature_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))sss_rsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))sss_rsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))sss_rsa_signature_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))sss_rsa_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sss_rsa_signature_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sss_rsa_signature_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))sss_rsa_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))sss_rsa_signature_digest_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))sss_rsa_signature_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))sss_rsa_signature_digest_verify},
    {0, NULL}};

#endif //#if SSS_HAVE_RSA
