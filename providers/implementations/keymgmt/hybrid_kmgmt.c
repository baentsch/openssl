/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/self_test.h>
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/hybrid.h"
#include "prov/securitycheck.h"
#include "crypto/hybrid.h"

static OSSL_FUNC_keymgmt_has_fn hybrid_has;
static OSSL_FUNC_keymgmt_match_fn hybrid_match;

static OSSL_FUNC_keymgmt_gen_init_fn x25519_mlkem768_gen_init;
static OSSL_FUNC_keymgmt_gen_fn hybrid_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn hybrid_gen_cleanup;

static OSSL_FUNC_keymgmt_gen_set_params_fn hybrid_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn hybrid_gen_settable_params;

static OSSL_FUNC_keymgmt_get_params_fn hybrid_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn hybrid_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn hybrid_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn hybrid_settable_params;

/* TODO later
static OSSL_FUNC_keymgmt_load_fn hybrid_load;
static OSSL_FUNC_keymgmt_import_fn hybrid_import;
static OSSL_FUNC_keymgmt_import_types_fn hybrid_imexport_types;
static OSSL_FUNC_keymgmt_export_fn hybrid_export;
static OSSL_FUNC_keymgmt_export_types_fn hybrid_imexport_types;
static OSSL_FUNC_keymgmt_validate_fn hybrid_validate;
*/

#define HYBRID_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

struct hybrid_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    HYBRID_KEY *hk;
    int selection;
};

static void *x25519_mlkem768_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    /* TODO keep in sync with actual alg names chosen */
    /* TODO: get propq from somewhere */
    return ossl_hybrid_key_new(PROV_LIBCTX_OF(provctx), "x25519", "MLKEM-768", NULL);
}

static int hybrid_has(const void *keydata, int selection)
{
    const HYBRID_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if (key->key1 == NULL || key->key2 == NULL)
        return 0;

    return evp_keymgmt_util_has(key->key1, selection)
           && evp_keymgmt_util_has(key->key2, selection);
}

static int hybrid_match(const void *keydata1, const void *keydata2, int selection)
{
    const HYBRID_KEY *key1 = keydata1;
    const HYBRID_KEY *key2 = keydata2;

    if (!ossl_prov_is_running() || key1 == NULL || key2 == NULL)
        return 0;

    if (key1->key1 == NULL || key1->key2 == NULL
       || key2->key1 == NULL || key2->key2 == NULL)
        return 0;

    return evp_keymgmt_util_match(key1->key1, key2->key1, selection)
       && evp_keymgmt_util_match(key1->key2, key2->key2, selection);
}

/* 
 * TODO: Decide which further commands are necessary, e.g., minimum strength logic for SEC_BITS
 */
static int hybrid_get_params(void *key, OSSL_PARAM params[])
{
    HYBRID_KEY *hkey = key;
    OSSL_PARAM *p, *pk;
    int overall_pubkey_len;
    char *overall_pubkey;
    int ret = 1;

    if (hkey == NULL || hkey->key1 == NULL || hkey->key2 == NULL)
        return 0;
//XXX next, extract and concatenate both public keys, maybe using EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &public_key?
// pub" (OSSL_PKEY_PARAM_PUB_KEY) <octet string> The public key value.
/*    if (EVP_PKEY_todata(hkey->key1, EVP_PKEY_PUBLIC_KEY, &pk) != 1)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, overall_pubkey, overall_pubkey_len))
            ret = 0;

    OSSL_PARAM_free(pk);
*/
    return ret;
}

static const OSSL_PARAM hybrid_gettable_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_gettable_params(void *provctx)
{
    return hybrid_gettable_params_list;
}


/* For now, don't enable and settable params.
 * TODO: Decide whether worthwhile adding some kind of minimum strength logic for SEC_BITS
 * and/or "combined pubkey export"
 */
static int hybrid_set_params(void *key, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM hybrid_settable_params_list[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_settable_params(void *provctx)
{
    return hybrid_settable_params_list;
}

static void *hybrid_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[],
                             const char *keytype1, const char *keytype2)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct hybrid_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    HYBRID_KEY *hk = x25519_mlkem768_new_key(provctx);

    if (hk == NULL)
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        gctx->selection = selection;
        gctx->hk = hk;
    }
    return gctx;
}

static void *x25519_mlkem768_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[])
{
    return hybrid_gen_init(provctx, selection, params, "X25519", "MLKEM-768");
}

/*
 * We do not expect to have to set gen params to either key component
 * TODO: review if necessary (P-hybrids??)
 */
static int hybrid_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct hybrid_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *hybrid_gen_settable_params(ossl_unused void *genctx,
                                                    ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *hybrid_gen(void *ctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct hybrid_gen_ctx *gctx = (struct hybrid_gen_ctx *)ctx;
    HYBRID_KEY *key;

    if (gctx == NULL)
        return NULL;
    key = gctx->hk;
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    /* otherwise, generate both key pairs */
    if (key->key1 != NULL || key->key2 != NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }

    key->key1 = EVP_PKEY_Q_keygen(gctx->libctx, gctx->propq, key->keytype1);
    key->key2 = EVP_PKEY_Q_keygen(gctx->libctx, gctx->propq, key->keytype2);

    if (key->key1 == NULL || key->key2 == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }
    return key;
err:
    ossl_hybrid_key_free(key);
    return NULL;
}

static void hybrid_gen_cleanup(void *genctx)
{
    struct hybrid_gen_ctx *gctx = genctx;

    ossl_hybrid_key_free(gctx->hk);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

#define MAKE_HYBRID_KEYMGMT_FUNCTIONS(alg1, alg2) \
    const OSSL_DISPATCH ossl_##alg1##_##alg2##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alg1##_##alg2##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ossl_hybrid_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))hybrid_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))hybrid_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))hybrid_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))hybrid_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hybrid_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hybrid_match }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))alg1##_##alg2##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))hybrid_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, \
          (void (*)(void))hybrid_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hybrid_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))hybrid_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ossl_hybrid_key_dup }, \
        OSSL_DISPATCH_END \
    };

/* Not yet needed:
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))alg##_validate }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ecx_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ecx_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ecx_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ecx_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ecx_load }, \
 */

MAKE_HYBRID_KEYMGMT_FUNCTIONS(x25519, mlkem768)
