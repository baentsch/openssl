/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

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
#include "internal/mlkem.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"

#ifdef NDEBUG
#define MLKEM_KM_PRINTF(a)
#define MLKEM_KM_PRINTF2(a, b)
#define MLKEM_KM_PRINTF3(a, b, c)
#else
#define MLKEM_KM_PRINTF(a)                                                       \
    if (getenv("MLKEMKM"))                                                       \
    printf(a)
#define MLKEM_KM_PRINTF2(a, b)                                                   \
    if (getenv("MLKEMKM"))                                                       \
    printf(a, b)
#define MLKEM_KM_PRINTF3(a, b, c)                                                \
    if (getenv("MLKEMKM"))                                                       \
    printf(a, b, c)
#endif // NDEBUG


static OSSL_FUNC_keymgmt_new_fn mlkem_new;
static OSSL_FUNC_keymgmt_free_fn mlkem_free;
static OSSL_FUNC_keymgmt_gen_init_fn mlkem_gen_init;
static OSSL_FUNC_keymgmt_gen_fn mlkem_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn mlkem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn mlkem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn mlkem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn mlkem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn mlkem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn mlkem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn mlkem_settable_params;
static OSSL_FUNC_keymgmt_has_fn mlkem_has;
static OSSL_FUNC_keymgmt_match_fn mlkem_match;
static OSSL_FUNC_keymgmt_import_fn mlkem_import;
static OSSL_FUNC_keymgmt_export_fn mlkem_export;
static OSSL_FUNC_keymgmt_import_types_fn mlkem_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn mlkem_imexport_types;

static OSSL_FUNC_keymgmt_dup_fn mlkem_dup;

#define ECX_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

struct mlkem_gen_ctx {
    void *provctx;
    int selection;
};

static void *mlkem_new(void *provctx)
{
    MLKEM_KEY* key = NULL;
    MLKEM_KM_PRINTF("MLKEMKM new key req\n");
    if (!ossl_prov_is_running())
        return 0;
    key = OPENSSL_zalloc(sizeof(MLKEM_KEY));
    if (key == NULL)
        return 0;
    key->keytype = MLKEM_KEY_TYPE_768; /* TODO any type */
    MLKEM_KM_PRINTF2("MLKEMKM new key = %p\n", key);
    return key;
}

static void mlkem_free(void *vkey)
{
    MLKEM_KEY *mkey = (MLKEM_KEY *)vkey;

    MLKEM_KM_PRINTF2("MLKEMKM free key %p\n", mkey);
    if (mkey == NULL)
        return;
    OPENSSL_free(mkey->pubkey);
    OPENSSL_free(mkey->seckey);
    OPENSSL_free(mkey);
}

static int mlkem_has(const void *keydata, int selection)
{
    const MLKEM_KEY *key = keydata;
    int ok = 0;

    MLKEM_KM_PRINTF2("MLKEMKM has %p\n", key);
    if (ossl_prov_is_running() && key != NULL) {
        /*
         * ML-KEM keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->seckey != NULL;
    }
    MLKEM_KM_PRINTF2("MLKEMKM has result %d\n", ok);
    return ok;
}

static int mlkem_match(const void *keydata1, const void *keydata2, int selection)
{
    const MLKEM_KEY *key1 = keydata1;
    const MLKEM_KEY *key2 = keydata2;
    int ok = 1;

    MLKEM_KM_PRINTF3("MLKEMKM matching %p and %p\n", key1, key2);
    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && key1->keytype == key2->keytype;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const uint8_t *pa = key1->pubkey;
            const uint8_t *pb = key2->pubkey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_PUBLICKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const uint8_t *pa = key1->seckey;
            const uint8_t *pb = key2->seckey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_SECRETKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    MLKEM_KM_PRINTF2("MLKEMKM match result %d\n", ok);
    return ok;
}

static int key_to_params(MLKEM_KEY *key, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], int include_private)
{
    if (key == NULL)
        return 0;

    /* TODO: Generalize to all key types */
    if (key->keytype != MLKEM_KEY_TYPE_768) {
        return 0;
    }

    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           key->pubkey, MLKEM768_PUBLICKEYBYTES))
        return 0;

    if (include_private
        && key->seckey != NULL
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              key->seckey, MLKEM768_SECRETKEYBYTES))
        return 0;

    return 1;
}

static int mlkem_export(void *key, int selection, OSSL_CALLBACK *param_cb,
                        void *cbarg)
{
    MLKEM_KEY *mkey = key;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    MLKEM_KM_PRINTF2("MLKEMKM export %p\n", key);
    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

        if (!key_to_params(mkey, tmpl, NULL, include_private))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    MLKEM_KM_PRINTF2("MLKEMKM export result %d\n", ret);
    return ret;
}

static int ossl_mlkem_key_fromdata(MLKEM_KEY *key,
                                   const OSSL_PARAM params[],
                                   int include_private)
{
    size_t privkeylen = 0, pubkeylen = 0;
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key;
    unsigned char *pubkey;

    if (key == NULL)
        return 0;

    /* TODO: Generalize to all key types */
    if (key->keytype != MLKEM_KEY_TYPE_768) {
        return 0;
    }

    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (param_pub_key == NULL && param_priv_key == NULL)
        return 0;

    if (param_priv_key != NULL) {
        if (!OSSL_PARAM_get_octet_string(param_priv_key,
                                         (void **)&key->seckey,
                                         MLKEM768_SECRETKEYBYTES,
                                         &privkeylen))
            return 0;
        if (privkeylen != MLKEM768_SECRETKEYBYTES) {
            /*
             * Invalid key length. We will clear what we've received now. We
             * can't leave it to ossl_mlkem_key_free() because that will call
             * OPENSSL_secure_clear_free() and assume the correct key length
             */
            printf("sec key len mismatch in import: %ld vs %d: HOWCAN?\n",
                privkeylen, MLKEM768_SECRETKEYBYTES);
            OPENSSL_secure_clear_free(key->seckey, privkeylen);
            key->seckey = NULL;
            return 0;
        }
    }


    pubkey = key->pubkey;
    if (param_pub_key != NULL
        && !OSSL_PARAM_get_octet_string(param_pub_key,
                                        (void **)&pubkey,
                                        MLKEM768_PUBLICKEYBYTES,
                                        &pubkeylen))
        return 0;

    if ((param_pub_key != NULL && pubkeylen != MLKEM768_PUBLICKEYBYTES)) {
        printf("sec key len mismatch in import: %ld vs %d: HOWCAN?\n",
            pubkeylen, MLKEM768_PUBLICKEYBYTES);
        return 0;
    }

    /* TBD if this also shall contain hybrid logic: reconstitute (only) classic part here */

    return 1;
}

static int mlkem_import(void *key, int selection, const OSSL_PARAM params[])
{
    MLKEM_KEY *mkey = key;
    int ok = 1;
    int include_private;

    MLKEM_KM_PRINTF2("MLKEMKM import %p\n", mkey);
    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    ok = ok && ossl_mlkem_key_fromdata(mkey, params, include_private);

    MLKEM_KM_PRINTF2("MLKEMKM import result %d\n", ok);
    return ok;
}

#define MLKEM_KEY_TYPES()                                                        \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                     \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM mlkem_key_types[] = {
    MLKEM_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_imexport_types(int selection)
{
    MLKEM_KM_PRINTF("MLKEMKM getting imexport types\n");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return mlkem_key_types;
    return NULL;
}

static int mlkem_get_params(void *key, OSSL_PARAM params[])
{
    MLKEM_KEY *mkey = key;
    OSSL_PARAM *p;

    MLKEM_KM_PRINTF2("MLKEMKM get params %p\n", mkey);
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_SECRETKEYBYTES * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_SECURITY_BITS))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_CIPHERTEXTBYTES))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, mkey->pubkey, MLKEM768_PUBLICKEYBYTES))
            return 0;
    }

    MLKEM_KM_PRINTF("MLKEMKM get params OK\n");
    return 1;
}

static const OSSL_PARAM mlkem_gettable_params_arr[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_gettable_params(void *provctx)
{
    MLKEM_KM_PRINTF("MLKEMKM gettable params called\n");
    return mlkem_gettable_params_arr;
}

static int mlkem_set_params(void *key, const OSSL_PARAM params[])
{
    MLKEM_KEY *mkey = key;
    const OSSL_PARAM *p;

    MLKEM_KM_PRINTF2("MLKEMKM set params called for %p\n", mkey);
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        void *buf;

        if (mkey->pubkey == NULL)
            mkey->pubkey = OPENSSL_malloc(MLKEM768_PUBLICKEYBYTES);

        buf = mkey->pubkey;
        if (buf == NULL)
            return 0;

        if (p->data_size != MLKEM768_PUBLICKEYBYTES
                || !OSSL_PARAM_get_octet_string(p, &buf, MLKEM768_PUBLICKEYBYTES,
                                                NULL))
            return 0;
        OPENSSL_clear_free(mkey->seckey, MLKEM768_SECRETKEYBYTES);
        mkey->seckey = NULL;
    }

    MLKEM_KM_PRINTF("MLKEMKM set params OK\n");
    return 1;
}

static const OSSL_PARAM mlkem_settable_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_settable_params(void *provctx)
{
    MLKEM_KM_PRINTF("MLKEMKM settable params called\n");
    return mlkem_settable_params_arr;
}

static void *mlkem_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    struct mlkem_gen_ctx *gctx = NULL;

    MLKEM_KM_PRINTF2("MLKEMKM gen init called for %p\n", provctx);
    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->selection = selection;
    }
    if (!mlkem_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    MLKEM_KM_PRINTF2("MLKEMKM gen init returns %p\n", gctx);
    return gctx;
}

static int mlkem_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct mlkem_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return 0;

    MLKEM_KM_PRINTF2("MLKEMKM empty gen_set params called for %p\n", gctx);
    return 1;
}

static const OSSL_PARAM *mlkem_gen_settable_params(ossl_unused void *genctx,
                                                   ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_END
    };
    return settable;
}

static void *mlkem_gen(void *vctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct mlkem_gen_ctx *gctx = (struct mlkem_gen_ctx *)vctx;
    MLKEM_KEY *mkey;

    MLKEM_KM_PRINTF2("MLKEMKM gen called for %p\n", gctx);
    if (gctx == NULL)
        return NULL;

    if ((mkey = mlkem_new(NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        MLKEM_KM_PRINTF2("MLKEMKM gen returns blank %p\n", mkey);
        return mkey;
    }

    mkey->keytype = MLKEM_KEY_TYPE_768;
    mkey->pubkey = OPENSSL_malloc(MLKEM768_PUBLICKEYBYTES);
    mkey->seckey = OPENSSL_malloc(MLKEM768_SECRETKEYBYTES);
    if (mkey->pubkey == NULL || mkey->seckey == NULL)
        goto err;

    if (!mlkem768_ref_keypair(mkey->pubkey, mkey->seckey))
        goto err;

    MLKEM_KM_PRINTF2("MLKEMKM gen returns set %p\n", mkey);
    return mkey;
err:
    mlkem_free(mkey);
    MLKEM_KM_PRINTF("MLKEMKM gen returns NULL\n");
    return NULL;
}

static void mlkem_gen_cleanup(void *genctx)
{
    struct mlkem_gen_ctx *gctx = genctx;

    MLKEM_KM_PRINTF2("MLKEMKM gen cleanup for %p\n", gctx);
    OPENSSL_free(gctx);
}

static void *mlkem_dup(const void *vsrckey, int selection)
{
    const MLKEM_KEY *srckey = (const MLKEM_KEY *)vsrckey;
    MLKEM_KEY *dstkey;

    MLKEM_KM_PRINTF2("MLKEMKM dup called for %p\n", srckey);
    if (!ossl_prov_is_running())
        return NULL;

    dstkey = mlkem_new(NULL);
    if (dstkey == NULL)
        return NULL;

    dstkey->keytype = srckey->keytype;
    if (srckey->pubkey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        dstkey->pubkey = OPENSSL_memdup(srckey->pubkey, MLKEM768_PUBLICKEYBYTES);
        if (dstkey->pubkey == NULL) {
            goto err;
        }
    }
    if (srckey->seckey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        dstkey->seckey = OPENSSL_memdup(srckey->seckey, MLKEM768_SECRETKEYBYTES);
        if (dstkey->seckey == NULL) {
            goto err;
        }
    }

    MLKEM_KM_PRINTF2("MLKEMKM dup returns %p\n", dstkey);
    return dstkey;
 err:
    mlkem_free(dstkey);
    MLKEM_KM_PRINTF("MLKEMKM dup returns NULL\n");
    return NULL;
}

const OSSL_DISPATCH ossl_mlkem768_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mlkem_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))mlkem_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))mlkem_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))mlkem_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))mlkem_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))mlkem_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))mlkem_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))mlkem_match },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))mlkem_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))mlkem_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))mlkem_export },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))mlkem_import },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mlkem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))mlkem_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mlkem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))mlkem_dup },
    OSSL_DISPATCH_END
};
