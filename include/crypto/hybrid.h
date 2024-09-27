/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal hybrid key functions for other submodules: not for application use */

#ifndef OSSL_CRYPTO_HYBRID_H
# define OSSL_CRYPTO_HYBRID_H
# pragma once

# include <openssl/opensslconf.h>
# include <crypto/evp.h>

struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EVP_PKEY *key1;
    EVP_PKEY *key2;
    char *keytype1;
    char *keytype2;
    CRYPTO_REF_COUNT references;
};

typedef struct hybrid_key_st HYBRID_KEY;

HYBRID_KEY *ossl_hybrid_key_dup(const HYBRID_KEY *key, int selection);
HYBRID_KEY *ossl_hybrid_key_new(OSSL_LIB_CTX *libctx, const char *keytype1,
                                const char *keytype2, const char *propq);
void ossl_hybrid_key_free(HYBRID_KEY *key);

#endif
