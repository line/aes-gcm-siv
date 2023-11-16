/*
 * Copyright 2023 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "aesgcmsiv_jni.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes_gcmsiv.h"

#define AES_GCMSIV_JNI_SUCCESS           0
#define AES_GCMSIV_JNI_ERR               1
#define AES_GCMSIV_JNI_ERR_NULL_POINTER  2
#define AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY 3

#define JAVA_EXCEPTION                   "java/lang/Exception"
#define JAVA_AEAD_BAD_TAG_EXCEPTION      "javax/crypto/AEADBadTagException"
#define JAVA_ILLEGAL_ARGUMENT_EXCEPTION  "java/lang/IllegalArgumentException"
#define JAVA_NULL_POINTER_EXCEPTION      "java/lang/NullPointerException"
#define JAVA_OUT_OF_MEMORY_EXCEPTION     "java/lang/OutOfMemoryError"

static int jni_get_byte_array(JNIEnv *env, jbyteArray bytes, uint8_t **array, size_t *array_sz);
static int jni_set_byte_array(JNIEnv *env, jbyteArray *bytes, const uint8_t *data, size_t data_sz);
static void jni_throw_aesgcmsiv_exception(JNIEnv *env, aes_gcmsiv_status_t status);
static void jni_throw_jni_exception(JNIEnv *env, int code);
static int jni_get_ctx(JNIEnv *env, jobject self, struct aes_gcmsiv_ctx **ctx);
static int jni_set_ctx(JNIEnv *env, jobject self, struct aes_gcmsiv_ctx *ctx);
static int jni_get_ctx_jfieldID(JNIEnv *env, jobject self, jfieldID *fid);

/*
 * Java class native functions
 */

JNIEXPORT jbyteArray JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_encrypt(
    JNIEnv *env, jobject self, jbyteArray jnonce, jbyteArray jplain, jbyteArray jaad)
{
    jbyteArray result = NULL;
    int res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    uint8_t *nonce = NULL;
    size_t nonce_sz = 0;
    uint8_t *plain = NULL;
    size_t plain_sz = 0;
    uint8_t *aad = NULL;
    size_t aad_sz = 0;
    uint8_t *cipher = NULL;
    size_t cipher_sz = 0;
    size_t needed_sz;

    if (NULL == self) {
        jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_NULL_POINTER);
        goto cleanup;
    }

    // Get AES-GCM-SIV context
    res = jni_get_ctx(env, self, &ctx);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    // Convert input parameters to C types
    res = jni_get_byte_array(env, jnonce, &nonce, &nonce_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    res = jni_get_byte_array(env, jplain, &plain, &plain_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    res = jni_get_byte_array(env, jaad, &aad, &aad_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    // Get needed output size
    res = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &needed_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    // Allocate resources
    cipher_sz = needed_sz;
    cipher = malloc(cipher_sz);
    if (NULL == cipher) {
        jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY);
        goto cleanup;
    }

    // Perform actual encryption
    res = aes_gcmsiv_encrypt_with_tag(ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    // Make returned value
    res = jni_set_byte_array(env, &result, cipher, cipher_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }
cleanup:
    if (NULL != nonce) {
        (*env)->ReleaseByteArrayElements(env, jnonce, (jbyte *)nonce, JNI_ABORT);
    }

    if (NULL != plain) {
        (*env)->ReleaseByteArrayElements(env, jplain, (jbyte *)plain, JNI_ABORT);
    }

    if (NULL != aad) {
        (*env)->ReleaseByteArrayElements(env, jaad, (jbyte *)aad, JNI_ABORT);
    }

    if (NULL != cipher) {
        free(cipher);
    }

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_decrypt(
    JNIEnv *env, jobject self, jbyteArray jnonce, jbyteArray jcipher, jbyteArray jaad)
{
    jbyteArray result = NULL;
    int res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    uint8_t *nonce = NULL;
    size_t nonce_sz = 0;
    uint8_t *cipher = NULL;
    size_t cipher_sz = 0;
    uint8_t *aad = NULL;
    size_t aad_sz = 0;
    uint8_t *plain = NULL;
    size_t plain_sz = 0;
    size_t needed_sz;

    if (NULL == self) {
        jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_NULL_POINTER);
        goto cleanup;
    }

    // Get AES-GCM-SIV context
    res = jni_get_ctx(env, self, &ctx);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    // Convert input parameters to C types
    res = jni_get_byte_array(env, jnonce, &nonce, &nonce_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    res = jni_get_byte_array(env, jcipher, &cipher, &cipher_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    res = jni_get_byte_array(env, jaad, &aad, &aad_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    // Get needed output size
    res = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &needed_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    // Allocate resources
    plain_sz = needed_sz;

    if (needed_sz > 0) {
        plain = malloc(plain_sz);
        if (NULL == plain) {
            jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY);
            goto cleanup;
        }
    }

    // Perform actual decryption
    res = aes_gcmsiv_decrypt_and_check(ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz, plain,
                                       plain_sz, &plain_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    // Make returned value
    res = jni_set_byte_array(env, &result, plain, plain_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }
cleanup:
    if (NULL != nonce) {
        (*env)->ReleaseByteArrayElements(env, jnonce, (jbyte *)nonce, JNI_ABORT);
    }

    if (NULL != cipher) {
        (*env)->ReleaseByteArrayElements(env, jcipher, (jbyte *)cipher, JNI_ABORT);
    }

    if (NULL != aad) {
        (*env)->ReleaseByteArrayElements(env, jaad, (jbyte *)aad, JNI_ABORT);
    }

    if (NULL != plain) {
        free(plain);
    }

    return result;
}

JNIEXPORT void JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_init(JNIEnv *env,
                                                                  jobject self,
                                                                  jbyteArray jkey)
{
    int res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    uint8_t *key = NULL;
    size_t key_sz = 0;

    if (NULL == self) {
        jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_NULL_POINTER);
        goto cleanup;
    }

    ctx = malloc(sizeof(*ctx));
    if (NULL == ctx) {
        jni_throw_jni_exception(env, AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY);
        goto cleanup;
    }

    aes_gcmsiv_init(ctx);

    res = jni_get_byte_array(env, jkey, &key, &key_sz);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    res = aes_gcmsiv_set_key(ctx, key, key_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    res = jni_set_ctx(env, self, ctx);
    if (0 != res) {
        jni_throw_jni_exception(env, res);
        goto cleanup;
    }

    ctx = NULL;
cleanup:
    if (NULL != key) {
        (*env)->ReleaseByteArrayElements(env, jkey, (jbyte *)key, JNI_ABORT);
    }

    if (NULL != ctx) {
        aes_gcmsiv_free(ctx);
        free(ctx);
    }

    return;
}

JNIEXPORT void JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_free(JNIEnv *env, jobject self)
{
    int res;
    struct aes_gcmsiv_ctx *ctx;

    if (NULL == self) {
        return;
    }

    res = jni_get_ctx(env, self, &ctx);
    if (0 != res) {
        return;
    }

    if (NULL == ctx) {
        return;
    }

    aes_gcmsiv_free(ctx);
    free(ctx);
    ctx = NULL;

    res = jni_set_ctx(env, self, ctx);
    if (0 != res) {
        return;
    }
}

/*
 * JNI utility functions
 */

int jni_get_byte_array(JNIEnv *env, jbyteArray bytes, uint8_t **array, size_t *array_sz)
{
    int ret = AES_GCMSIV_JNI_ERR;
    jbyte *tmp = NULL;

    *array = NULL;
    *array_sz = 0;

    if (NULL == bytes) {
        ret = AES_GCMSIV_JNI_SUCCESS;
        goto cleanup;
    }

    tmp = (*env)->GetByteArrayElements(env, bytes, NULL);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        ret = AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

    *array = (uint8_t *)tmp;
    *array_sz = (*env)->GetArrayLength(env, bytes);
    tmp = NULL;

    ret = AES_GCMSIV_JNI_SUCCESS;
cleanup:
    if (NULL != tmp) {
        (*env)->ReleaseByteArrayElements(env, bytes, (jbyte *)tmp, JNI_ABORT);
    }

    return ret;
}

int jni_set_byte_array(JNIEnv *env, jbyteArray *bytes, const uint8_t *data, size_t data_sz)
{
    int ret = AES_GCMSIV_JNI_ERR;
    jbyteArray tmp = NULL;

    tmp = (*env)->NewByteArray(env, data_sz);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        ret = AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (data_sz > 0) {
        (*env)->SetByteArrayRegion(env, tmp, 0, data_sz, (jbyte *)data);
    }

    *bytes = tmp;
    tmp = NULL;

    ret = AES_GCMSIV_JNI_SUCCESS;
cleanup:
    if (NULL != tmp) {
        (*env)->DeleteLocalRef(env, tmp);
    }

    return ret;
}

void jni_throw_aesgcmsiv_exception(JNIEnv *env, aes_gcmsiv_status_t status)
{
    const char *name = NULL;
    const char *msg = "";
    jclass cls = NULL;

    switch (status) {
    case AES_GCMSIV_OUT_OF_MEMORY:
        name = JAVA_OUT_OF_MEMORY_EXCEPTION;
        break;
    case AES_GCMSIV_INVALID_TAG:
        name = JAVA_AEAD_BAD_TAG_EXCEPTION;
        break;
    case AES_GCMSIV_INVALID_PARAMETERS:
    case AES_GCMSIV_INVALID_KEY_SIZE:
    case AES_GCMSIV_INVALID_NONCE_SIZE:
    case AES_GCMSIV_INVALID_PLAINTEXT_SIZE:
    case AES_GCMSIV_INVALID_AAD_SIZE:
    case AES_GCMSIV_INVALID_CIPHERTEXT_SIZE:
        name = JAVA_ILLEGAL_ARGUMENT_EXCEPTION;
        break;
    default:
        name = JAVA_EXCEPTION;
        break;
    }

    msg = aes_gcmsiv_get_status_code_msg(status);

    cls = (*env)->FindClass(env, name);
    if (!(*env)->ExceptionCheck(env)) {
        (*env)->ThrowNew(env, cls, msg);
    }
}

void jni_throw_jni_exception(JNIEnv *env, int code)
{
    const char *name = NULL;
    const char *msg = "";
    jclass cls = NULL;

    switch (code) {
    case AES_GCMSIV_JNI_ERR_NULL_POINTER:
        name = JAVA_NULL_POINTER_EXCEPTION;
        msg = "null";
        break;
    case AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY:
        name = JAVA_OUT_OF_MEMORY_EXCEPTION;
        msg = "Cannot allocate enough memory";
        break;
    default:
        name = JAVA_EXCEPTION;
        msg = "";
        break;
    }

    cls = (*env)->FindClass(env, name);
    if (!(*env)->ExceptionCheck(env)) {
        (*env)->ThrowNew(env, cls, msg);
    }
}

int jni_get_ctx(JNIEnv *env, jobject self, struct aes_gcmsiv_ctx **ctx)
{
    int ret = AES_GCMSIV_JNI_ERR;
    int res;
    jfieldID fid = NULL;

    res = jni_get_ctx_jfieldID(env, self, &fid);
    if (0 != res) {
        ret = res;
        goto cleanup;
    }

    *ctx = (struct aes_gcmsiv_ctx *)(*env)->GetLongField(env, self, fid);

    ret = AES_GCMSIV_JNI_SUCCESS;
cleanup:
    return ret;
}

int jni_set_ctx(JNIEnv *env, jobject self, struct aes_gcmsiv_ctx *ctx)
{
    int ret = AES_GCMSIV_JNI_ERR;
    int res;
    jfieldID fid = NULL;

    res = jni_get_ctx_jfieldID(env, self, &fid);
    if (0 != res) {
        ret = res;
        goto cleanup;
    }

    (*env)->SetLongField(env, self, fid, (jlong)ctx);

    ret = AES_GCMSIV_JNI_SUCCESS;
cleanup:
    return ret;
}

int jni_get_ctx_jfieldID(JNIEnv *env, jobject self, jfieldID *fid)
{
    int ret = AES_GCMSIV_JNI_ERR;
    static jfieldID ctx_id = NULL;
    jclass cls;

    if (NULL == ctx_id) {
        cls = (*env)->GetObjectClass(env, self);

        ctx_id = (*env)->GetFieldID(env, cls, "aes_gcmsiv_ctx", "J");
        if ((*env)->ExceptionCheck(env)) {
            ctx_id = NULL;
            (*env)->ExceptionClear(env);
            ret = AES_GCMSIV_JNI_ERR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    *fid = ctx_id;

    ret = AES_GCMSIV_JNI_SUCCESS;
cleanup:
    return ret;
}
