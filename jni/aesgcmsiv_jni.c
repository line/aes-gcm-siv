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

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes_gcmsiv.h"

static int jbyteArray_new(
    JNIEnv *env, size_t size, jbyteArray *array, uint8_t **ptr, const char *name);
static int jbyteArray_get(
    JNIEnv *env, jbyteArray array, const uint8_t **ptr, size_t *size, const char *name);
static int jbyteArray_shrink(JNIEnv *env, jbyteArray *array, size_t size, const char *name);

static inline void jni_throw_exception(JNIEnv *env, const char *name, const char *msg);
static inline void jni_throw_nullpointer_exception(JNIEnv *env, const char *msg);
static inline void jni_throw_outofmemory_exception(JNIEnv *env, const char *msg);
static inline void jni_throw_aesgcmsiv_exception(JNIEnv *env, aes_gcmsiv_status_t status);

JNIEXPORT jlong JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_initNative(JNIEnv *env,
                                                                         jclass cls,
                                                                         jbyteArray key)
{
    jlong result = 0;
    aes_gcmsiv_status_t res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    const uint8_t *key_ptr = NULL;
    size_t key_sz = 0;
    ((void)cls);

    // Convert input parameters to C types
    res = jbyteArray_get(env, key, &key_ptr, &key_sz, "key");
    if (JNI_OK != res) {
        goto cleanup;
    }

    // Allocate AES-GCM-SIV context
    ctx = malloc(sizeof(*ctx));
    if (NULL == ctx) {
        jni_throw_outofmemory_exception(env, "ctx");
        goto cleanup;
    }

    // Initialize and setup AES-GCM-SIV context
    aes_gcmsiv_init(ctx);

    res = aes_gcmsiv_set_key(ctx, key_ptr, key_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        aes_gcmsiv_free(ctx);
        free(ctx);

        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    result = (jlong)ctx;
cleanup:
    if (NULL != key_ptr) {
        (*env)->ReleaseByteArrayElements(env, key, (jbyte *)key_ptr, JNI_ABORT);
    }

    return result;
}

JNIEXPORT void JNICALL Java_com_linecorp_aesgcmsiv_AESGCMSIV_freeNative(JNIEnv *env,
                                                                        jclass cls,
                                                                        jlong aesGcmSivContext)
{
    struct aes_gcmsiv_ctx *ctx = (struct aes_gcmsiv_ctx *)aesGcmSivContext;
    ((void)env);
    ((void)cls);

    if (NULL == ctx) {
        return;
    }

    aes_gcmsiv_free(ctx);
    free(ctx);
}

JNIEXPORT jbyteArray JNICALL
Java_com_linecorp_aesgcmsiv_AESGCMSIV_encryptNative(JNIEnv *env,
                                                    jclass cls,
                                                    jlong aesGcmSivContext,
                                                    jbyteArray nonce,
                                                    jbyteArray plaintext,
                                                    jbyteArray additionalData)
{
    jbyteArray result = NULL;
    jbyteArray ciphertext = NULL;
    aes_gcmsiv_status_t res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    const uint8_t *nonce_ptr = NULL;
    size_t nonce_sz = 0;
    const uint8_t *plain_ptr = NULL;
    size_t plain_sz = 0;
    const uint8_t *aad_ptr = NULL;
    size_t aad_sz = 0;
    uint8_t *cipher_ptr = NULL;
    size_t cipher_sz = 0;
    size_t write_sz = 0;
    ((void)cls);

    // Convert input parameters to C types
    ctx = (struct aes_gcmsiv_ctx *)aesGcmSivContext;
    if (NULL == ctx) {
        jni_throw_nullpointer_exception(env, "aesGcmSivContext");
        goto cleanup;
    }

    res = jbyteArray_get(env, nonce, &nonce_ptr, &nonce_sz, "nonce");
    if (JNI_OK != res) {
        goto cleanup;
    }

    res = jbyteArray_get(env, plaintext, &plain_ptr, &plain_sz, "plaintext");
    if (JNI_OK != res) {
        goto cleanup;
    }

    res = jbyteArray_get(env, additionalData, &aad_ptr, &aad_sz, "additionalData");
    if (JNI_OK != res) {
        goto cleanup;
    }

    // Get needed output size
    res = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    if (cipher_sz > (size_t)INT_MAX) {
        jni_throw_aesgcmsiv_exception(env, AES_GCMSIV_INVALID_PLAINTEXT_SIZE);
        goto cleanup;
    }

    // Allocate resources
    res = jbyteArray_new(env, cipher_sz, &ciphertext, &cipher_ptr, "ciphertext");
    if (JNI_OK != res) {
        goto cleanup;
    }

    // Perform actual encryption
    res = aes_gcmsiv_encrypt_with_tag(ctx, nonce_ptr, nonce_sz, plain_ptr, plain_sz, aad_ptr,
                                      aad_sz, cipher_ptr, cipher_sz, &write_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    (*env)->ReleaseByteArrayElements(env, ciphertext, (jbyte *)cipher_ptr, 0);
    cipher_ptr = NULL;

    // Check if we actually wrote as many bytes as announced
    if (write_sz < cipher_sz) {
        res = jbyteArray_shrink(env, &ciphertext, write_sz, "ciphertext");
        if (JNI_OK != res) {
            goto cleanup;
        }
    }

    result = ciphertext;
    ciphertext = NULL;
cleanup:
    if (NULL != nonce_ptr) {
        (*env)->ReleaseByteArrayElements(env, nonce, (jbyte *)nonce_ptr, JNI_ABORT);
    }
    if (NULL != plain_ptr) {
        (*env)->ReleaseByteArrayElements(env, plaintext, (jbyte *)plain_ptr, JNI_ABORT);
    }
    if (NULL != aad_ptr) {
        (*env)->ReleaseByteArrayElements(env, additionalData, (jbyte *)aad_ptr, JNI_ABORT);
    }
    if (NULL != cipher_ptr) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, (jbyte *)cipher_ptr, JNI_ABORT);
    }

    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_linecorp_aesgcmsiv_AESGCMSIV_decryptNative(JNIEnv *env,
                                                    jclass cls,
                                                    jlong aesGcmSivContext,
                                                    jbyteArray nonce,
                                                    jbyteArray ciphertext,
                                                    jbyteArray additionalData)
{
    jbyteArray result = NULL;
    jbyteArray plaintext = NULL;
    aes_gcmsiv_status_t res;
    struct aes_gcmsiv_ctx *ctx = NULL;
    const uint8_t *nonce_ptr = NULL;
    size_t nonce_sz = 0;
    const uint8_t *cipher_ptr = NULL;
    size_t cipher_sz = 0;
    const uint8_t *aad_ptr = NULL;
    size_t aad_sz = 0;
    uint8_t *plain_ptr = NULL;
    size_t plain_sz = 0;
    size_t write_sz = 0;
    ((void)cls);

    // Convert input parameters to C types
    ctx = (struct aes_gcmsiv_ctx *)aesGcmSivContext;
    if (NULL == ctx) {
        jni_throw_nullpointer_exception(env, "aesGcmSivContext");
        goto cleanup;
    }

    res = jbyteArray_get(env, nonce, &nonce_ptr, &nonce_sz, "nonce");
    if (JNI_OK != res) {
        goto cleanup;
    }

    res = jbyteArray_get(env, ciphertext, &cipher_ptr, &cipher_sz, "ciphertext");
    if (JNI_OK != res) {
        goto cleanup;
    }

    res = jbyteArray_get(env, additionalData, &aad_ptr, &aad_sz, "additionalData");
    if (JNI_OK != res) {
        goto cleanup;
    }

    // Get needed output size
    res = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    if (plain_sz > (size_t)INT_MAX) {
        jni_throw_aesgcmsiv_exception(env, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);
        goto cleanup;
    }

    // Allocate resources
    res = jbyteArray_new(env, plain_sz, &plaintext, &plain_ptr, "plaintext");
    if (JNI_OK != res) {
        goto cleanup;
    }

    // Perform actual decryption
    res = aes_gcmsiv_decrypt_and_check(ctx, nonce_ptr, nonce_sz, cipher_ptr, cipher_sz, aad_ptr,
                                       aad_sz, plain_ptr, plain_sz, &write_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        jni_throw_aesgcmsiv_exception(env, res);
        goto cleanup;
    }

    (*env)->ReleaseByteArrayElements(env, plaintext, (jbyte *)plain_ptr, 0);
    plain_ptr = NULL;

    // Check if we actually wrote as many bytes as announced
    if (write_sz < plain_sz) {
        res = jbyteArray_shrink(env, &plaintext, write_sz, "ciphertext");
        if (JNI_OK != res) {
            goto cleanup;
        }
    }

    result = plaintext;
cleanup:
    if (NULL != nonce_ptr) {
        (*env)->ReleaseByteArrayElements(env, nonce, (jbyte *)nonce_ptr, JNI_ABORT);
    }
    if (NULL != cipher_ptr) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, (jbyte *)cipher_ptr, JNI_ABORT);
    }
    if (NULL != aad_ptr) {
        (*env)->ReleaseByteArrayElements(env, additionalData, (jbyte *)aad_ptr, JNI_ABORT);
    }
    if (NULL != plain_ptr) {
        (*env)->ReleaseByteArrayElements(env, plaintext, (jbyte *)plain_ptr, JNI_ABORT);
    }

    return result;
}

int jbyteArray_new(JNIEnv *env, size_t size, jbyteArray *array, uint8_t **ptr, const char *name)
{
    jbyteArray tmp = (*env)->NewByteArray(env, size);
    if (NULL == tmp) {
        jni_throw_outofmemory_exception(env, name);
        return JNI_ERR;
    }

    jbyte *tmp_ptr = (*env)->GetByteArrayElements(env, tmp, NULL);
    if (NULL == tmp_ptr) {
        jni_throw_outofmemory_exception(env, name);
        return JNI_ERR;
    }

    *array = tmp;
    *ptr = (uint8_t *)tmp_ptr;

    return JNI_OK;
}

int jbyteArray_get(
    JNIEnv *env, jbyteArray array, const uint8_t **ptr, size_t *size, const char *name)
{
    if (NULL == array) {
        *ptr = NULL;
        *size = 0;

        return JNI_OK;
    }

    size_t array_sz = (*env)->GetArrayLength(env, array);

    jbyte *array_ptr = (*env)->GetByteArrayElements(env, array, NULL);
    if (NULL == array_ptr) {
        jni_throw_outofmemory_exception(env, name);
        return JNI_ERR;
    }

    *ptr = (const uint8_t *)array_ptr;
    *size = array_sz;

    return JNI_OK;
}

int jbyteArray_shrink(JNIEnv *env, jbyteArray *array, size_t size, const char *name)
{
    int ret = JNI_ERR;

    // Create new array
    jbyteArray new_array = (*env)->NewByteArray(env, size);
    if (NULL == new_array) {
        jni_throw_outofmemory_exception(env, name);
        goto cleanup;
    }

    // Get pointer to old array
    jbyte *array_ptr = (*env)->GetByteArrayElements(env, *array, NULL);
    if (NULL == array_ptr) {
        jni_throw_outofmemory_exception(env, name);
        goto cleanup;
    }

    // Copy old array to new array
    (*env)->SetByteArrayRegion(env, new_array, 0, size, array_ptr);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    // Release old array and assign new one
    (*env)->ReleaseByteArrayElements(env, *array, array_ptr, JNI_ABORT);
    *array = new_array;
    new_array = NULL;

    ret = JNI_OK;
cleanup:
    if (NULL != new_array) {
        (*env)->DeleteLocalRef(env, new_array);
    }

    return ret;
}

void jni_throw_exception(JNIEnv *env, const char *name, const char *msg)
{
    // Check for pending exceptions
    if ((*env)->ExceptionCheck(env)) {
        return;
    }

    // Find class, if not found, an exception is raised
    jclass cls = (*env)->FindClass(env, name);
    if (NULL == cls) {
        return;
    }

    // Throw exception
    (*env)->ThrowNew(env, cls, msg);
}

void jni_throw_nullpointer_exception(JNIEnv *env, const char *msg)
{
    jni_throw_exception(env, "java/lang/NullPointerException", msg);
}

void jni_throw_outofmemory_exception(JNIEnv *env, const char *msg)
{
    jni_throw_exception(env, "java/lang/OutOfMemoryError", msg);
}

void jni_throw_aesgcmsiv_exception(JNIEnv *env, aes_gcmsiv_status_t status)
{
    const char *msg = aes_gcmsiv_get_status_code_msg(status);

    switch (status) {
    case AES_GCMSIV_OUT_OF_MEMORY:
        return jni_throw_exception(env, "java/lang/OutOfMemoryError", msg);
    case AES_GCMSIV_UPDATE_OUTPUT_SIZE:
    case AES_GCMSIV_INVALID_PARAMETERS:
    case AES_GCMSIV_INVALID_KEY_SIZE:
    case AES_GCMSIV_INVALID_NONCE_SIZE:
    case AES_GCMSIV_INVALID_PLAINTEXT_SIZE:
    case AES_GCMSIV_INVALID_AAD_SIZE:
    case AES_GCMSIV_INVALID_CIPHERTEXT_SIZE:
        return jni_throw_exception(env, "java/lang/IllegalArgumentException", msg);
    case AES_GCMSIV_INVALID_TAG:
        return jni_throw_exception(env, "javax/crypto/AEADBadTagException", msg);
    default:
        return jni_throw_exception(env, "java/lang/Exception", msg);
    }
}
