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

#ifndef AES_GCMSIV_H
#define AES_GCMSIV_H

/**
 * @file
 * @brief                   AES-GCM-SIV header
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// GCM-SIV constants
#define AES_GCMSIV_NONCE_SIZE         12
#define AES_GCMSIV_TAG_SIZE           16
#define AES_GCMSIV_MAX_PLAINTEXT_SIZE (UINT64_C(1) << 36)
#define AES_GCMSIV_MAX_AAD_SIZE       (UINT64_C(1) << 36)

/** AES-GCM-SIV status codes
 * Status codes returned by the AES-GCM-SIV library.
 */
typedef enum {
    AES_GCMSIV_SUCCESS = 0,                 /**< Success. */
    AES_GCMSIV_FAILURE = 1,                 /**< Unknown failure. */
    AES_GCMSIV_OUT_OF_MEMORY = 2,           /**< System ran out of memory. */
    AES_GCMSIV_UPDATE_OUTPUT_SIZE = 3,      /**< Output buffer size is not sufficient. */
    AES_GCMSIV_INVALID_PARAMETERS = 4,      /**< Input parameters are invalid. */
    AES_GCMSIV_INVALID_KEY_SIZE = 5,        /**< Key size is invalid. */
    AES_GCMSIV_INVALID_NONCE_SIZE = 6,      /**< Nonce size is invalid. */
    AES_GCMSIV_INVALID_PLAINTEXT_SIZE = 7,  /**< Plaintext size is invalid. */
    AES_GCMSIV_INVALID_AAD_SIZE = 8,        /**< Additional authenticated data size is invalid. */
    AES_GCMSIV_INVALID_CIPHERTEXT_SIZE = 9, /**< Ciphertext size is invalid. */
    AES_GCMSIV_INVALID_TAG = 10,            /**< Authentication tag cannot match provided data. */
} aes_gcmsiv_status_t;

struct aes_gcmsiv_ctx {
    void *key_gen_ctx;
    size_t key_sz;
};

/**
 * @brief                   Return the size of a AES-GCM-SIV context.
 *
 * @return                  The needed size in bytes of a AES-GCM-SIV context structure.
 */
size_t aes_gcmsiv_context_size(void);

/**
 * @brief                   Initialize a AES-GCM-SIV context.
 *
 * Initialize the context to be well-defined before any other usage.
 * It ensures that any further function manipulating the context has a defined behaviour.
 * This function IS NOT thread-safe.
 *
 * @param[in]  ctx          The AES-GCM-SIV context to initialize.
 *                          If \p ctx is \p NULL, the function does not perform anything.
 *                          This function needs to be called before any other utilization.
 *                          It ensures that \p aes_gcmsiv_free can be called at any time following
 *                          this function call.
 */
void aes_gcmsiv_init(struct aes_gcmsiv_ctx *ctx);

/**
 * @brief                   Clear a AES-GCM-SIV context.
 *
 * Releases the resources allocated by the context.
 * The context MUST be initialized before calling this function.
 * This function IS NOT thread-safe.
 *
 * It is not safe to call this function from multiple threads, as it could lead to double-free
 * situations.
 *
 * @param[in]  ctx          The GCM-SIV context to clear (content is zeroized).
 *                          If \p ctx is \p NULL, the function does not perform anything.
 *                          If \p ctx is not \p NULL, it must be initialized.
 */
void aes_gcmsiv_free(struct aes_gcmsiv_ctx *ctx);

/**
 * @brief                   Setup a given key to a AES-GCM-SIV context.
 *
 * Setup the provided key to be used with encryption and decryption operations.
 * The context MUST be initialized before calling this function.
 * This function IS NOT thread-safe.
 *
 * Once a context is initialized and has its key setup, it can safely be shared between threads,
 * especially in regard to performing encryptions and decryptions.
 *
 * After
 *
 * @param[in]  ctx          The AES-GCM-SIV context to setup.
 *                          This must not be \p NULL and must be initialized.
 *                          It can already have been setup, in which case, the new key replace the
 *                          previous key (only if the new call succeed).
 * @param[in]  key          The AES key to use for encryption or decryption.
 *                          This must not be \p NULL, and it must consist of \p key_sz bytes.
 * @param[in]  key_sz       The key buffer size in bytes.
 *                          Valid key sizes are:
 *                          - 16 bytes to use AES-128
 *                          - 32 bytes to use AES-256
 *
 * @return                  \p AES_GCMSIV_SUCCESS on success.
 * @return                  A related \p aes_gcmsiv_status_t code otherwise.
 */
aes_gcmsiv_status_t aes_gcmsiv_set_key(struct aes_gcmsiv_ctx *ctx,
                                       const uint8_t *key,
                                       size_t key_sz);

/**
 * @brief                   Give the size needed to encrypt a plaintext with its additional data.
 *
 * @param[in]  plain_sz     The plaintext buffer size in bytes.
 *                          The maximum length is \p AES_GCMSIV_MAX_PLAINTEXT_SIZE (2^36), as
 *                          specified in the standard.
 * @param[in]  aad_sz       The additional data buffer size in bytes.
 *                          The maximum length is \p AES_GCMSIV_MAX_AAD_SIZE (2^36), as specified
 *                          in the standard.
 * @param[out] cipher_sz    The ciphertext buffer size in bytes.
 *                          This must not be \p NULL.
 *
 * @return                  \p AES_GCMSIV_SUCCESS on success.
 * @return                  A related \p aes_gcmsiv_status_t code otherwise.
 */
aes_gcmsiv_status_t aes_gcmsiv_encrypt_size(size_t plain_sz, size_t aad_sz, size_t *cipher_sz);

/**
 * @brief                   Encrypt and authenticate data with AES-GCM-SIV mode.
 *
 * Encrypt and authenticate data.
 * The context MUST be initialized before calling this function, and have a key setup.
 * This function is thread-safe.
 *
 * @param[in]  ctx          The AES-GCM-SIV context containing the key material.
 *                          This must not be \p NULL and must be initialized.
 * @param[in]  nonce        The nonce used to randomize inner encryption and authentication.
 *                          This must not be \p NULL, and must consist of \p nonce_sz bytes.
 * @param[in]  nonce_sz     The nonce buffer size in bytes.
 *                          It must be \p AES_GCMSIV_NONCE_SIZE bytes (which is \p 12, according
 *                          to the standard).
 * @param[in]  plain        The plaintext data to encrypt.
 *                          It can be \p NULL.
 *                          If \p plain is not \p NULL, it must consist of \p plain_sz bytes.
 * @param[in]  plain_sz     The plaintext buffer size in bytes.
 *                          If \p plain is \p NULL, the value must be \p 0.
 *                          The maximum length is \p AES_GCMSIV_MAX_PLAINTEXT_SIZE (2^36), as
 *                          specified in the standard.
 * @param[in]  aad          The additional data to authenticate, but not to encrypt.
 *                          It can be \p NULL.
 *                          If \p aad is not \p NULL, it must consist of \p aad_sz bytes.
 * @param[in]  aad_sz       The additional data buffer size in bytes.
 *                          If \p aad is \p NULL, the value must be \p 0.
 *                          The maximum length is \p AES_GCMSIV_MAX_AAD_SIZE (2^36), as specified
 *                          in the standard.
 * @param[out] cipher       The ciphertext data.
 *                          It contains the encrypted data (if any), and the authentication tag
 *                          (but not the additional data).
 *                          It can be \p NULL only if \p cipher_sz is 0.
 *                          If \p cipher is not \p NULL, it must consist of \p cipher_sz bytes.
 *                          If \p plain and \p cipher overlap, it is <b>Undefined Behaviour</b>.
 * @param[in] cipher_sz     The ciphertext buffer size in bytes.
 *                          It must consist of the number of writable bytes of \p cipher.
 *                          If the value is smaller than the actual needed size to write all the
 *                          output, the function returns \p AES_GCMSIV_UPDATE_OUTPUT_SIZE, and the
 *                          parameter \p write_sz is updated with the needed size to succeed the
 *                          encryption.
 *                          The function needs to be called a second time with the proper data size
 *                          to perform actual encryption.
 * @param[out] write_sz     The amount of bytes written in the \p cipher buffer.
 *                          This must not be \p NULL.
 *                          If the encryption process is performed and successul, it is updated with
 *                          the actual number of usefull bytes in \p cipher.
 *                          If \p cipher does not contain enough bytes (as specified by
 *                          \p cipher_sz), the function returns \p AES_GCMSIV_UPDATE_OUTPUT_SIZE and
 *                          this parameter is updated with the minimum amount of bytes needed to
 *                          perform the encryption.
 *
 * @return                  \p AES_GCMSIV_SUCCESS on success.
 * @return                  \p AES_GCMSIV_UPDATE_OUTPUT_SIZE when \p cipher_sz is not large enough.
 *                          \p write_sz is then updated with the needed size.
 * @return                  A related \p aes_gcmsiv_status_t code otherwise.
 */
aes_gcmsiv_status_t aes_gcmsiv_encrypt_with_tag(struct aes_gcmsiv_ctx *ctx,
                                                const uint8_t *nonce,
                                                size_t nonce_sz,
                                                const uint8_t *plain,
                                                size_t plain_sz,
                                                const uint8_t *aad,
                                                size_t aad_sz,
                                                uint8_t *cipher,
                                                size_t cipher_sz,
                                                size_t *write_sz);

/**
 * @brief                   Give the size needed to decrypt a ciphertext with its additional data.
 *
 * @param[in]  cipher_sz    The ciphertext buffer size in bytes.
 *                          It must be at least \p AES_GCMSIV_TAG_SIZE bytes (which is \p 16).
 *                          The maximum length is the maximum length of a plaintext and the length
 *                          of the authentication tag (which is 2^36 + 16 bytes).
 * @param[in]  aad_sz       The additional data buffer size in bytes.
 *                          The maximum length is \p AES_GCMSIV_MAX_AAD_SIZE (2^36), as specified
 *                          in the standard.
 * @param[out] plain_sz     The plaintext buffer size in bytes.
 *                          This must not be \p NULL.
 *
 * @return                  \p AES_GCMSIV_SUCCESS on success.
 * @return                  A related \p aes_gcmsiv_status_t code otherwise.
 */
aes_gcmsiv_status_t aes_gcmsiv_decrypt_size(size_t cipher_sz, size_t aad_sz, size_t *plain_sz);

/**
 * @brief                   Decrypt and check authenticity of data with AES-GCM-SIV node.
 *
 * Decrypt and check authentcity of data.
 * The context MUST be initialized before calling this function, and have a key setup.
 * This function is thread-safe.
 *
 * @param[in]  ctx          The AES-GCM-SIV context containing the key material.
 *                          This must not be \p NULL and must be initialized.
 * @param[in]  nonce        The nonce used to randomize inner decryption and authentication.
 *                          This must not be \p NULL, and must consist of \p nonce_sz bytes.
 * @param[in]  nonce_sz     The nonce buffer size in bytes.
 *                          It must be \p AES_GCMSIV_NONCE_SIZE bytes (which is \p 12, according
 *                          to the standard).
 * @param[in]  cipher       The ciphertext data to decrypt.
 *                          It cannot be \p NULL.
 *                          It should contain the encrypted data (if any), and the authenticated tag
 *                          (but not the additional data).
 * @param[in]  cipher_sz    The ciphertext buffer size in bytes.
 *                          It must be at least \p AES_GCMSIV_TAG_SIZE bytes (which is \p 16).
 *                          The maximum length is the maximum length of a plaintext and the length
 *                          of the authentication tag (which is 2^36 + 16 bytes).
 * @param[in]  aad          The authenticated additional data used during encryption.
 *                          It can be \p NULL.
 *                          If \p aad is not \p NULL, it must consist of \p aad_sz bytes.
 * @param[in]  aad_sz       The additional data buffer size in bytes.
 *                          If \p aad is \p NULL, the value must be \p 0.
 *                          The maximum length is \p AES_GCMSIV_MAX_AAD_SIZE (2^36), as specified
 *                          in the standard.
 * @param[out] plain        The plaintext data.
 *                          It contains the plaintext data if the encryption could be performed
 *                          properly, and the tag matches the authenticated data and the decrypted
 *                          text.
 *                          It can be \p NULL only if \p plain_sz is 0.
 *                          If \p plain is not \p NULL, it must consist of \p plain_sz bytes.
 *                          If \p plain and \p cipher overlap, it is <b>Undefined Behaviour</b>.
 * @param[out] plain_sz     The plaintext buffer size in bytes.
 *                          It must consist of the number of writable bytes of \p plain.
 *                          If the value is smaller than the actual needed size to write all the
 *                          output, the function returns \p AES_GCMSIV_UPDATE_OUTPUT_SIZE, and the
 *                          parameter \p write_sz is updated with the needed size to succeed the
 *                          decryption.
 *                          The function needs to be called a second time with the proper data size
 *                          to perform actual decryption.
 * @param[out] write_sz     The amount of bytes written in the \p plain buffer.
 *                          This must not be \p NULL.
 *                          If the decryption process is performed and successul, it is updated with
 *                          the actual number of usefull bytes in \p plain.
 *                          If \p plain does not contain enough bytes (as specified by \p plain_sz),
 *                          the function returns \p AES_GCMSIV_UPDATE_OUTPUT_SIZE and this parameter
 *                          is updated with the minimum amount of bytes needed to perform the
 *                          decryption.
 *
 * @return                  \p AES_GCMSIV_SUCCESS on success.
 * @return                  \p AES_GCMSIV_UPDATE_OUTPUT_SIZE when \p plain_sz is not large enough.
 *                          \p write_sz is then updated with the needed size.
 * @return                  \p AES_GCMSIV_INVALID_TAG if the data cannot be authenticated.
 *                          In this case, ciphertext or authenticated data has been corrupted and
 *                          cannot be used.
 * @return                  A related \p aes_gcmsiv_status_t code otherwise.
 */
aes_gcmsiv_status_t aes_gcmsiv_decrypt_and_check(struct aes_gcmsiv_ctx *ctx,
                                                 const uint8_t *nonce,
                                                 size_t nonce_sz,
                                                 const uint8_t *cipher,
                                                 size_t cipher_sz,
                                                 const uint8_t *aad,
                                                 size_t aad_sz,
                                                 uint8_t *plain,
                                                 size_t plain_sz,
                                                 size_t *write_sz);

/**
 * @brief                   Get a human-readable message regarding a status code.
 *
 * @param[in] status        Status code for which we try to get the message.
 *
 * @return                  A static string pointing to the human-readable
 *                          message of the provided \p status parameter.
 */
const char *aes_gcmsiv_get_status_code_msg(aes_gcmsiv_status_t status);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_GCMSIV_H */
