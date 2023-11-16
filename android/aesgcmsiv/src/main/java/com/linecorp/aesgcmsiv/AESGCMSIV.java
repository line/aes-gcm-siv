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

package com.linecorp.aesgcmsiv;

import javax.crypto.AEADBadTagException;

public final class AESGCMSIV {
    /**
     * Size for AES-GCM-SIV nonce
     */
    public static final int NONCE_SIZE = 12;
    public static final int TAG_SIZE = 16;

    /**
     * Load the shared library
     */
    static {
        System.loadLibrary("aesgcmsiv_jni");
    }

    /**
     * Pointer to native AES-GCM-SIV context
     */
    private long aes_gcmsiv_ctx;

    /**
     * Create a AES-GCM-SIV cipher for a specified key.
     *
     * @param key the AES key, whose length can be 128 or 256 bits (16 or 32 bytes respectively).
     *            AES-GCM-SIV does not support AES with a key of 192 bits.
     * @throws IllegalArgumentException if the input parameter does not have a valid size
     */
    public AESGCMSIV(byte[] key) throws IllegalArgumentException {
        aes_gcmsiv_ctx = 0;
        init(key);
    }

    public void finalize() {
        free();
    }

    /**
     * Encrypt plaintext, and authenticate this plaintext and additional data.
     *
     * @param nonce          the random (but not secret) nonce to use for this encryption.
     *                       It must be 96-bit long (12 bytes).
     * @param plaintext      the data to be encrypted and authenticated.
     *                       It can be null or empty if there is no data to encrypt, but only additional data to authenticate.
     *                       Maximum size is 2^36 bytes.
     * @param additionalData the additional data to be only authenticated only.
     *                       It can be null or empty if there is no additional data to authenticate.
     *                       Maximum size is 2^36 bytes.
     * @return the ciphertext of the plaintext, which embed as well the authentication tag for the plaintext and the additional data.
     *         It does not embed the nonce or additional data if any.
     * @throws IllegalArgumentException if any of the input parameters don't have a valid size
     */
    public native byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] additionalData)
            throws IllegalArgumentException;

    /**
     * @param nonce          the random (but not secret) nonce used during the encryption.
     *                       It must be 96-bit long (12 bytes).
     * @param ciphertext     the data to be decrypted.
     *                       It must have a minimum size of 16-bytes, which is the size of the authentication tag.
     * @param additionalData the additional data that was authenticated during encryption.
     *                       It can be null or empty if there was no additional data authenticated.
     * @return the plaintext corresponding to the ciphertext provided.
     *         It can be an empty array if no data was encrypted, but only additional data were authenticated.
     * @throws IllegalArgumentException if any of the input parameters don't have a valid size
     * @throws AEADBadTagException      if the embedded authentication tag in the ciphertext does not match the
     *                                  authentication tag of the plaintext and the additional data
     */
    public native byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] additionalData)
            throws IllegalArgumentException, AEADBadTagException;

    private native void init(byte[] key) throws IllegalArgumentException;

    private native void free();
}
