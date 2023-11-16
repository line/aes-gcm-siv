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

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;

@RunWith(AndroidJUnit4.class)
public class AESGCMSIVExample {
    @Test
    public void exampleAesGcmSiv128() throws Exception {
        SecureRandom secureRandom = new SecureRandom();

        // Generate a random 128-bits key
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);

        // Instantiate AES-GCM-SIV context with the key
        AESGCMSIV ctx = new AESGCMSIV(key);

        // Generate a unique nonce per message
        byte[] nonce = new byte[AESGCMSIV.NONCE_SIZE];
        secureRandom.nextBytes(nonce);

        // Setup authenticated data and plaintext
        byte[] aad = "Authenticated but not encrypted data".getBytes();
        byte[] plain = "Encrypted and authenticated data".getBytes();

        // Encrypt plaintext and compute authentication tag
        byte[] cipher = ctx.encrypt(nonce, plain, aad);

        // Decrypt ciphertext and check authenticity
        byte[] decrypt = ctx.decrypt(nonce, cipher, aad);

        // Check that the two messages are equals
        Assert.assertArrayEquals(plain, decrypt);
    }

    @Test
    public void exampleAesGcmSiv256() throws Exception {
        SecureRandom secureRandom = new SecureRandom();

        // Generate a random 256-bits key
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

        // Instantiate AES-GCM-SIV context with the key
        AESGCMSIV ctx = new AESGCMSIV(key);

        // Generate a unique nonce per message
        byte[] nonce = new byte[AESGCMSIV.NONCE_SIZE];
        secureRandom.nextBytes(nonce);

        // Setup authenticated data and plaintext
        byte[] aad = "Authenticated but not encrypted data".getBytes();
        byte[] plain = "Encrypted and authenticated data".getBytes();

        // Encrypt plaintext and compute authentication tag
        byte[] cipher = ctx.encrypt(nonce, plain, aad);

        // Decrypt ciphertext and check authenticity
        byte[] decrypt = ctx.decrypt(nonce, cipher, aad);

        // Check that the two messages are equals
        Assert.assertArrayEquals(plain, decrypt);
    }
}
