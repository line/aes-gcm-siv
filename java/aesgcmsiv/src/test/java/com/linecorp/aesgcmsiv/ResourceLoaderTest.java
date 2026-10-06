/*
 * Copyright 2026 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
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

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Permission;
import java.util.Arrays;
import java.util.PropertyPermission;

public class ResourceLoaderTest {
    private static final String TMP_DIR_PROPERTY = "com.linecorp.aesgcmsiv.tmpdir";

    private String originalTmpDirectory;
    private SecurityManager originalSecurityManager;
    private Path testDirectory;

    @Before
    public void backupEnvironment() throws IOException {
        originalTmpDirectory = System.getProperty(TMP_DIR_PROPERTY);
        originalSecurityManager = System.getSecurityManager();
        testDirectory = Files.createTempDirectory("aesgcmsiv-test-");
    }

    @After
    public void restoreEnvironment() throws IOException {
        if (System.getSecurityManager() != originalSecurityManager) {
            System.setSecurityManager(originalSecurityManager);
        }

        if (originalTmpDirectory == null) {
            System.clearProperty(TMP_DIR_PROPERTY);
        } else {
            System.setProperty(TMP_DIR_PROPERTY, originalTmpDirectory);
        }

        Files.deleteIfExists(testDirectory);
    }

    @Test
    public void customTmpDirectoryTakesPrecedence() throws IOException {
        System.setProperty(TMP_DIR_PROPERTY, testDirectory.toString());
        assertTmpDirectoryCreatedIn(testDirectory);
    }

    @Test
    public void missingOrBlankCustomTmpDirectoryUsesTheDefault() throws IOException {
        assertDefaultForMissingOrBlankProperty();
    }

    @Test
    public void defaultDoesNotRequireJavaTmpdirPermission() throws IOException {
        denyPropertyReads("java.io.tmpdir");
        assertDefaultForMissingOrBlankProperty();
    }

    @Test
    public void unreadableCustomTmpDirectoryUsesTheDefault() throws IOException {
        System.setProperty(TMP_DIR_PROPERTY, testDirectory.toString());
        denyPropertyReads("java.io.tmpdir", TMP_DIR_PROPERTY);

        assertTmpDirectoryCreatedIn(testDirectory.getParent());
    }

    private void assertDefaultForMissingOrBlankProperty() throws IOException {
        System.clearProperty(TMP_DIR_PROPERTY);
        assertTmpDirectoryCreatedIn(testDirectory.getParent());

        for (String value : new String[]{"", " \t\n "}) {
            System.setProperty(TMP_DIR_PROPERTY, value);
            assertTmpDirectoryCreatedIn(testDirectory.getParent());
        }
    }

    private static void assertTmpDirectoryCreatedIn(Path parent) throws IOException {
        Path directory = ResourceLoader.createTmpDirectory();

        try {
            Assert.assertEquals(parent, directory.getParent());
        } finally {
            Files.delete(directory);
        }
    }

    private static void denyPropertyReads(String... properties) {
        try {
            System.setSecurityManager(new SecurityManager() {
                @Override
                public void checkPermission(Permission permission) {
                    if (permission instanceof PropertyPermission
                            && "read".equals(permission.getActions())
                            && Arrays.asList(properties).contains(permission.getName())) {
                        throw new SecurityException("Property read denied: " + permission.getName());
                    }
                }
            });
        } catch (UnsupportedOperationException e) {
            // Newer JDKs disable SecurityManager, but we're testing with Java 11.
            Assume.assumeNoException(e);
        }
    }
}
