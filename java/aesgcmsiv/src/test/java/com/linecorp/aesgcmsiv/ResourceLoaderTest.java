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
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Paths;

public class ResourceLoaderTest {
    private static final String TMP_DIR_PROPERTY = "com.linecorp.aesgcmsiv.tmpdir";

    private String originalTmpDirectory;

    @Before
    public void backupEnvironment() {
        originalTmpDirectory = System.getProperty(TMP_DIR_PROPERTY);
    }

    @After
    public void restoreEnvironment() {
        if (originalTmpDirectory == null) {
            System.clearProperty(TMP_DIR_PROPERTY);
        } else {
            System.setProperty(TMP_DIR_PROPERTY, originalTmpDirectory);
        }
    }

    @Test
    public void customTmpDirectoryTakesPrecedence() {
        System.setProperty(TMP_DIR_PROPERTY, "/custom/aesgcmsiv/tmp");

        Assert.assertEquals(
                Paths.get("/custom/aesgcmsiv/tmp"),
                ResourceLoader.getTmpDirectory());
    }

    @Test
    public void javaTmpDirectoryIsTheDefault() {
        System.clearProperty(TMP_DIR_PROPERTY);

        Assert.assertEquals(
                Paths.get(System.getProperty("java.io.tmpdir")),
                ResourceLoader.getTmpDirectory());
    }

    @Test
    public void blankCustomTmpDirectoryUsesTheDefault() {
        System.setProperty(TMP_DIR_PROPERTY, "   ");

        Assert.assertEquals(
                Paths.get(System.getProperty("java.io.tmpdir")),
                ResourceLoader.getTmpDirectory());
    }
}
