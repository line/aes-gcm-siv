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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Random;

final class ResourceLoader {
    private final static String TMP_DIR_PREFIX = "aesgcmsiv_jni";
    private final static String JNI_BASE_DIR = "jni/";
    private static File tmpDir = null;
    private static File archDir = null;

    public static void loadLibraryFromJar(String name) throws IOException {
        File tmpLib = extractJarResource(name);
        System.load(tmpLib.getAbsolutePath());
    }

    private static File extractJarResource(String name) throws IOException {
        String libName = getLibNameByOs(name);

        // Get source file path
        File archDir = getArchDirectory();
        File jarFile = new File(archDir, libName);

        // Get temporary destination path
        File tmpDir = getTmpDirectory();
        File tmpFile = new File(tmpDir, libName);

        // Copy library to temporary directory
        if (tmpFile.getParentFile().exists() == false && !tmpFile.mkdirs()) {
            throw new FileSystemException("Failed to create path " + tmpFile.getAbsolutePath());
        }

        Files.copy(loadJarResource(jarFile.toString()), tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        tmpFile.deleteOnExit();

        return tmpFile;
    }

    private synchronized static File getTmpDirectory() throws IOException {
        if (ResourceLoader.tmpDir != null) {
            return ResourceLoader.tmpDir;
        }

        String dirBase = System.getProperty("java.io.tmpdir");
        Random unsecureRandom = new Random(System.currentTimeMillis());

        // Get unique temporary directory
        while (ResourceLoader.tmpDir == null) {
            String dirName = TMP_DIR_PREFIX + '-' + Long.toHexString(unsecureRandom.nextLong());
            ResourceLoader.tmpDir = new File(dirBase, dirName);

            if (ResourceLoader.tmpDir.exists()) {
                ResourceLoader.tmpDir = null;
            }
        }

        // Create directory
        if (!ResourceLoader.tmpDir.mkdir()) {
            ResourceLoader.tmpDir = null;
            throw new IOException("No permission to create temporary directory");
        }
        ResourceLoader.tmpDir.deleteOnExit();

        return ResourceLoader.tmpDir;
    }

    private synchronized static File getArchDirectory() throws RuntimeException {
        if (ResourceLoader.archDir != null) {
            return ResourceLoader.archDir;
        }

        String arch = System.getProperty("os.arch").toLowerCase();

        // Get normalized arch directory
        if (arch.matches("^(x86_64|amd64|x64|x86-64)$")) {
            ResourceLoader.archDir = new File(JNI_BASE_DIR, "x86_64");
        } else if (arch.matches("^(x86|i386|ia-32|i686)$")) {
            ResourceLoader.archDir = new File(JNI_BASE_DIR, "x86");
        } else if (arch.matches("^(aarch64|arm64|arm-v8)$")) {
            ResourceLoader.archDir = new File(JNI_BASE_DIR, "arm64");
        } else if (arch.matches("^(arm|arm-v7|armv7|arm32)$")) {
            ResourceLoader.archDir = new File(JNI_BASE_DIR, "arm");
        } else {
            throw new RuntimeException("Unsupported CPU architecture: " + arch);
        }

        return ResourceLoader.archDir;
    }

    private static String getLibNameByOs(String base) throws RuntimeException {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.startsWith("linux")) {
            return "lib" + base + ".so";
        } else if (os.startsWith("mac")) {
            return "lib" + base + ".dylib";
        } else if (os.startsWith("windows")) {
            return base + ".dll";
        }

        throw new RuntimeException("Unsupported runtime environment: " + os);
    }

    private static InputStream loadJarResource(String resource) throws IOException {
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        if (is == null) {
            throw new FileNotFoundException(resource + " not found in JAR");
        }

        return is;
    }
}
