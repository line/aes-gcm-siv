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
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

final class ResourceLoader {
    private static final String JNI_BASE_DIR = "jni";
    private static final String TMP_DIR_PREFIX = "aesgcmsiv_jni-";
    private static volatile File libFile;

    public static void loadLibraryFromJar(String lib) throws IOException {
        if (libFile == null) {
            synchronized (ResourceLoader.class) {
                if (libFile == null) {
                    libFile = extractLibraryFromJar(lib);
                    System.load(libFile.getAbsolutePath());
                }
            }
        }
    }

    private static File extractLibraryFromJar(String lib) throws IOException {
        String libName = getLibNameByOs(lib);

        // Get library file in JAR
        String libPath = getLibPathByArch(libName);
        InputStream libStream = getResourceAsStream(libPath);

        // Create temporary directory
        File tmpDir = Files.createTempDirectory(TMP_DIR_PREFIX).toFile();
        tmpDir.deleteOnExit();

        // Copy library to temporary directory
        File tmpFile = new File(tmpDir, libName);
        tmpFile.deleteOnExit();

        Files.copy(libStream, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        return tmpFile;
    }

    private static String getLibNameByOs(String lib) throws RuntimeException {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.startsWith("linux")) {
            return "lib" + lib + ".so";
        } else if (os.startsWith("mac")) {
            return "lib" + lib + ".dylib";
        } else if (os.startsWith("windows")) {
            return lib + ".dll";
        }

        throw new RuntimeException("Unsupported OS environment: " + os);
    }

    private static String getLibPathByArch(String libName) throws RuntimeException {
        String arch = System.getProperty("os.arch").toLowerCase();

        if (arch.matches("^(x86_64|amd64|x64|x86-64)$")) {
            return JNI_BASE_DIR + "/x86_64/" + libName;
        } else if (arch.matches("^(x86|i386|ia-32|i686)$")) {
            return JNI_BASE_DIR + "/x86/" + libName;
        } else if (arch.matches("^(aarch64|arm64|arm-v8)$")) {
            return JNI_BASE_DIR + "/arm64/" + libName;
        } else if (arch.matches("^(arm|arm-v7|armv7|arm32)$")) {
            return JNI_BASE_DIR + "/arm/" + libName;
        }

        throw new RuntimeException("Unsupported CPU architecture: " + arch);
    }

    private static InputStream getResourceAsStream(String resource) throws IOException {
        ClassLoader loader;
        InputStream stream;

        // Context ClassLoader
        loader = Thread.currentThread().getContextClassLoader();
        stream = (loader != null) ? loader.getResourceAsStream(resource) : null;
        if (stream != null) {
            return stream;
        }

        // Fallback on class ClassLoader
        loader = ResourceLoader.class.getClassLoader();
        stream = (loader != null) ? loader.getResourceAsStream(resource) : null;
        if (stream != null) {
            return stream;
        }

        throw new FileNotFoundException("Resource not found in JAR: " + resource);
    }
}
