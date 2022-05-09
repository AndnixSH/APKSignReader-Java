/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksigner;

import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.MinSdkVersionException;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Command-line tool for signing APKs and for checking whether an APK's signature are expected to
 * verify on Android devices.
 */
public class ApkSignerTool {

    private static MessageDigest sha256 = null;
    private static MessageDigest sha1 = null;
    private static MessageDigest md5 = null;

    public static void main(String[] params) throws Exception {
        if ((params.length == 0) || ("--help".equals(params[0])) || ("-h".equals(params[0]))) {
            System.out.println("Please input the APK file");
            return;
        }

        // BEGIN-AOSP
        addProviders();
        // END-AOSP
        System.out.println("Reading APK, please wait...");
        verify(Arrays.copyOfRange(params, 0, params.length));
    }

    // BEGIN-AOSP

    /**
     * Adds additional security providers to add support for signature algorithms not covered by
     * the default providers.
     */
    private static void addProviders() {
        try {
            Security.addProvider(new org.conscrypt.OpenSSLProvider());
        } catch (UnsatisfiedLinkError e) {
            // This is expected if the library path does not include the native conscrypt library;
            // the default providers support all but PSS algorithms.
        }
    }
    // END-AOSP


    private static void verify(String[] params) throws Exception {
        File inputApk = null;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        boolean maxSdkVersionSpecified = false;
        boolean printCerts = false;
        boolean verbose = false;
        boolean warningsTreatedAsErrors = false;
        boolean verifySourceStamp = false;
        File v4SignatureFile = null;
        OptionsParser optionsParser = new OptionsParser(params);
        String optionOriginalForm = null;
        String sourceCertDigest = null;

        printCerts = optionsParser.getOptionalBooleanValue(true);

        params = optionsParser.getRemainingParams();

        if (inputApk != null) {
            // Input APK has been specified in preceding parameters. We don't expect any more
            // parameters.
            if (params.length > 0) {
                throw new ParameterException(
                        "Unexpected parameter(s) after " + optionOriginalForm + ": " + params[0]);
            }
        } else {
            // Input APK has not been specified in preceding parameters. The next parameter is
            // supposed to be the input APK.
            if (params.length < 1) {
                throw new ParameterException("Missing APK");
            } else if (params.length > 1) {
                throw new ParameterException(
                        "Unexpected parameter(s) after APK (" + params[1] + ")");
            }
            inputApk = new File(params[0]);
        }

        if ((minSdkVersionSpecified) && (maxSdkVersionSpecified)
                && (minSdkVersion > maxSdkVersion)) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion
                            + ")");
        }

        ApkVerifier.Builder apkVerifierBuilder = new ApkVerifier.Builder(inputApk);
        if (minSdkVersionSpecified) {
            apkVerifierBuilder.setMinCheckedPlatformVersion(minSdkVersion);
        }
        if (maxSdkVersionSpecified) {
            apkVerifierBuilder.setMaxCheckedPlatformVersion(maxSdkVersion);
        }
        if (v4SignatureFile != null) {
            if (!v4SignatureFile.exists()) {
                throw new ParameterException("V4 signature file does not exist: "
                        + v4SignatureFile.getCanonicalPath());
            }
            apkVerifierBuilder.setV4SignatureFile(v4SignatureFile);
        }

        ApkVerifier apkVerifier = apkVerifierBuilder.build();
        ApkVerifier.Result result;
        try {
            result = verifySourceStamp
                    ? apkVerifier.verifySourceStamp(sourceCertDigest)
                    : apkVerifier.verify();
        } catch (MinSdkVersionException e) {
            String msg = e.getMessage();
            if (!msg.endsWith(".")) {
                msg += '.';
            }
            throw new MinSdkVersionException(
                    "Failed to determine APK's minimum supported platform version"
                            + ". Use --min-sdk-version to override",
                    e);
        }

        boolean verified = result.isVerified();
        ApkVerifier.Result.SourceStampInfo sourceStampInfo = result.getSourceStampInfo();
        boolean warningsEncountered = false;
        if (verified) {
            List<X509Certificate> signerCerts = result.getSignerCertificates();

            if (verbose) {
                System.out.println("Verifies");
                System.out.println(
                        "Verified using v1 scheme (JAR signing): "
                                + result.isVerifiedUsingV1Scheme());
                System.out.println(
                        "Verified using v2 scheme (APK Signature Scheme v2): "
                                + result.isVerifiedUsingV2Scheme());
                System.out.println(
                        "Verified using v3 scheme (APK Signature Scheme v3): "
                                + result.isVerifiedUsingV3Scheme());
                System.out.println(
                        "Verified using v4 scheme (APK Signature Scheme v4): "
                                + result.isVerifiedUsingV4Scheme());
                System.out.println("Verified for SourceStamp: " + result.isSourceStampVerified());
                if (!verifySourceStamp) {
                    System.out.println("Number of signers: " + signerCerts.size());
                }
            }

            if (printCerts) {
                int signerNumber = 0;
                for (X509Certificate signerCert : signerCerts) {
                    signerNumber++;
                    printCertificate(signerCert, "Signer #" + signerNumber, verbose);
                }
                if (sourceStampInfo != null) {
                    printCertificate(sourceStampInfo.getCertificate(), "Source Stamp Signer",
                            verbose);
                }
            }
        } else {
            System.err.println("DOES NOT VERIFY");
        }

        for (ApkVerifier.IssueWithParams error : result.getErrors()) {
            System.err.println("ERROR: " + error);
        }

        @SuppressWarnings("resource") // false positive -- this resource is not opened here
        PrintStream warningsOut = warningsTreatedAsErrors ? System.err : System.out;

        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
            String signerName = signer.getName();
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println("ERROR: JAR signer " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println("WARNING: JAR signer " + signerName + ": " + warning);
            }
        }
        for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println(
                        "ERROR: APK Signature Scheme v2 " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println(
                        "WARNING: APK Signature Scheme v2 " + signerName + ": " + warning);
            }
        }
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println(
                        "ERROR: APK Signature Scheme v3 " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println(
                        "WARNING: APK Signature Scheme v3 " + signerName + ": " + warning);
            }
        }

        if (sourceStampInfo != null) {
            for (ApkVerifier.IssueWithParams error : sourceStampInfo.getErrors()) {
                System.err.println("ERROR: SourceStamp: " + error);
            }
            for (ApkVerifier.IssueWithParams warning : sourceStampInfo.getWarnings()) {
                warningsOut.println("WARNING: SourceStamp: " + warning);
            }
        }

        if (!verified) {
            System.exit(1);
            return;
        }
        if ((warningsTreatedAsErrors) && (warningsEncountered)) {
            System.exit(1);
            return;
        }
    }

    /**
     * Prints details from the provided certificate to stdout.
     *
     * @param cert    the certificate to be displayed.
     * @param name    the name to be used to identify the certificate.
     * @param verbose boolean indicating whether public key details from the certificate should be
     *                displayed.
     * @throws NoSuchAlgorithmException     if an instance of MD5, SHA-1, or SHA-256 cannot be
     *                                      obtained.
     * @throws CertificateEncodingException if an error is encountered when encoding the
     *                                      certificate.
     */
    public static void printCertificate(X509Certificate cert, String name, boolean verbose)
            throws NoSuchAlgorithmException, CertificateEncodingException, IOException {

        if (cert == null) {
            throw new NullPointerException("cert == null");
        }
        if (sha256 == null || sha1 == null || md5 == null) {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha1 = MessageDigest.getInstance("SHA-1");
            md5 = MessageDigest.getInstance("MD5");
        }
        byte[] encodedCert = cert.getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.write(1);
        dos.writeInt(encodedCert.length);
        dos.write(encodedCert);

        StringBuilder sb = new StringBuilder();
        sb.append("std::vector<std::vector<uint8_t>> apk_signatures {");

            sb.append("{");

            for (int j = 0; j < encodedCert.length; j++) {
                sb.append(String.format("0x%02X", encodedCert[j]));
                if (j != encodedCert.length - 1) {
                    sb.append(",");
                }
            }
            sb.append("}");

        sb.append("};");

        System.out.println("-----------------------------------------------");

        System.out.println("Base64: \"" + Base64.getEncoder().encodeToString(baos.toByteArray()) + "\"");

        System.out.println("");

        System.out.println("C++: \"" + sb + "\"");

        System.out.println("-----------------------------------------------");

        System.out.println(name + " certificate DN: " + cert.getSubjectDN());

        System.out.println(name + " certificate SHA-256 digest: " + HexEncoding.encode(
                sha256.digest(encodedCert)));
        System.out.println(name + " certificate SHA-1 digest: " + HexEncoding.encode(
                sha1.digest(encodedCert)));
        System.out.println(
                name + " certificate MD5 digest: " + HexEncoding.encode(md5.digest(encodedCert)));

        System.out.println("-----------------------------------------------");
    }
}
