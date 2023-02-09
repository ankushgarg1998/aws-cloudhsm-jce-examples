/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

/**
 * KeyStoreExampleRunner demonstrates how to load a keystore, get a key entry, sign and store a
 * certificate with the key and list all aliases on the keystore.
 *
 * <p>This example relies on implicit credentials, so you must setup your environment correctly.
 *
 * <p>https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class KeyStoreExampleRunner {

    private static final String helpString =
            "KeyStoreExampleRunner\n"
                + "This sample demonstrates how to load and store keys using a keystore.\n\n"
                + "Options\n"
                + "\t--help\t\t\tDisplay this message.\n"
                + "\t--store <filename>\t\tPath of the keystore.\n"
                + "\t--password <password>\t\tPassword for the keystore (not your CU password).\n"
                + "\t--label <label>\t\t\tLabel to store the key and certificate under.\n"
                + "\t--list\t\t\tList all the keys in the keystore.\n\n";

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (final IOException ex) {
            System.out.println(ex);
            return;
        }

        String keystoreFile = null;
        String password = null;
        String labelArg = null;
        boolean list = false;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (args[i]) {
                case "--store":
                    keystoreFile = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--label":
                    labelArg = args[++i];
                    break;
                case "--list":
                    list = true;
                    break;
                case "--help":
                    help();
                    return;
            }
        }

        if (null == keystoreFile || null == password) {
            help();
            return;
        }

        if (list) {
            listKeys(keystoreFile, password);
            return;
        }

        final String entryLabel = "entryLabel";

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE);
//        try {
//            final FileInputStream instream = new FileInputStream(keystoreFile);
//            // This call to keyStore.load() will open the CloudHSM keystore file with the supplied
//            // password.
//            keyStore.load(instream, password.toCharArray());
//        } catch (final FileNotFoundException ex) {
//            System.err.println("Keystore not found, loading an empty store");
//            keyStore.load(null, null);
//        }

//        final PasswordProtection passwordProtection = new PasswordProtection(password.toCharArray());
//
//        System.out.println("Searching for example key");
//        if (!keyStore.containsAlias(entryLabel)) {
//            System.out.println("No entry found for '" + entryLabel + "', creating a secretKey...");
//            final KeyAttributesMap keyAttributesMap = new KeyAttributesMapBuilder()
//                    .put(KeyAttribute.ENCRYPT, true)
//                    .put(KeyAttribute.DECRYPT, true)
//                    .build();
//            final Key aesKey = SymmetricKeys.generateAESKey(256, entryLabel, keyAttributesMap);
//            final KeyStore.SecretKeyEntry aesKeyEntry = new KeyStore.SecretKeyEntry((SecretKey) aesKey);
//
//            keyStore.setEntry(entryLabel, aesKeyEntry, passwordProtection);
//
//            final FileOutputStream outstream = new FileOutputStream(keystoreFile);
//            keyStore.store(outstream, password.toCharArray());
//            outstream.close();
//            System.out.println("Keystore saved");
//        }

        SecretKey secretKey = (SecretKey) keyStore.getKey(entryLabel, null);
        System.out.println(secretKey.getAlgorithm());
    }

    private static void help() {
        System.out.println(helpString);
    }

    /** List all the keys in the keystore. */
    private static void listKeys(final String keystoreFile, final String password)
            throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);

        try {
            final FileInputStream inputStream = new FileInputStream(keystoreFile);
            keyStore.load(inputStream, password.toCharArray());
        } catch (final FileNotFoundException ex) {
            System.err.println("Keystore not found, creating an empty store.");
            keyStore.load(null, null);
        }

        for (final Enumeration<String> entry = keyStore.aliases(); entry.hasMoreElements(); ) {
            System.out.println(entry.nextElement());
        }
    }

    /** Generate a certificate signed by a given keypair. */
    private static Certificate createAndSignCertificate(final KeyPair keyPair)
            throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException,
                    SignatureException, InvalidKeyException, OperatorCreationException {
        final X500Name x500Name =
                new X500Name("C=US, ST=Washington, L=Seattle, O=Amazon, OU=AWS, CN=CloudHSM");

        // Serial number should be unique per CA
        final long serialNumberValue = System.currentTimeMillis() % Long.MAX_VALUE;
        final BigInteger serialNumber = BigInteger.valueOf(serialNumberValue);
        final Calendar calendar = Calendar.getInstance();

        final String keyAlgorithm = keyPair.getPrivate().getAlgorithm();
        final SubjectPublicKeyInfo publicKeyInfo =
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final X500Name issuer = x500Name;
        final X500Name subject = x500Name;
        final Date notValidUntil = calendar.getTime();
        final Date notValidAfter = notValidUntil;
        final X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(
                        issuer, serialNumber, notValidUntil, notValidAfter, subject, publicKeyInfo);

        final String signatureAlgorithm;
        if (keyAlgorithm.equalsIgnoreCase("RSA")) {
            signatureAlgorithm = "SHA512WithRSA";
        } else {
            throw new IllegalArgumentException(
                    "KeyAlgorithm should be RSA, but found " + keyAlgorithm);
        }

        final ContentSigner signer =
                new JcaContentSignerBuilder(signatureAlgorithm)
                        .setProvider(CloudHsmProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate());
        final X509CertificateHolder certificateHolder = builder.build(signer);
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(certificateHolder);
    }
}
