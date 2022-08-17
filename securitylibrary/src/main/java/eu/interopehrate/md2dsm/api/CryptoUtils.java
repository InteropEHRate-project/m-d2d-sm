/*
 * Author: UBITECH
 * Project: InteropEHRate - www.interopehrate.eu
 * Description: Necessary Crypto Utils
 */

package eu.interopehrate.md2dsm.api;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;


public class CryptoUtils {

    private static final String TAG = "Crypto Operations";
    private String alias = "myKey";

    /*
     * Load the Android KeyStore instance using the
     * "" provider
     */
    private static Enumeration<String> loadKeystore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Enumeration<String> aliases = ks.aliases();
        return aliases;
    }

    /*
     * Generate a new EC key pair entry in the Android Keystore by
     * using the KeyPairGenerator API. The private key can only be
     * used for signing or verification and only with SHA-256 or
     * SHA-512 as the message digest.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        KeyPair kp = kpg.generateKeyPair();
        return kpg.generateKeyPair();
    }

    /*
     * Use a PrivateKey in the KeyStore to create a signature over
     * some data.
     */
    public byte[] signData(byte[] data) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, InvalidKeyException,
            SignatureException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        s.update(data);
        byte[] signature = s.sign();
        //String str = new String(signature, "UTF-8");
        return signature;
    }

    /*
     * Verify a signature previously made by a PrivateKey in our
     * KeyStore. This uses the X.509 certificate attached to our
     * private key in the KeyStore to validate a previously
     * generated signature.
     */
    public boolean verifySignedData(byte[] data, byte[] signature) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            InvalidKeyException, SignatureException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        boolean valid = s.verify(signature);
        return valid;
    }

}
