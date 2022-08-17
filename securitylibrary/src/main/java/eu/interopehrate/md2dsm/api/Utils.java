package eu.interopehrate.md2dsm.api;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class Utils {
    private static final String KEYSTORE_ANDROID = "AndroidKeyStore";

    private static Utils instance;
    private static final String KEYCHAIN_ID = "keychain 1";

    private Utils() {
    }

    /**
     * Returns the singleton instance.
     */
    public static synchronized Utils getInstance() {
        if (instance == null) {
            instance = new Utils();
        }
        return instance;
    }

    /**
     * Creates a storage context that is protected by device-specific credentials.
     *
     * <p>This method only has an effect on API levels 24 and above.
     */
    Context getDeviceProtectedStorageContext(Context context) {
        if (VERSION.SDK_INT >= VERSION_CODES.N) {
            return context.createDeviceProtectedStorageContext();
        }
        return context;
    }


    /**
     * Checks if the device screen lock is enabled. Returns the status as a boolean.
     */
    private boolean isScreenLockEnabled(Context context) {
        KeyguardManager keyguardManager =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        assert keyguardManager != null;
        if (VERSION.SDK_INT >= VERSION_CODES.M) {
            return keyguardManager.isDeviceSecure();
        }
        return keyguardManager.isKeyguardSecure();
    }

    /**
     * Checks if the device is locked. Returns the status as a boolean.
     */
    boolean isScreenLocked(Context context) {
        KeyguardManager keyguardManager =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        assert keyguardManager != null;
        if (VERSION.SDK_INT >= VERSION_CODES.M) {
            return keyguardManager.isDeviceLocked();
        }
        return keyguardManager.isKeyguardLocked();
    }

    public static KeyStore loadKeyStore() throws GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
        try {
            keyStore.load(null);
        } catch (IOException e) {
            throw new GeneralSecurityException("unable to load keystore", e);
        }
        return keyStore;
    }


    /**
     * API
     */
    //API call 1: fetchCertificate
    public static void fetchCertificate(Activity activity, Context context, byte[] payload) {
        MyKeyChainAliasCallback keyChainAliasCallback;

        // Function the choose the certificate to used for the app
        KeyChain.choosePrivateKeyAlias(activity,
                keyChainAliasCallback = new MyKeyChainAliasCallback(payload, context),
                new String[] {}, // Any key types.
                null, // Any issuers.
                "localhost", // Any host
                -1, // Any port
                "");
    }

    //API call 2: createPayload
    public static byte[] createPayload(String data) {
        return new String(data).getBytes();
    }


}
