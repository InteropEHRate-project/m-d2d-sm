/*
 * Author: UBITECH
 * Project: InteropEHRate - www.interopehrate.eu
 * Description: Consent API
 */
package eu.interopehrate.md2dsm.s_ehr_a;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import eu.interopehrate.md2dsm.api.MyKeyChainAliasCallback;
import eu.interopehrate.md2dsm.api.Utils;

public class MainActivity extends AppCompatActivity {
    SharedPreferences pref;


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @SuppressLint("WrongThread")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //API call 2: createPayload
        byte[] payload = Utils.createPayload("Data to be signed");

        // Call it only the first time - Initialization to get chosen alias
        //API call 1: fetchCertificate |  signPayload | verifySignature
        Utils.fetchCertificate(this,getApplicationContext(), payload);


        //API call 3: signPayload
        // keyChainAliasCallback.signPayload(data);






        /*
        pref = PreferenceManager.getDefaultSharedPreferences(this);
        pref.edit().putString(PREFS_NAME, String.valueOf(false)).apply();

        // By defalt consent is false
        Consent consent = new Consent(0, false, getBaseContext(), pref);

        consent.giveConsent();
        consent.sentConsent();
        consent.recallConsent();
        consent.sentConsent();*/
    }


}
