package eu.interopehrate.md2dsm.api;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

public class MyKeyChainAliasCallback implements KeyChainAliasCallback {
    byte[] mData;

    Context mContext;
    String mAlias = "";

    byte[] mSignedData;
    boolean mVerifiedData;

    PrivateKey mPrivateKey = null;
    Signature mSignature = null;
    PublicKey mPublicKey = null;


    public MyKeyChainAliasCallback(byte[] data, Context context) {
        this.mData = data;
        this.mContext = context;
    }

    public MyKeyChainAliasCallback(Context context) {
        this.mContext = context;
    }

    @Override
    public void alias(String alias) {

        mAlias=alias;

        // To be replaced
        //API call 3: signPayload
        try {
            mSignedData = signPayload(mData);
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        // To be replaced
        //API call 11: verifySignature
        try {
            mVerifiedData = verifySignature(mSignedData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (KeyChainException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }

    public byte[] signPayload(byte[] data) throws KeyChainException, InterruptedException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signed = new byte[0];

        mPrivateKey = KeyChain.getPrivateKey(mContext, mAlias);
        mSignature = Signature.getInstance("SHA256withRSA");
        mSignature.initSign(mPrivateKey);
        mSignature.update(data);
        signed = mSignature.sign();

        String signedData = Base64.encodeToString(data,
                Base64.NO_WRAP | Base64.NO_PADDING)
                + "]" + Base64.encodeToString(signed,
                Base64.NO_WRAP | Base64.NO_PADDING);
        Log.i("Signed Data",signedData);

        Log.i("Selected Alias",mAlias);

        return signed;
    }

    public boolean verifySignature(byte[] signedData) throws NoSuchAlgorithmException,
            KeyChainException, InterruptedException, InvalidKeyException, SignatureException {

        X509Certificate[] chain = KeyChain.getCertificateChain(mContext, mAlias);
        mPublicKey = chain[0].getPublicKey();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(mPublicKey);
        signature.update(mData);

        Log.i("Verify signature", String.valueOf(signature.verify(signedData)));
        return signature.verify(signedData);
    }
}
