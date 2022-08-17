/*
 * Author: UBITECH
 * Project: InteropEHRate - www.interopehrate.eu
 * Description: Consent API
 */
package eu.interopehrate.md2dsm.api;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import android.widget.Toast;

public class Consent {
    private static final String PREFS_NAME = "consent";

    Integer consentId;
    Boolean consVerdict;
    SharedPreferences mSettings;
    private Context context;

    public Consent(Integer consentId, Boolean consVerdict, Context context, SharedPreferences mSettings) {
        this.consentId = consentId;
        this.consVerdict = consVerdict;
        this.context = context;
        this.mSettings = mSettings;
    }

    public static void s(Context c, String message) {

        Toast.makeText(c, message, Toast.LENGTH_SHORT).show();

    }

    public int giveConsent() {
        if (consentId.equals(null)) {
            this.consentId = 0;
        }
        this.consVerdict = true;
        this.consentId++;

        mSettings.edit().putString(PREFS_NAME, String.valueOf(true)).apply();
        Log.d(PREFS_NAME, "giveConsent");
        return this.consentId;
    }

    public void recallConsent() {
        this.consVerdict = false;
        SharedPreferences.Editor editor = mSettings.edit();
        editor.putString(PREFS_NAME, String.valueOf(false));
        editor.commit();
        Log.d(PREFS_NAME, "recallConsent");
    }

    public Consent sentConsent() {
        Consent consent = new Consent(this.consentId, this.consVerdict, context, mSettings);
        String data = mSettings.getString(PREFS_NAME, null);
        Log.d(PREFS_NAME, data.toString());
        return consent;
    }

    @Override
    public String toString() {
        return "Consent{" +
                "consentId=" + consentId +
                ", consVerdict=" + consVerdict +
                '}';
    }
}
