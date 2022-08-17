package eu.ubitech.sehra.s_ehr_a;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;

import eu.ubitech.sehra.securitylibrary.Consent;

public class MainActivity extends AppCompatActivity {
    private static final String PREFS_NAME = "consent";
    SharedPreferences pref;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        pref = PreferenceManager.getDefaultSharedPreferences(this);
        pref.edit().putString(PREFS_NAME, String.valueOf(false)).apply();

        // By defalt consent is false
        Consent consent = new Consent(0, false, getBaseContext(), pref);

        consent.giveConsent();
        consent.sentConsent();
        consent.recallConsent();
        consent.sentConsent();
    }
}
