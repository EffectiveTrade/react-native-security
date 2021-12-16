package ru.eftr.RNSecurity.SecurityV2;

import android.content.Context;

import ru.eftr.RNSecurity.sharedPreferences.Preferences;

public class DataHelperV2 {
    private static final String PACKAGE_NAME = "SecurityV2.";

    public static void clean(Context context) {
        cleanUnlockAttempts(context);
        cleanCreds(context);
        cleanCode(context);
        cleanBiometryValue(context);

        setCheckHash(context, null);
        setFingerPrintSecret(context, null);

    }

    public static boolean isEmpty(Context context) {
        return get(context, "unlock_attempts", null) == null
                && get(context, "creds", null) == null
                && get(context, "code", null) == null
                && get(context, "biometry_value", null) == null;
    }

    // UnlockAttempts

    public static void addUnlockAttempts(Context context) {
        set(context, "unlock_attempts", getUnlockAttempts(context) + 1);
    }

    public static int getUnlockAttempts(Context context) {
        return (Integer) get(context, "unlock_attempts", 0);
    }

    public static void cleanUnlockAttempts(Context context) {
        set(context, "unlock_attempts", null);
    }

    // Creds

    public static void setCreds(Context context, String value) {
        set(context, "creds", value);
    }

    public static String getCreds(Context context) {
        return (String) get(context, "creds", null);
    }

    public static void cleanCreds(Context context) {
        set(context, "creds", null);
    }

    // Code

    public static void setCode(Context context, String value) {
        set(context, "code", value);
    }

    public static String getCode(Context context) {
        return (String) get(context, "code", null);
    }

    public static void cleanCode(Context context) {
        set(context, "code", null);
    }

    // BiometryValue

    public static void setBiometryValue(Context context, String value) {
        set(context, "biometry_value", value);
    }

    public static String getBiometryValue(Context context) {
        return (String) get(context, "biometry_value", null);
    }

    public static void cleanBiometryValue(Context context) {
        set(context, "biometry_value", null);
    }


    // FingerPrintSecret

    public static void setFingerPrintSecret(Context context, String value) {
        set(context, "fingerprint_secret", value);
    }

    public static String getFingerPrintSecret(Context context) {
        return (String) get(context, "fingerprint_secret", "");
    }

    // CheckHash

    public static void setCheckHash(Context context, String value) {
        set(context, "check_hash", value);
    }

    public static String getCheckHash(Context context) {
        return ((String) get(context, "check_hash", "")).replace("\n", "").replace("\r", "");
    }

    // Common

    private static void set(Context context, String key, Object value) {
        Preferences.instance(context).setParamPref(PACKAGE_NAME + key, value);
    }

    private static <T> Object get(Context context, String key, Object defValue) {
        return Preferences.instance(context).getParamPref(PACKAGE_NAME + key, defValue);
    }
}
