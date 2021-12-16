package ru.eftr.RNSecurity.sharedPreferences;

import android.content.Context;

public class DataHelper {

    public static void clean(Context context) {
        setLoginPass(context, null);
        setCheckHash(context, null);
        setFingerptintSecret(context, null);
        cleatFingerPrintAttempts(context);
        cleatPinCodeAttempts(context);
    }

    public static void addFingerPrintAttempt(Context context) {
        set(context, "fingerprint_attempts", getFingerPrintAttempt(context) + 1);
    }

    public static int getFingerPrintAttempt(Context context) {
        return (Integer) get(context, "fingerprint_attempts", 0);
    }

    public static void cleatFingerPrintAttempts(Context context) {
        set(context, "fingerprint_attempts", 0);
    }

    public static void addPinCodeAttempt(Context context) {
        set(context, "pincode_attempts", getPinCodeAttempt(context) + 1);
    }

    public static int getPinCodeAttempt(Context context) {
        return (Integer) get(context, "pincode_attempts", 0);
    }

    public static void cleatPinCodeAttempts(Context context) {
        set(context, "pincode_attempts", 0);
    }

    public static void setFingerptintSecret(Context context, String value) {
        set(context, "fingerprint_secret", value);
    }

    public static String getFingerptintSecret(Context context) {
        return (String) get(context, "fingerprint_secret", "");
    }

    public static void setLoginPass(Context context, String value) {
        set(context, "login_pass", value);
    }

    public static String getLoginPass(Context context) {
        return (String) get(context, "login_pass", "");
    }

    public static void setCheckHash(Context context, String value) {
        set(context, "check_hash", value);
    }

    public static String getCheckHash(Context context) {
        return ((String) get(context, "check_hash", "")).replace("\n", "").replace("\r", "");
    }

    public static void setCipherIV(Context context, String value) {
        set(context, "touchid_cipherIV", value);
    }

    public static String getCipherIV(Context context) {
        return (String) get(context, "touchid_cipherIV", "");
    }

    private static final String PACKAGE_NAME = "ru.eftr.";

    private static void setObject(Context context, String key, Object value) {
        Preferences.instance(context).setParamObjPref(PACKAGE_NAME + key, value);
    }

    private static <T> Object getObject(Context context, String key, Class<T> clazz) {
        return Preferences.instance(context).getParamObjPref(PACKAGE_NAME + key, clazz);
    }

    private static void set(Context context, String key, Object value) {
        Preferences.instance(context).setParamPref(PACKAGE_NAME + key, value);
    }

    private static <T> Object get(Context context, String key, Object defValue) {
        return Preferences.instance(context).getParamPref(PACKAGE_NAME + key, defValue);
    }
}
