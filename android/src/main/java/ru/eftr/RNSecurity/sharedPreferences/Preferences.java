package ru.eftr.RNSecurity.sharedPreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class Preferences {
    private static SharedPreferences pref;
    private static Preferences instance = null;

    private Preferences(Context context) {
        pref = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public static Preferences instance(Context context) {
        if (instance == null) {
            synchronized (Preferences.class) {
                if (instance == null) {
                    instance = new Preferences(context);
                }
            }
        }
        return instance;
    }

    public Object getParamPref(String key, Object value) {
        try {
            if (pref.contains(key)) {
                if (value instanceof String) {
                    return pref.getString(key, "");
                } else if (value instanceof Long) {
                    return pref.getLong(key, (Long) value);
                } else if (value instanceof Integer) {
                    return pref.getInt(key, (Integer) value);
                } else if (value instanceof Boolean) {
                    return pref.getBoolean(key, (Boolean) value);
                } else if (value instanceof Float) {
                    return pref.getFloat(key, (Float) value);
                }

            }
        } catch (ClassCastException ex) {
            ;
        }
        return value;
    }

    public void setParamPref(String key, Object value) {
        SharedPreferences.Editor editor = pref.edit();

        if (value == null)
            editor.remove(key);
        else if (value instanceof String) {
            editor.putString(key, (String) value);
        } else if (value instanceof Integer) {
            editor.putInt(key, (Integer) value);
        } else if (value instanceof Boolean) {
            editor.putBoolean(key, (Boolean) value);
        } else if (value instanceof Float) {
            editor.putFloat(key, (Float) value);
        }
        editor.commit();
    }

    public <T> Object getParamObjPref(String key, Class<T> clazz) {
        Object result = null;
        String json = (String) getParamPref(key, "");

        if (!json.equals("")) {
            result = JSONHelper.fromJsonText(json, clazz);
        }
        return result;
    }

    public void setParamObjPref(String key, Object value) {
        if (value == null)
            setParamPref(key, value);
        String json = JSONHelper.createJsonText(value);
        setParamPref(key, json);
    }
}
