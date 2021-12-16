package ru.eftr.RNSecurity.sharedPreferences;

import com.google.gson.Gson;

public class JSONHelper {

    static public String createJsonText(Object obj) {
        Gson gson = new Gson();
        return gson.toJson(obj);
    }

    static public <T> Object fromJsonText(String jText, Class<T> clazz) {
        Gson gson = new Gson();
        return gson.fromJson(jText, clazz);
    }
}
