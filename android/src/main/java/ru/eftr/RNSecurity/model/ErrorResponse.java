package ru.eftr.RNSecurity.model;

import com.facebook.react.bridge.Promise;
import com.google.gson.Gson;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

public class ErrorResponse extends Object {
    private static Gson gson = new Gson();

    public String code;
    public String message;
    public String subCode;

    public ErrorResponse(String code) {
        this(code, "error", "0");
    }

    public ErrorResponse(String code, String message) {
        this(code, message, "0");
    }

    public ErrorResponse(String code, String message, String subCode) {
        this.code = code;
        this.message = message;
        this.subCode = subCode;
    }

    public ErrorResponse(ErrorCode code) {
        this(code, "error", "0");
    }

    public ErrorResponse(ErrorCode code, String message) {
        this(code, message, "0");
    }

    public ErrorResponse(ErrorCode code, String message, String subCode) {
        this(code.getCode(), message != null ? message : code.toString(), subCode);
    }

    public ErrorResponse(RNException ex) {
        this(ex.code, ex.message, ex.subCode);
    }

    public String toJson() {
        return gson.toJson(this);
    }

    public void reject(Promise promise) {
        promise.reject(this.code, this.toJson());
    }
}
