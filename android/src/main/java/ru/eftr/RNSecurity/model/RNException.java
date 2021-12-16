package ru.eftr.RNSecurity.model;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

public class RNException extends Exception {
    public ErrorCode code = ErrorCode.NONE;
    public String message;
    public String subCode;

    public RNException(ErrorCode code) {
        this.code = code;
    }

    public RNException(ErrorCode code, String message) {
        this(code, message, "0");
    }

    public RNException(ErrorCode code, String message, String subCode) {
        this.code = code;
        this.message = message;
        this.subCode = subCode;
    }
}
