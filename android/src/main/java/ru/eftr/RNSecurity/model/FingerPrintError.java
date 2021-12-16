package ru.eftr.RNSecurity.model;

public enum FingerPrintError {
  USER_CANCEL(13, ErrorCode.FINGERPRINT_CANCELED),
  USER_BACK_PRESSED(10, ErrorCode.FINGERPRINT_CANCELED),
  UNKNOWN(-1, ErrorCode.FINGERPRINT_FAILED);

  private Integer androidErrorCode;
  public ErrorCode securityErrorCode;

  FingerPrintError(Integer androidErrorCode, ErrorCode sequrityErrorCode) {
    this.androidErrorCode = androidErrorCode;
    this.securityErrorCode = sequrityErrorCode;
  }

  static public FingerPrintError getFingerPrintError(Integer code) {
    for (FingerPrintError error : values()) {
      if (error.androidErrorCode == code)
        return error;
    }
    return UNKNOWN;
  }
}
