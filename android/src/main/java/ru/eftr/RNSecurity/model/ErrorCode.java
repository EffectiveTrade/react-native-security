package ru.eftr.RNSecurity.model;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

/*
IOS ERROR CODE:

0 - NO ERROR
1 - Can't save password
2 - Can't save login
3 - Can't get login and passwrod
4 - Can't delete cred from keychain

5 - Check your Touch ID Settings
6 - No Touch ID fingers enrolled.
7 - Touch ID not available on your device.
8 - Need a passcode set to use Touch ID.
9 - Check your Touch ID Settings.

10 = System canceled auth request due to app coming to foreground or background.
11 = User failed auth by biometry.
12 = User cancelled.
13 = Fallback auth method should be implemented here.
14 = No Touch ID fingers enrolled.
15 = Touch ID not available on your device.
16 = Need a passcode set to use Touch ID.

20 = User failed after a few attempts unlockByCode.
21 = Validation error

*/

public enum ErrorCode {
    NONE("0"),//no error

    UNDEFINED("-1"),//some system exception, non-interceptable error

    NO_TOUCHID_FINGERS("6"), // если на устройстве нет отпечатков
    TOUCHID_NOT_AVAILABLE("7"),

    PINCODE_TO_MUCH_ATTEMPTS("20"),//too much attempts (now 3)
    PINCODE_CHECK_FAILED("21"),//check hash failed (compare saved hash and hash with new input values)
    PINCODE_ENCRYPT_FAILED("22"),//some exception on encrypt step
    PINCODE_DECRYPT_FAILED("23"),//some exception on decrypt step

    FINGERPRINT_BUSY("30"),//fingerprint listener is running earlier
    FINGERPRINT_FAILED("31"),//native android fingerprint return error
    FINGERPRINT_CANCELED("32"),//cancel or backpressed by user
    FINGERPRINT_ENCRYPT_INIT_FAILED("33"),//some error on init cipher step (fingerpring encrypt setup)
    FINGERPRINT_DECRYPT_FAILED("34"),//cant decode login password
    FINGERPRINT_TO_MUCH_ATTEMPTS("35"),//too much attempts (now 3)
    FINGERPRINT_NOT_SUPPORTED("36"),//device not supported fingerprint
    FINGERPRINT_NOT_SETUP("37"),//fingerprint login/password not setup/encript (or clean)

    FINGERPRINT_NOT_GRANTED("38"), // не разрешён доступ пользователем
    FINGERPRINT_NOT_SECURE("39"), // если устройство не защищено пином, рисунком или паролем

    LOCKED("40"),
    CANT_SET_CODE("41"),
    CANT_SET_BIOMETRY("42"),

    BIOMETRY_NEED_RENEW("50"), // нужно выполнить сохранение биометрии заново

    ACTIVITY_NOT_FOUND("100"); //can't get context (app close)

    private final String code;

    ErrorCode(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
