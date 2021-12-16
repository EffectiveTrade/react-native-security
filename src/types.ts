export interface CancellablePromise<T> extends Promise<T> {
  cancel(): void;

  then<TResult1 = T, TResult2 = never>(
    onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | undefined | null,
    onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | undefined | null
  ): CancellablePromise<TResult1 | TResult2>;

  catch<TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | undefined | null): CancellablePromise<T | TResult>;
}

export interface RNSecurity {
  saveCred(login: string, password: string, code: string): Promise<RNSecurityError>;
  unlockByCode(code: string): Promise<RNSecurityCredential>;
  saveCredByBiometry(login: string, password: string): CancellablePromise<RNSecurityError>;
  unlockByBiometry(text?: string): CancellablePromise<RNSecurityCredential>;
  clean(): Promise<RNSecurityError>;
  isSupported(): Promise<RNSecurityBiometryType>;
}

export interface RNSecurityError {
  code: RNSecurityErrorEnum;
  message: string;
  subCode?: number | string;
}

export interface RNSecurityCredential extends RNSecurityError {
  login: string;
  password: string;
}

export interface RNSecurityBiometryType extends RNSecurityError {
  message: string;
}

export enum RNSecurityErrorEnum {
  UNDEFINED = -1, //some system exception, non-interceptable error

  CANT_SAVE_PASSWORD = 1,
  CANT_SAVE_LOGIN = 2,
  CANT_GET_LOGIN_PASSWORD = 3,
  CANT_DELETE_CRED = 4,

  WRONG_TOUCHID_SETTINGS = 5, // Check your Touch ID Menu
  NO_TOUCHID_FINGERS = 6, // No Touch ID fingers enrolled.
  TOUCHID_NOT_AVAILABLE = 7, // Touch ID not available on your device.
  PASSCODE_FOR_TOUCHID = 8, // Need a passcode set to use Touch ID.
  WRONG_TOUCHID_SETTINGS2 = 9, // Check your Touch ID Menu.

  SYSTEM_UNAVAILABLE = 10,
  BIOMETRY_FAILED = 11,
  BIOMETRY_CANCELLED = 12,
  AUTH_FALLBACK = 13,
  NO_TOUCHID_FINGERS2 = 14,
  TOUCHID_NOT_AVAILABLE2 = 15,
  PASSCODE_FOR_TOUCHID2 = 16,

  PINCODE_TO_MUCH_ATTEMPTS = 20, // too much attempts
  PINCODE_CHECK_FAILED = 21, // check hash failed
  PINCODE_ENCRYPT_FAILED = 22, // some exception on encrypt step
  PINCODE_DECRYPT_FAILED = 23, // some exception on decrypt step

  FINGERPRINT_BUSY = 30, // fingerprint listener is running earlier
  FINGERPRINT_FAILED = 31, // native android fingerprint return error
  FINGERPRINT_CANCELED = 32, // cancel or backpressed by user
  FINGERPRINT_ENCRYPT_INIT_FAILED = 33, // some error on init cipher step (fingerpring encrypt setup)
  FINGERPRINT_DECRYPT_FAILED = 34, // cant decode login password
  FINGERPRINT_TO_MUCH_ATTEMPTS = 35, // too much attempts (now 3)
  FINGERPRINT_NOT_SUPPORTED = 36, // device not supported fingerprint
  FINGERPRINT_NOT_SETUP = 37, // fingerprint login/password not setup/encript (or clean)

  LOCKED = 40,
  CANT_SET_CODE = 41,
  CANT_SET_BIOMETRY = 42,

  /**
   * Нужно выполнить сохранение биометрии заново.
   * Возникает в случае
   * - добавления нового отпечатка пальца в Android, исключение UnrecoverableKeyException (см. subCode)
   */
  BIOMETRY_NEED_RENEW = 50,

  ACTIVITY_NOT_FOUND = 100
}

// Values: https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.html
// ❗ При добавлении значений необходимо также добавить его в index.js
export enum SecurityErrorSubCodeAndroidEnum {
  FINGERPRINT_ACQUIRED_IMAGER_DIRTY = 0x00000003,
  FINGERPRINT_ERROR_LOCKOUT = 0x00000007,
  /**
   * Fingerprint operation canceled.
   * Вернёт, если во время запроса отпечатся залочить устройство.
   */
  FINGERPRINT_ERROR_CANCELED = 0x00000005,
  FINGERPRINT_ERROR_USER_CANCELED = 0x0000000a,
}
