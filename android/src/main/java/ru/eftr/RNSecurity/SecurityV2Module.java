package ru.eftr.RNSecurity;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Handler;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import devliving.online.securedpreferencestore.DefaultRecoveryHandler;
import devliving.online.securedpreferencestore.SecuredPreferenceStore;
import ru.eftr.RNSecurity.SecurityV2.CipherHelper;
import ru.eftr.RNSecurity.SecurityV2.FingerprintChangeObserver;
import ru.eftr.RNSecurity.model.ErrorCode;
import ru.eftr.RNSecurity.model.ErrorResponse;
import ru.eftr.RNSecurity.model.FingerPrintError;
import ru.eftr.RNSecurity.model.RNException;

import static android.hardware.fingerprint.FingerprintManager.FINGERPRINT_ACQUIRED_IMAGER_DIRTY;

enum LockType {
  Code,
  Biometry
}

public class SecurityV2Module extends ReactContextBaseJavaModule {
  private static final String UNLOCK_ATTEMPTS_KEY = "unlock_attempts";
  private static final String CREDS_KEY = "creds";
  private static final String CODE_KEY = "code";
  private static final int MAX_ATTEMPTS = 3;
  private static final int TOUCH_ID_REQUEST = 1012;

  private boolean _isLocked = true;
  private boolean _isInitialized = false;
  private BiometricPrompt biometricPrompt;

  public SecurityV2Module(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  public String getName() {
    return "SecurityV2";
  }

  /**
   * Не должен кидать исключений. В случае ошибки делает clean.
   */
  private void initIfNeeded() {
    if (!this._isInitialized) {
      boolean ok;
      try {
        this._isLocked = !this.isEmpty();
        ok = true;
      } catch (RNException ex) {
        ex.printStackTrace();
        ok = false;
      }

      if (!ok) {
        try {
          this._clean();
        } catch (RNException ex) {
          ex.printStackTrace();
        }
      }

      this._isInitialized = true;
    }
  }

  private SecuredPreferenceStore getSecuredPreferenceStore() throws RNException, IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, SecuredPreferenceStore.MigrationFailedException, KeyStoreException {
    if (!this._isInitialized) {
      final Context context = this.getContext();
      //not mandatory, can be null too
      String storeFileName = this.getName() + ".securedStore";
      //not mandatory, can be null too
      String keyPrefix = this.getName();
      //it's better to provide one, and you need to provide the same key each time after the first time
      byte[] seedKey = (this.getName() + ".seedKey").getBytes();
      SecuredPreferenceStore.init(context, storeFileName, keyPrefix, seedKey, new DefaultRecoveryHandler());
      this._isInitialized = true;
    }

    return SecuredPreferenceStore.getSharedInstance();
  }

  private void ensureUnlocked() throws RNException {
    if (this.getIsLocked()) {
      throw new RNException(ErrorCode.LOCKED);
    }
  }

  private boolean getIsLocked() {
    this.initIfNeeded();
    return this._isLocked;
  }

  private boolean isEmpty() throws RNException {
    try {
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      boolean result = store.getAll().size() == 0;
      store.throwExceptionIfErrorOccurred();
      return result;
    } catch (Exception ex) {
      throw new RNException(ErrorCode.UNDEFINED, ex.getMessage());
    }
  }

//    clean(options?: {}): Promise<void>;

  @ReactMethod
  public void clean(ReadableMap options, Promise promise) {
    try {
      this._clean();
      promise.resolve(null);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

  private void _clean() throws RNException {
    try {
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      store.edit().clear().commit();
      store.throwExceptionIfErrorOccurred();
    } catch (Exception ex) {
      throw new RNException(ErrorCode.UNDEFINED, ex.getMessage());
    } finally {
      biometricPrompt = null;
    }

    this._isLocked = false;
  }

  //    lock(options?: {}): Promise<void>;

  @ReactMethod
  public void lock(ReadableMap options, Promise promise) {
    try {
      this._isLocked = true;
      promise.resolve(null);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

  private void tryIncrementUnlockAttempts(LockType lockType) throws RNException {
    try {
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      int nextValue = store.getInt(UNLOCK_ATTEMPTS_KEY, 0) + 1;
      store.throwExceptionIfErrorOccurred();

      if (nextValue >= MAX_ATTEMPTS) {
        // по старой логике очистку делать только при неверном коде
        if (lockType == LockType.Code) {
          this._clean();
        }

        ErrorCode errorCode = lockType == LockType.Code ? ErrorCode.PINCODE_TO_MUCH_ATTEMPTS : ErrorCode.FINGERPRINT_TO_MUCH_ATTEMPTS;
        throw new RNException(errorCode);
      } else {
        store.edit().putInt(UNLOCK_ATTEMPTS_KEY, nextValue).commit();
        store.throwExceptionIfErrorOccurred();
      }
    } catch (RNException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new RNException(ErrorCode.UNDEFINED, ex.getMessage());
    }
  }

  private void _resetUnlockAttempts() throws RNException {
    try {
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      store.edit().putInt(UNLOCK_ATTEMPTS_KEY, 0).commit();
      store.throwExceptionIfErrorOccurred();
    } catch (Exception ex) {
      throw new RNException(ErrorCode.UNDEFINED, ex.getMessage());
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  private void _ensureFingerprintAuthAvailable() throws RNException {
    final Context context = this.getContext();

    boolean ok = BiometricManager.from(context).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
    if (!ok) {
      throw new RNException(ErrorCode.FINGERPRINT_NOT_SUPPORTED);
    }

    if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
      ok = isPermissionsGranted(context);
      if (!ok) {
        throw new RNException(ErrorCode.FINGERPRINT_NOT_GRANTED);
      }
    }

    KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    ok = keyguardManager != null && keyguardManager.isKeyguardSecure() && keyguardManager.isDeviceSecure();
    if (!ok) {
      throw new RNException(ErrorCode.FINGERPRINT_NOT_SECURE);
    }

    ok = BiometricManager.from(getContext()).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
    if (!ok) {
      throw new RNException(ErrorCode.NO_TOUCHID_FINGERS);
    }
  }

  private boolean isPermissionsGranted(Context context) {
    return IntentUtils.isPermitionsGranted(context, IntentUtils.PERMISSIONS_TOUCH_ID, TOUCH_ID_REQUEST);
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  private BiometricPrompt.CryptoObject getCryptoObject() throws RNException {
    final Context context = this.getContext();
    if (CipherHelper.getInstance().initCipher(context, Cipher.DECRYPT_MODE)) {
      //TODO current version BiometryPrompt depends from IdentityCredential api 30
      // we dont need CryptoObject - that's why it's ok for now
      return null;//new BiometricPrompt.CryptoObject(CipherHelper.getInstance().getCipher());
    }
    return null;
  }

//    save(creds: string | undefined, options?: {}): Promise<void>;

  @ReactMethod
  public void save(String creds, ReadableMap options, Promise promise) {
    try {
      this.ensureUnlocked();
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      store.edit().putString(CREDS_KEY, creds).commit();
      store.throwExceptionIfErrorOccurred();
      promise.resolve(null);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

//    read(options?: {}): Promise<string | undefined>;

  @ReactMethod
  public void read(ReadableMap options, Promise promise) {
    try {
      this.ensureUnlocked();
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      String creds = store.getString(CREDS_KEY, null);
      store.throwExceptionIfErrorOccurred();

      promise.resolve(creds);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

//    setUnlockCode(code: string, options?: {}): Promise<void>;

  @ReactMethod
  public void setUnlockCode(String code, ReadableMap options, Promise promise) {
    try {
      this.ensureUnlocked();
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      store.edit().putString(CODE_KEY, code).commit();
      store.throwExceptionIfErrorOccurred();
      promise.resolve(null);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

//    unlockByCode(code: string, options?: {}): Promise<void>;

  @ReactMethod
  public void unlockByCode(String code, ReadableMap options, Promise promise) {
    try {
      SecuredPreferenceStore store = this.getSecuredPreferenceStore();
      String unlockCode = store.getString(CODE_KEY, "");
      boolean isValid = unlockCode.equals(code);
      store.throwExceptionIfErrorOccurred();
      if (!isValid) {
        this.tryIncrementUnlockAttempts(LockType.Code);
        throw new RNException(ErrorCode.PINCODE_CHECK_FAILED);
      }

      _resetUnlockAttempts();
      this._isLocked = false;

      promise.resolve(null);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

//    setUnlockBiometry(options?: {}): Promise<void>;

  @RequiresApi(api = Build.VERSION_CODES.M)
  @ReactMethod
  public void setUnlockBiometry(ReadableMap options, final Promise promise) {
    try {
      this.ensureUnlocked();
      this._authenticateByBiometry(options, promise, false);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

//    unlockByBiometry(options?: {}): Promise<void>;

  @RequiresApi(api = Build.VERSION_CODES.M)
  @ReactMethod
  public void unlockByBiometry(ReadableMap options, Promise promise) {
    try {
      this._authenticateByBiometry(options, promise, true);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  private void _authenticateByBiometry(ReadableMap options, final Promise promise, final boolean lockOnFail) throws RNException {
    this._ensureFingerprintAuthAvailable();
    this._cancelAndResetBiometry();

    Context context = null;
    try {
      context = getContext();
    } catch (RNException e) {
      e.printStackTrace();
    }

    Executor executor = ContextCompat.getMainExecutor(context);
    biometricPrompt = new BiometricPrompt((FragmentActivity) context,
      executor, new BiometricPrompt.AuthenticationCallback() {
      @Override
      public void onAuthenticationError(int errorCode,
                                        @NonNull CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        if (biometricPrompt == null) return; // already handled
        //отпечаток считался, но не распознался
        ErrorCode error = FingerPrintError.getFingerPrintError(errorCode).securityErrorCode;
        _onBiometryFailed(error,
          promise, lockOnFail,
          new ErrorResponse(error, "", String.valueOf(errorCode))
        );
      }

      @Override
      public void onAuthenticationSucceeded(
        @NonNull BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        if (biometricPrompt == null) return; // already handled
        //все прошло успешно
        _cancelAndResetBiometry();
        try {
          _resetUnlockAttempts();
          _isLocked = false;
          promise.resolve(null);
        } catch (RNException ex) {
          new ErrorResponse(ex).reject(promise);
        }
      }

      @Override
      public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        if (biometricPrompt == null) return; // already handled
        //грязные пальчики, недостаточно сильный зажим
        //можно показать helpString в виде тоста
        _onBiometryFailed(ErrorCode.FINGERPRINT_FAILED,
          promise, lockOnFail,
          new ErrorResponse(ErrorCode.FINGERPRINT_FAILED, "", String.valueOf(FINGERPRINT_ACQUIRED_IMAGER_DIRTY))
        );
      }
    });

    String title = "Приложите палец";
    //String optionsTitle = options.getString("title");
    //if (optionsTitle != null)
    //title = optionsTitle;
    String subTitle = "";
    //String optionsSubTitle = options.getString("subtitle");
    //if (optionsSubTitle != null)
    //  subTitle = optionsSubTitle;
    String negativeText = "Отмена";

    final BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setSubtitle(subTitle)
      .setNegativeButtonText(negativeText)
      .build();

    Handler h = new Handler(context.getMainLooper());
    h.postDelayed(new Runnable() {
      @Override
      public void run() {
        biometricPrompt.authenticate(promptInfo);
      }
    }, 100);
  }

  private void _onBiometryFailed(ErrorCode errorCode, Promise promise, boolean lockOnFail, ErrorResponse errorResponse) {
    _cancelAndResetBiometry();
    if (lockOnFail) {
      _isLocked = true;
    }

    try {
      //not increment retry count when not try scan
      if (errorCode != ErrorCode.FINGERPRINT_CANCELED)
        tryIncrementUnlockAttempts(LockType.Biometry);
      errorResponse.reject(promise);
    } catch (RNException ex) {
      new ErrorResponse(ex).reject(promise);
    }
  }

  @ReactMethod
  public void cancelBiometry(ReadableMap options, Promise promise) {
    try {
      this._cancelAndResetBiometry();
      promise.resolve(null);
    } catch (Exception ex) {
      new ErrorResponse(ErrorCode.UNDEFINED, ex.getMessage()).reject(promise);
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @ReactMethod
  public void hasFingerPrintChanged(Callback errorCallback, Callback successCallback) {
    try {
      this._ensureFingerprintAuthAvailable();
      FingerprintChangeObserver.getInstance(this.getReactApplicationContext()).hasFingerPrintChanged(errorCallback, successCallback);
    } catch (RNException | RuntimeException e) {
      errorCallback.invoke("BIOMETRY_UNAVAILABLE" + e);
    }
  }

  @ReactMethod
  private void _cancelAndResetBiometry() {
    if (biometricPrompt != null) {
      biometricPrompt.cancelAuthentication();
      biometricPrompt = null;
    }
  }

  private Context getContext() throws RNException {
    Context context = getCurrentActivity();
    if (context == null)
      throw new RNException(ErrorCode.ACTIVITY_NOT_FOUND);
    return context;
  }
}
