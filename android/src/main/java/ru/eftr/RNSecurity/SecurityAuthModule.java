package ru.eftr.RNSecurity;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.app.ActivityCompat;

import android.text.TextUtils;
import android.util.Base64;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.google.gson.Gson;

import ru.eftr.RNSecurity.model.ErrorCode;
import ru.eftr.RNSecurity.model.ErrorResponse;
import ru.eftr.RNSecurity.model.AuthResponse;
import ru.eftr.RNSecurity.model.RNException;
import ru.eftr.RNSecurity.sharedPreferences.DataHelper;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static android.hardware.fingerprint.FingerprintManager.AuthenticationResult;
import static android.hardware.fingerprint.FingerprintManager.CryptoObject;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;


public class SecurityAuthModule extends ReactContextBaseJavaModule {

  private static final String KEY_NAME = "ru..touchId_key";

  public static final int TOUCH_ID_REQUEST = 1012;

  private static final int PINCODE_MAX_ATTEMPTS = 3;
  private static final int TOUCH_ID_MAX_ATTEMPTS = 3;

  private KeyStore keyStore;
  private Cipher cipher;

  private FingerprintHandler mFingerprintHandler;

  private Callback saveByBiometryErrorCallback;
  private Callback unlockByBiometryErrorCallback;

  public static boolean inProgress = false;

  public SecurityAuthModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  public String getName() {
    return "VBNativeAuth";
  }

  @ReactMethod
  public void SaveCred(String login, String password, String code, Callback reactErrorCallback, Callback reactSuccessCallback) {
    Gson gson = new Gson();
    try {
      Context context = getContext();

      PincodeModule.encryptByPincode(context, login, password, code);

      DataHelper.cleatPinCodeAttempts(context);
      DataHelper.cleatFingerPrintAttempts(context);

      reactSuccessCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.NONE.getCode())));
    } catch (RNException ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ex.code.getCode())));
    } catch (Exception ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.UNDEFINED.getCode(), ex.getMessage())));
    }
  }

  @ReactMethod
  public void UnlockByCode(String code, Callback reactErrorCallback, Callback reactSuccessCallback) {
    Gson gson = new Gson();
    try {
      Context context = getContext();

      DataHelper.addPinCodeAttempt(context);

      if (DataHelper.getPinCodeAttempt(context) >= PINCODE_MAX_ATTEMPTS) {
        DataHelper.clean(getContext());
        reactErrorCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.PINCODE_TO_MUCH_ATTEMPTS.getCode())));
        return;
      }

      String[] result = PincodeModule.decryptByPincode(context, code);

      DataHelper.cleatPinCodeAttempts(context);
      DataHelper.cleatFingerPrintAttempts(context);

      reactSuccessCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.NONE.getCode(), result[0], result[1])));
    } catch (RNException ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ex.code.getCode())));
    } catch (Exception ex) {
      reactErrorCallback.invoke(gson.toJson(getErrorWithException(ErrorCode.UNDEFINED.getCode(), ex)));
    }
  }

  @ReactMethod
  public void UnlockByBiometry(String title, String subTitle, final Callback reactErrorCallback, final Callback reactSuccessCallback) {
    try {
      if (unlockByBiometryErrorCallback != null) {
        reactErrorCallback.invoke(ErrorCode.FINGERPRINT_BUSY.getCode());
        CancelUnlockByBiometry();
        return;
      }
      unlockByBiometryErrorCallback = reactErrorCallback;

      final Context context = getContext();
      if (TextUtils.isEmpty(DataHelper.getFingerptintSecret(context))) {
        cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SETUP.getCode()));
        return;
      }

      if (DataHelper.getFingerPrintAttempt(context) >= TOUCH_ID_MAX_ATTEMPTS) {
        cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_TO_MUCH_ATTEMPTS.getCode()));
        return;
      }
      if (isFingerprintAuthAvailable(context)) {
        if (!inProgress) {

          if (initCipher(context, DECRYPT_MODE)) {
            if (cipher != null) {
              BiometricPrompt.CryptoObject cryptoObject = null;//new BiometricPrompt.CryptoObject(cipher);

              mFingerprintHandler = new FingerprintHandler(BiometricManager.from(getContext()), new FingerprintHandler.Callback() {
                @Override
                public void onAuthenticated(BiometricPrompt.AuthenticationResult result) {
                  try {
                    byte[] bytes = Base64.decode(DataHelper.getFingerptintSecret(context), Base64.NO_WRAP);
                    BiometricPrompt.CryptoObject resultCryptoObject = result.getCryptoObject();
                    Cipher resultCipher = null;
                    if (resultCryptoObject != null) {
                      resultCipher = resultCryptoObject.getCipher();
                    }
                    String decodedLoginpass = null;
                    if (resultCipher != null) {
                      decodedLoginpass = new String(resultCipher.doFinal(bytes));
                    }
                    if (decodedLoginpass == null) {
                      cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_DECRYPT_FAILED.getCode()));
                      return;
                    }

                    String[] values = decodedLoginpass.split(PincodeModule.SEPARATOR);

                    if (values.length != 3) {
                      cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_DECRYPT_FAILED.getCode()));
                      return;
                    }

                    String t1 = values[0] + PincodeModule.SEPARATOR + values[1];
                    String sha256LoginPass = PincodeModule.sha256(t1);

                    if (!sha256LoginPass.equals(values[2])) {
                      cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_DECRYPT_FAILED.getCode()));
                      return;
                    }

                    DataHelper.cleatFingerPrintAttempts(context);
                    DataHelper.cleatPinCodeAttempts(context);

                    Gson gson = new Gson();

                    unlockByBiometryErrorCallback = null;
                    reactSuccessCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.NONE.getCode(), values[0], values[1])));
                  } catch (Exception e) {
                    DataHelper.addFingerPrintAttempt(context);
                    cancelUnlockByBiometry(new ErrorResponse(ErrorCode.UNDEFINED.getCode(), e.getMessage()));
                  }
                }

                @Override
                public void onError(String errorString, String subCode) {
                  DataHelper.addFingerPrintAttempt(context);
                  cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_FAILED.getCode(), errorString, subCode));
                }

                @Override
                public void onCancelled() {
                  cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_CANCELED.getCode()));
                }
              });

              if (!FingerprintHandler.isFingerprintAuthAvailable(BiometricManager.from(getContext()))) {
                cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode()));
              } else {
                BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                  .setTitle(title)
                  .setSubtitle(subTitle)
                  .build();
                mFingerprintHandler.startAuth(getContext(), promptInfo, cryptoObject);
              }
            } else {
              inProgress = false;
              cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_ENCRYPT_INIT_FAILED.getCode()));
            }
          }
        } else {
          cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_BUSY.getCode()));
        }
      } else {
        cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode()));
      }
    } catch (RNException ex) {
      cancelUnlockByBiometry(new ErrorResponse(ex.code.getCode()));
    } catch (Exception ex) {
      cancelUnlockByBiometry(getErrorWithException(ErrorCode.UNDEFINED.getCode(), ex));
    }
  }

  private void cancelUnlockByBiometry(ErrorResponse error) {
    if (unlockByBiometryErrorCallback != null) {
      Gson gson = new Gson();
      unlockByBiometryErrorCallback.invoke(gson.toJson(error));
      unlockByBiometryErrorCallback = null;
    }
    if (mFingerprintHandler != null) {
      mFingerprintHandler.endAuth();
    }
  }

  @ReactMethod
  public void CancelUnlockByBiometry() {
    cancelUnlockByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_CANCELED.getCode()));
        /*if(mFingerprintHandler!=null) {
            mFingerprintHandler.endAuth();
        }*/
  }

  @ReactMethod
  public void Clean(Callback reactErrorCallback, Callback reactSuccessCallback) {
    Gson gson = new Gson();
    try {
      DataHelper.clean(getContext());

      reactSuccessCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.NONE.getCode())));
    } catch (RNException ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ex.code.getCode())));
    } catch (Exception ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.UNDEFINED.getCode(), ex.getMessage())));
    }
  }

  @ReactMethod
  public void SaveCredByBiometry(final String login, final String password, String title, String subTitle, final Callback reactErrorCallback, final Callback reactSuccessCallback) {
    try {
      if (saveByBiometryErrorCallback != null) {
        reactErrorCallback.invoke(ErrorCode.FINGERPRINT_BUSY.getCode());
        CancelSaveCredByBiometry();
        return;
      }
      saveByBiometryErrorCallback = reactErrorCallback;

      final Context context = getContext();

      if (isFingerprintAuthAvailable(context)) {
        if (!inProgress) {
          inProgress = true;

          if (initCipher(context, ENCRYPT_MODE)) {
            if (cipher != null) {
              BiometricPrompt.CryptoObject cryptoObject = null;//new BiometricPrompt.CryptoObject(cipher);

              mFingerprintHandler = new FingerprintHandler(BiometricManager.from(getContext()), new FingerprintHandler.Callback() {
                @Override
                public void onAuthenticated(BiometricPrompt.AuthenticationResult result) {
                  try {
                    String t1 = login + PincodeModule.SEPARATOR + password;
                    String sha256LoginPass = PincodeModule.sha256(t1);

                    String t2 = login + PincodeModule.SEPARATOR + password + PincodeModule.SEPARATOR + sha256LoginPass;

                    BiometricPrompt.CryptoObject resultCryptoObject = result.getCryptoObject();
                    Cipher resultCipher = null;
                    if (resultCryptoObject != null) {
                      resultCipher = resultCryptoObject.getCipher();
                    }
                    byte[] bytes = null;
                    if (resultCipher != null) {
                      bytes = resultCipher.doFinal(t2.getBytes());
                    }

                    String encryptedText = "";
                    if (bytes != null) {
                      encryptedText = Base64.encodeToString(bytes, Base64.NO_WRAP);
                    }
                    DataHelper.setFingerptintSecret(context, encryptedText);

                    DataHelper.cleatFingerPrintAttempts(context);
                    DataHelper.cleatPinCodeAttempts(context);

                    Gson gson = new Gson();

                    saveByBiometryErrorCallback = null;
                    reactSuccessCallback.invoke(gson.toJson(new AuthResponse(ErrorCode.NONE.getCode())));
                  } catch (Exception e) {
                    cancelSaveByBiometry(new ErrorResponse(ErrorCode.UNDEFINED.getCode(), e.getMessage()));
                  }
                }

                @Override
                public void onError(String errorString, String subCode) {
                  cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_FAILED.getCode(), errorString, subCode));
                }

                @Override
                public void onCancelled() {
                  cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_CANCELED.getCode()));
                }
              });

              if (!mFingerprintHandler.isFingerprintAuthAvailable(BiometricManager.from(getContext()))) {
                cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode()));
              } else {
                BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                  .setTitle(title)
                  .setSubtitle(subTitle)
                  .build();
                mFingerprintHandler.startAuth(getContext(), promptInfo, cryptoObject);
              }
            } else {
              cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_ENCRYPT_INIT_FAILED.getCode()));
            }
            inProgress = false;
          } else {
            inProgress = false;
            cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_ENCRYPT_INIT_FAILED.getCode()));
          }
        }
      } else {
        cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode()));
      }
    } catch (RNException ex) {
      cancelSaveByBiometry(new ErrorResponse(ex.code.getCode()));
    } catch (Exception ex) {
      cancelSaveByBiometry(getErrorWithException(ErrorCode.UNDEFINED.getCode(), ex));
    }
  }

  private ErrorResponse getErrorWithException(String code, Exception ex) {
    return new ErrorResponse(ErrorCode.UNDEFINED.getCode());
  }

  private void cancelSaveByBiometry(ErrorResponse error) {
    if (saveByBiometryErrorCallback != null) {
      Gson gson = new Gson();
      saveByBiometryErrorCallback.invoke(gson.toJson(error));
      saveByBiometryErrorCallback = null;
    }
    if (mFingerprintHandler != null) {
      mFingerprintHandler.endAuth();
    }
  }

  @ReactMethod
  public void CancelSaveCredByBiometry() {
    cancelSaveByBiometry(new ErrorResponse(ErrorCode.FINGERPRINT_CANCELED.getCode()));
        /*if(mFingerprintHandler!=null) {
            mFingerprintHandler.endAuth();
        }*/
  }

  @ReactMethod
  public void IsSupported(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
    Gson gson = new Gson();
    try {
      if (android.os.Build.VERSION.SDK_INT < 23) {
        reactSuccessCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode(), "")));
        return;
      }

      if (FingerprintHandler.isFingerprintAuthAvailable(BiometricManager.from(getContext()))) {
        reactSuccessCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.NONE.getCode(), "TouchID")));
      } else {
        reactSuccessCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.FINGERPRINT_NOT_SUPPORTED.getCode(), "")));
      }
    } catch (RNException ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ex.code.getCode())));
    } catch (Exception ex) {
      reactErrorCallback.invoke(gson.toJson(new ErrorResponse(ErrorCode.UNDEFINED.getCode(), ex.getMessage())));
    }
  }

  private Context getContext() throws RNException {
    Context context = getCurrentActivity();
    if (context == null)
      throw new RNException(ErrorCode.ACTIVITY_NOT_FOUND);
    return context;
  }

  private boolean isFingerprintAuthAvailable(Context context) throws RNException {
    if (android.os.Build.VERSION.SDK_INT < 23) {
      throw new RNException(ErrorCode.FINGERPRINT_NOT_SUPPORTED);
    }

    if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
      isPermitionsGranted(context);
      return false;
    }

    KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    if (keyguardManager == null || !keyguardManager.isKeyguardSecure()) {
      return false;
    }

    return FingerprintHandler.isFingerprintAuthAvailable(BiometricManager.from(context))
      && keyguardManager.isKeyguardSecure()
      && keyguardManager.isDeviceSecure();
  }

  public boolean isPermitionsGranted(Context context) {
    return IntentUtils.isPermitionsGranted(context, IntentUtils.PERMISSIONS_TOUCH_ID, TOUCH_ID_REQUEST);
  }

  private boolean initCipher(Context context, int mode) throws RNException {
    try {
      if (keyStore == null) {
        keyStore = KeyStore.getInstance("AndroidKeyStore");
      }
      cipher = Cipher.getInstance(
        KeyProperties.KEY_ALGORITHM_AES + "/"
          + KeyProperties.BLOCK_MODE_CBC + "/"
          + KeyProperties.ENCRYPTION_PADDING_PKCS7);

      keyStore.load(null);
      SecretKey key;
      switch (mode) {
        case ENCRYPT_MODE:
          createKey();
          key = (SecretKey) keyStore.getKey(KEY_NAME,
            null);
          cipher.init(mode, key);
          DataHelper.setCipherIV(context, Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
          break;
        case DECRYPT_MODE:
          key = (SecretKey) keyStore.getKey(KEY_NAME,
            null);
          byte[] iv = Base64.decode(DataHelper.getCipherIV(context), Base64.NO_WRAP);
          IvParameterSpec ivspec = new IvParameterSpec(iv);
          cipher.init(mode, key, ivspec);
          break;
      }

      return true;
    } catch (NoSuchProviderException | NoSuchPaddingException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
      | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      throw new RNException(ErrorCode.BIOMETRY_NEED_RENEW, "", e.getClass().getSimpleName());
    }
  }

  public void createKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
    try {
      KeyGenerator mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

      mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        // Require the user to authenticate with a fingerprint to authorize every use
        // of the key
        .setUserAuthenticationRequired(true)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .build());
      mKeyGenerator.generateKey();

      mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

      //Initialize an empty KeyStore//
      keyStore.load(null);

      //Initialize the KeyGenerator//
      mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
        KeyProperties.PURPOSE_ENCRYPT |
          KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

        //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
        .setUserAuthenticationRequired(true)
        .setEncryptionPaddings(
          KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .build());

      //Generate the key//
      mKeyGenerator.generateKey();
    } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException e) {
      throw e;
    } catch (CertificateException e) {
      e.printStackTrace();
    }
  }

}
