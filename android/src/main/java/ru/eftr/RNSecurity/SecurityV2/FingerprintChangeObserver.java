package ru.eftr.RNSecurity.SecurityV2;

import android.annotation.TargetApi;
import android.content.SharedPreferences;

import android.os.Build;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;

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

public class FingerprintChangeObserver extends ReactContextBaseJavaModule {
    private static FingerprintChangeObserver instance;
    private final ReactApplicationContext reactContext;
    private final String DEFAULT_KEY_NAME = "default_key";
    private final String INIT_KEYSTORE = "INIT_KEYSTORE";

    private final SharedPreferences spref;
    private final KeyStore mKeyStore;
    private final KeyGenerator mKeyGenerator;

  public FingerprintChangeObserver(ReactApplicationContext reactContext) {
    super(reactContext);

    this.reactContext = reactContext;

    // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
    // for your flow. Use of keys is necessary if you need to know if the set of
    // enrolled fingerprints has changed.
    try {
      mKeyStore = KeyStore.getInstance("AndroidKeyStore");
    } catch (KeyStoreException e) {
      throw new RuntimeException("Failed to get an instance of KeyStore", e);
    }
    try {
      mKeyGenerator = KeyGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {

      throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
    }

    spref = PreferenceManager.getDefaultSharedPreferences(reactContext);

    //when initializing the app we want to create the key only one so we can detect changes
    if (spref.getBoolean(INIT_KEYSTORE, true)) {
      createKey(DEFAULT_KEY_NAME, true);
      spref.edit().putBoolean(INIT_KEYSTORE, false).apply();
    }
  }

  public static FingerprintChangeObserver getInstance(ReactApplicationContext reactContext) {
    if (instance == null) {
      instance = new FingerprintChangeObserver(reactContext);
    }

    return instance;
  }

  public void hasFingerPrintChanged(Callback errorCallback, Callback successCallback) {

    Cipher defaultCipher;
    try {
      defaultCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
        + KeyProperties.BLOCK_MODE_GCM + "/"
        + KeyProperties.ENCRYPTION_PADDING_NONE);

    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      errorCallback.invoke(e.getMessage());
      throw new RuntimeException("Failed to get an instance of Cipher", e);
    }
    if (initCipher(defaultCipher, DEFAULT_KEY_NAME)) {
      successCallback.invoke(false);
    } else {
      if (this.reactContext != null) {
        //after we find a change in a fingerprint we need to reinitialize the keystore
        spref.edit().putBoolean(INIT_KEYSTORE, true).apply();
        createKey(DEFAULT_KEY_NAME, true);

        successCallback.invoke(true);
      } else {
        successCallback.invoke(false);

      }
    }
  }

  @Override
  public String getName() {
    return "FingerprintChangeObserver";
  }
  @TargetApi(Build.VERSION_CODES.M)
  private boolean initCipher(Cipher cipher, String keyName) {
    try {
      mKeyStore.load(null);
      SecretKey key = (SecretKey) mKeyStore.getKey(keyName, null);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return true;
    } catch (KeyPermanentlyInvalidatedException e) {
      return false;
      // После изменения режима шифрования на GCM старые ключи становятся невалидными, выбрасывается InvalidKeyException, нужно его обработать и создать новый ключ
    } catch (InvalidKeyException e) {
      return false;
    } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
      | NoSuchAlgorithmException e) {
      throw new RuntimeException("Failed to init Cipher", e);
    }
  }

  /**
   * Creates a symmetric key in the Android Key Store which can only be used after the user has
   * authenticated with fingerprint.
   *
   * @param keyName                          the name of the key to be created
   * @param invalidatedByBiometricEnrollment if {@code false} is passed, the created key will not
   *                                         be invalidated even if a new fingerprint is enrolled.
   *                                         The default value is {@code true}, so passing
   *                                         {@code true} doesn't change the behavior
   *                                         (the key will be invalidated if a new fingerprint is
   *                                         enrolled.). Note that this parameter is only valid if
   *                                         the app works on Android N developer preview.
   */
  @TargetApi(Build.VERSION_CODES.M)
  public void createKey(String keyName, boolean invalidatedByBiometricEnrollment) {


    try {
      mKeyStore.load(null);
      // Set the alias of the entry in Android KeyStore where the key will appear
      // and the constrains (purposes) in the constructor of the Builder

      KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
        KeyProperties.PURPOSE_ENCRYPT |
          KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        // Require the user to authenticate with a fingerprint to authorize every use
        // of the key
        .setUserAuthenticationRequired(true)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE);

      // This is a workaround to avoid crashes on devices whose API level is < 24
      // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
      // visible on API level +24.
      // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
      // which isn't available yet.
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
      }
      mKeyGenerator.init(builder.build());
      mKeyGenerator.generateKey();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
      | CertificateException | IOException e) {
      throw new RuntimeException(e);
    }
  }
}
