package ru.eftr.RNSecurity.SecurityV2;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import androidx.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import ru.eftr.RNSecurity.sharedPreferences.DataHelper;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

public class CipherHelper {
  private static CipherHelper instance;
  private static final String KEY_NAME = "SecurityV2.touchId_key";
  private KeyStore keyStore;
  private Cipher cipher;

  public static CipherHelper getInstance() {
    if (instance == null) {
      instance = new CipherHelper();
    }

    return instance;
  }

  public Cipher getCipher() {
    return this.cipher;
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  public boolean initCipher(Context context, int mode) {
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
    } catch (KeyPermanentlyInvalidatedException exception) {
      this.deleteInvalidKey();
      Log.e("KeyPermanentlyInvalidatedException", exception.getMessage());
      Log.e("initCipher", Arrays.toString(exception.getStackTrace()));
      return false;
    } catch (NoSuchProviderException | NoSuchPaddingException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
      | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
      Log.e("initCipher", e.getMessage());
      Log.e("initCipher", Arrays.toString(e.getStackTrace()));
      return false;
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  private void createKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
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

  private void deleteInvalidKey() {
    if (this.keyStore != null) {
      try {
        this.keyStore.deleteEntry(KEY_NAME);
      } catch (KeyStoreException e) {
        e.printStackTrace();
      }
    }
  }
}
