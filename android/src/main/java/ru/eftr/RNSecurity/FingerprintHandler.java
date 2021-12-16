package ru.eftr.RNSecurity;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;

public class FingerprintHandler extends BiometricPrompt.AuthenticationCallback {
  private boolean selfCancelled;

  private final BiometricManager mBiometricManager;
  private BiometricPrompt mBiometricPrompt;
  private final Callback mCallback;

  public FingerprintHandler(BiometricManager biometricManager, Callback callback) {
    mBiometricManager = biometricManager;
    mCallback = callback;
  }

  public static boolean isFingerprintAuthAvailable(BiometricManager biometricManager) {
    switch (biometricManager.canAuthenticate()) {
      case BiometricManager.BIOMETRIC_SUCCESS:
        //App can authenticate using biometrics.
        return true;
      case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
        //No biometric features available on this device.
        return false;
      case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
        //Biometric features are currently unavailable.
        return false;
      case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
        // Prompts the user to create credentials that your app accepts.
        /*final Intent enrollIntent = new Intent(Settings.ACTION_BIOMETRIC_ENROLL);
        enrollIntent.putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
          BIOMETRIC_STRONG | DEVICE_CREDENTIAL);
        startActivityForResult(enrollIntent, REQUEST_CODE);*/
        //Biometric not enrolled
        return false;
      default:
        return false;
    }
  }

  public void startAuth(Context context, BiometricPrompt.PromptInfo promptInfo, BiometricPrompt.CryptoObject cryptoObject) {
    Executor executor = ContextCompat.getMainExecutor(context);
    mBiometricPrompt = new BiometricPrompt((FragmentActivity) context,
      executor, this);
    mBiometricPrompt.authenticate(promptInfo, cryptoObject);
    selfCancelled = false;
  }

  public void endAuth() {
    if (mBiometricPrompt != null) {
      mBiometricPrompt.cancelAuthentication();
      selfCancelled = true;
    }
  }

  @Override
  public void onAuthenticationError(int errMsgId,
                                    CharSequence errString) {
    if (mCallback != null) {
      if (!selfCancelled) {
        mCallback.onError(errString.toString(), Integer.toString(errMsgId));
      } else {
        mCallback.onCancelled();
      }
    }
  }

  @Override
  public void onAuthenticationFailed() {
    if (mCallback != null)
      mCallback.onError("Authentication Failed", "0");
  }

  @Override
  public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
    if (mCallback != null)
      mCallback.onAuthenticated(result);
  }

  public interface Callback {
    void onAuthenticated(BiometricPrompt.AuthenticationResult result);

    void onError(String errorString, String subCode);

    void onCancelled();
  }
}
