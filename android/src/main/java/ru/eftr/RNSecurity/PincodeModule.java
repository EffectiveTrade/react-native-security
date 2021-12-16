package ru.eftr.RNSecurity;

import android.content.Context;
import android.provider.Settings;
import androidx.annotation.Nullable;
import android.util.Base64;

import ru.eftr.RNSecurity.helpers.AESCrypt;
import ru.eftr.RNSecurity.model.ErrorCode;
import ru.eftr.RNSecurity.model.RNException;
import ru.eftr.RNSecurity.sharedPreferences.DataHelper;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

public class PincodeModule {
    protected static final String SEPARATOR = "some_separator";

    public static String[] decryptByPincode(Context context, String pincode) throws RNException{
        // Check HASH
        String deviceId = Settings.Secure.getString(context.getContentResolver(),
                Settings.Secure.ANDROID_ID);

        // calculate CHECK HASH
        String checkHash = encodeCodeDeviceId(pincode, deviceId);

        String savedCheckHash = DataHelper.getCheckHash(context);

        if (checkHash == null || savedCheckHash == null || !checkHash.equals(savedCheckHash)) {
            throw new RNException(ErrorCode.PINCODE_CHECK_FAILED);
        }

        try {
            String keyHash = sha256(deviceId + pincode);

            String encodedLoginpass = DataHelper.getLoginPass(context);

            String decodedLoginpass = AESCrypt.decrypt(keyHash, encodedLoginpass);

            if (decodedLoginpass == null)
                throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);

            String[] values = decodedLoginpass.split(SEPARATOR);

            if (values.length != 3)
                throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);

            String t1 = values[0] + SEPARATOR + values[1];
            String sha256LoginPass = sha256(t1);

            if (!sha256LoginPass.equals(values[2]))
                throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);

            return values;

        } catch (NoSuchAlgorithmException e) {
            throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);
        } catch (UnsupportedEncodingException e) {
            throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);
        } catch (GeneralSecurityException e) {
            throw new RNException(ErrorCode.PINCODE_DECRYPT_FAILED);
        }
    }

    public static void encryptByPincode(Context context, String login, String password, String code) throws RNException {
        String deviceId = Settings.Secure.getString(context.getContentResolver(),
                Settings.Secure.ANDROID_ID);

        // calculate CHECK HASH
        String checkHash = encodeCodeDeviceId(code, deviceId);

        // save CHECK HASH
        DataHelper.setCheckHash(context, checkHash);

        // encode login pass
        String loginpass = encrypt(deviceId, login, password, code);

        DataHelper.setLoginPass(context, loginpass);
    }

    @Nullable
    private static String encrypt(String deviceId, String login, String pass, String pincode) throws RNException{
        String encodedString = null;
        try {
            String t1 = login + SEPARATOR + pass;
            String sha256LoginPass = sha256(t1);

            String t2 = login + SEPARATOR + pass + SEPARATOR + sha256LoginPass;

            String keyHash = sha256(deviceId + pincode);

            try {
                encodedString = AESCrypt.encrypt(keyHash, t2);
            } catch (GeneralSecurityException e) {
                throw new RNException(ErrorCode.PINCODE_ENCRYPT_FAILED);
            }

            return encodedString;
        } catch (NoSuchAlgorithmException e) {
            throw new RNException(ErrorCode.PINCODE_ENCRYPT_FAILED);
        }catch (UnsupportedEncodingException e){
            throw new RNException(ErrorCode.PINCODE_ENCRYPT_FAILED);
        }

    }

    public static String sha256(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text.getBytes("UTF-8"));
        byte[] digest = md.digest();
        return String.format("%064x", new java.math.BigInteger(1, digest));
    }

    public static String encodeCodeDeviceId(String secret, String deviceId) throws RNException{
        try {

            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);

            String hash = new String(Base64.encode(sha256_HMAC.doFinal(deviceId.getBytes()), 0));
            return hash.replace("\n", "").replace("\r", "");
        } catch (Exception e) {
            throw new RNException(ErrorCode.PINCODE_ENCRYPT_FAILED);
        }
    }
}
