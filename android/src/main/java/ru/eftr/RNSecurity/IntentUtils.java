package ru.eftr.RNSecurity;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

public class IntentUtils {

    public static String[] PERMISSIONS_TOUCH_ID = {Manifest.permission.USE_FINGERPRINT};

    public static boolean isPermitionsGranted(Context context, String[] permissions, int permitionRequestId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {

            List<String> requestPermitions = new ArrayList<>();
            for(String permission: permissions){
                if (ContextCompat.checkSelfPermission(context,
                        permission)
                        != PackageManager.PERMISSION_GRANTED){
                    requestPermitions.add(permission);
                }
            }

            if(requestPermitions.size()>0) {

                String[] notGrantedPermissions = new String[requestPermitions.size()];
                notGrantedPermissions = requestPermitions.toArray(notGrantedPermissions);

                ((Activity)context).requestPermissions(notGrantedPermissions,
                        permitionRequestId);

                return false;
            }
        }

        return true;
    }
}
