//
//  VBNativeAuth.m
//  VBAuth
//
//  Created by Dmitriy Tsurkan on 2/19/18.
//  Copyright © 2018 Dima Tsurkan. All rights reserved.
//

#import "VBNativeAuth.h"
#import "SAMKeychain.h"
#import "EHFAuthenticator.h"
#import <React/RCTUtils.h>

NSString *const CredServiceLogin = @"CredServiceLogin";
NSString *const CredServicePassword = @"CredServicePassword";
NSString *const CredServiceBiometry = @"CredServiceBiometry";
NSString *const CredServiceAttemptCounter = @"CredServiceAttemptCounter";
NSString *const GlobalAccount = @"global";
NSString *const BiometryAccount = @"biometry";
NSInteger const AttemptCounterLimit = 3;

/*
 ERROR CODE:

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

@implementation VBNativeAuth

RCT_EXPORT_MODULE()

-(BOOL)setAttemptCounterValue:(NSInteger) value {
    NSData *payload = [NSData dataWithBytes:&value length:sizeof(value)];
    BOOL counterSuccess = [SAMKeychain setPasswordData:payload forService:CredServiceAttemptCounter account:GlobalAccount];
    return counterSuccess;
}

-(NSInteger)attemptCounterValue {
    NSInteger value = 0;
    NSData* payload = [SAMKeychain passwordDataForService:CredServiceAttemptCounter account:GlobalAccount];
    if(payload) {
        [payload getBytes:&value length:sizeof(value)];
    }
    return value;
}

-(BOOL)incrementAttemptCounterOrCleanWhenLimitExceeded {
    BOOL result;
    NSInteger nextValue = [self attemptCounterValue] + 1;
    if(nextValue >= AttemptCounterLimit ){
        [self _clean];
        result = YES;
    }
    else {
        [self setAttemptCounterValue:nextValue];
        result = NO;
    }
    return result;
}

RCT_EXPORT_METHOD(saveCred:(NSString *)login password:(NSString *)password code:(NSString *)code completion:(RCTResponseSenderBlock)callback){
    [self checkFirstLaunch];

    // argument validation
    NSError* error = NULL;
    NSString* errorString = NULL;
    if(!code || [code length] == 0) {
        error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
        errorString = @"Code must not be empty";
    }
    if(!login || [login length] == 0) {
        error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
        errorString = @"Login must not be empty";
    }
    if(!password || [password length] == 0) {
        error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
        errorString = @"Password must not be empty";
    }
    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
        return;
    }

    // logic

    [SAMKeychain setAccessibilityType:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
    BOOL passwordSuccess = [SAMKeychain setPassword:password forService:CredServicePassword account:code];
    BOOL loginSuccess = [SAMKeychain setPassword:login forService:CredServiceLogin account:code];


    if (passwordSuccess && loginSuccess) {
        [self setAttemptCounterValue:0];
        callback(@[[NSNull null]]);
    } else if (passwordSuccess && !loginSuccess) {
        error = [NSError errorWithDomain:@"Error" code:1 userInfo:nil];
    } else {
        error = [NSError errorWithDomain:@"Error" code:2 userInfo:nil];
    }

    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
    }
}

RCT_EXPORT_METHOD(unlockByCode:(NSString *_Nullable)code completion:(RCTResponseSenderBlock)callback) {
    [self checkFirstLaunch];

    // argument validation
    NSError* error = NULL;
    NSString* errorString = NULL;
    if(!code || [code length] == 0) {
        error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
        errorString = @"Code must not be empty";
    }
    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
        return;
    }

    // logic

    NSString *password = [SAMKeychain passwordForService:CredServicePassword account:code];
    NSString *login = [SAMKeychain passwordForService:CredServiceLogin account:code];

    if (login && password) {
        [self setAttemptCounterValue:0];
        callback(@[[NSNull null], login, password]);
    } else {
        error = [NSError errorWithDomain:@"Error" code:3 userInfo:nil];
    }

    if(error) {
        BOOL cleanOk = [self incrementAttemptCounterOrCleanWhenLimitExceeded];
        if(!cleanOk)
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        else {
            error = [NSError errorWithDomain:@"Error" code:20 userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        }
    }
}

RCT_EXPORT_METHOD(saveCredByBiometry:(NSString *)login password:(NSString *)password completion:(RCTResponseSenderBlock)callback) {
    [self checkFirstLaunch];

    // argument validation
    {
        NSError* error = NULL;
        NSString* errorString = NULL;
        if(!login || [login length] == 0) {
            error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
            errorString = @"Login must not be empty";
        }
        if(!password || [password length] == 0) {
            error = [NSError errorWithDomain:@"Validation error" code:21 userInfo:nil];
            errorString = @"Password must not be empty";
        }
        if(error) {
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
            return;
        }
    }

    // logic

    CFErrorRef error = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    kSecAccessControlTouchIDAny, &error);
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecAccessControlCreateWithFlags error: %@", error];
        NSError* error = [NSError errorWithDomain:@"saveCredByBiometry error" code:1 userInfo:nil];
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
    }
    else {
        NSArray* array = @[login, password];
        NSData *data = [NSKeyedArchiver archivedDataWithRootObject:array];
        NSDictionary *attributes = @{
                                     (id)kSecClass: (id)kSecClassGenericPassword,
                                     (id)kSecAttrService: CredServiceBiometry,
                                     (id)kSecValueData: data,
                                     (id)kSecAttrAccount: BiometryAccount,
                                     (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIAllow,
                                     (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                     };


        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);

        // if item exists, delete it and add new one
        if(status == errSecDuplicateItem) {
            [SAMKeychain deletePasswordForService:CredServiceBiometry];
             status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        }

        if(status == errSecSuccess) {
            callback(@[[NSNull null]]);
        }
        else {
            NSString *errorString = [NSString stringWithFormat:@"SecItemAdd status: %@", [self keychainErrorToString:status]];
            NSError* error = [NSError errorWithDomain:@"saveCredByBiometry error" code:1 userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
        }
    }
}

RCT_EXPORT_METHOD(unlockByBiometry:(NSString *)secUseOperationPrompt completion:(RCTResponseSenderBlock)callback) {
    [self checkFirstLaunch];

    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrService: CredServiceBiometry,
                            (id)kSecAttrAccount: BiometryAccount,
                            (id)kSecMatchLimit: (id)kSecMatchLimitOne,
                            (id)kSecReturnData: @YES,
                            (id)kSecUseOperationPrompt: secUseOperationPrompt,
                            };

    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CFTypeRef dataTypeRef = NULL;

        // query touch id or face id here
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
        if (status == errSecSuccess) {
            NSData *resultData = (__bridge_transfer NSData *)dataTypeRef;
            NSArray *array = [NSKeyedUnarchiver unarchiveObjectWithData:resultData];
            NSString *login = array[0];
            NSString *password = array[1];

            callback(@[[NSNull null], login, password]);
        }
        else {
            NSString *message = [NSString stringWithFormat:@"SecItemCopyMatching status: %@", [self keychainErrorToString:status]];

            NSError* error = [NSError errorWithDomain:@"unlockByBiometry error" code:3 userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], message, error)]);
        }
    });
}

RCT_EXPORT_METHOD(clean:(RCTResponseSenderBlock)callback) {
    NSError* error = NULL;
    BOOL ok = [self _clean];

    if (ok) {
        callback(@[[NSNull null]]);
    } else {
        error = [NSError errorWithDomain:@"Error" code:4 userInfo:nil];
    }

    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
    }
}

- (BOOL)_clean {
//    BOOL passwordSuccess = [SAMKeychain deletePasswordForService:CredServicePassword];
//    BOOL loginSuccess = [SAMKeychain deletePasswordForService:CredServiceLogin];
//    BOOL biometrySuccess = [SAMKeychain deletePasswordForService:CredServiceBiometry];
//    BOOL ok = passwordSuccess && loginSuccess && biometrySuccess;
    [SAMKeychain deletePasswordForService:CredServicePassword];
    [SAMKeychain deletePasswordForService:CredServiceLogin];
    [SAMKeychain deletePasswordForService:CredServiceBiometry];

    return YES;
}

- (NSString *)keychainErrorToString:(OSStatus)error {
    NSString *message = [NSString stringWithFormat:@"%ld", (long)error];

    switch (error) {
        case errSecSuccess:
            message = @"success";
            break;

        case errSecDuplicateItem:
            message = @"error item already exists";
            break;

        case errSecItemNotFound :
            message = @"error item not found";
            break;

        case errSecAuthFailed:
            message = @"error item authentication failed";
            break;

        default:
            break;
    }

    return message;
}

- (void)checkFirstLaunch {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if([defaults boolForKey:@"wasLaunchBefore"] == NO) {
        [self _clean];
        [defaults setBool:YES forKey:@"wasLaunchBefore"];
    }
}

@end
