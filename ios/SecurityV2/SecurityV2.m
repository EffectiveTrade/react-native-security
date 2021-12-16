//
//  SecurityV2.m
//  VBNativeAuth
//
//  Created by Dmitry Chudnyy on 11/02/2019.
//  Copyright © 2019 ORGANIZATIONNAME. All rights reserved.
//

#import "SecurityV2.h"
#import "SAMKeychain.h"
#import "EHFAuthenticator.h"
#import <React/RCTUtils.h>

NSString *const SecurityV2_Service_AttemptCounter = @"SecurityV2_Service_AttemptCounter";
NSString *const SecurityV2_Service_Code = @"SecurityV2_Service_Code";
NSString *const SecurityV2_Service_Creds = @"SecurityV2_Service_Creds";
NSString *const SecurityV2_Service_Biometry = @"SecurityV2_Service_Biometry";
NSString *const SecurityV2_GlobalAccount = @"SecurityV2_global";
NSInteger const SecurityV2_AttemptCounterLimit = 3;
NSString *const SecurityV2_BiometryKeyChainValue = @"SecurityV2_BiometryKeyChainValue";
NSString *const SecurityV2_FirstLaunchFlag = @"SecurityV2_FirstLaunchFlag";

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
 PINCODE_CHECK_FAILED = 21,

 LOCKED = 40,
 CANT_SET_CODE = 41,
 CANT_SET_BIOMETRY = 42,

 */

@interface SecurityV2 ()

@property (nonatomic, assign) BOOL _isLocked;

@end

@implementation SecurityV2

- (id) init {
    self = [super init];
    if (self != nil) {
        [self checkFirstLaunch];
        [self refreshInitState];
    }
    return self;
}

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
    return YES;
}

-(BOOL)setAttemptCounterValue:(NSInteger) value {
    NSData *payload = [NSData dataWithBytes:&value length:sizeof(value)];
    BOOL counterSuccess = [SAMKeychain setPasswordData:payload forService:SecurityV2_Service_AttemptCounter account:SecurityV2_GlobalAccount];
    return counterSuccess;
}

-(NSInteger)attemptCounterValue {
    NSInteger value = 0;
    NSData* payload = [SAMKeychain passwordDataForService:SecurityV2_Service_AttemptCounter account:SecurityV2_GlobalAccount];
    if(payload) {
        [payload getBytes:&value length:sizeof(value)];
    }
    return value;
}

-(BOOL)incrementAttemptCounterOrCleanWhenLimitExceeded {
    BOOL result;
    NSInteger nextValue = [self attemptCounterValue] + 1;
    if(nextValue >= SecurityV2_AttemptCounterLimit ){
        [self _clean];
        result = YES;
    }
    else {
        [self setAttemptCounterValue:nextValue];
        result = NO;
    }
    return result;
}

-(NSError*)ensureUnlocked {
    if(self._isLocked) {
        return [NSError errorWithDomain:@"Error" code:40 userInfo:nil];
    }

    return NULL;
}

- (NSError*) ensureBiometrySupported {
    if (@available(iOS 11.0, *)) {
        LAContext *context = [[LAContext alloc] init];
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]){
            if(context.biometryType == LABiometryTypeTouchID || context.biometryType == LABiometryTypeFaceID) {
                return NULL;
            }
        }
    }

    return [NSError errorWithDomain:@"Error" code:7 userInfo:nil];
}

// NSUserDefaults очищаются при удалении приложения с устройства, а KeyChain нет
// поэтому, чтобы при запуске после установки не были получены старые данные из KeyChain,
// мониторим первый запуск по NSUserDefaults и делаем очистку KeyChain
- (void)checkFirstLaunch {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if([defaults boolForKey:SecurityV2_FirstLaunchFlag] == NO) {
        [self _clean];
        [defaults setBool:YES forKey:SecurityV2_FirstLaunchFlag];
    }
}

- (void)refreshInitState {
    self._isLocked = ![self _isEmpty];
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

//clean(options?: {}): Promise<void>;

RCT_EXPORT_METHOD(clean:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
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
    [SAMKeychain deletePasswordForService:SecurityV2_Service_AttemptCounter];
    [SAMKeychain deletePasswordForService:SecurityV2_Service_Code];
    [SAMKeychain deletePasswordForService:SecurityV2_Service_Creds];
    [SAMKeychain deletePasswordForService:SecurityV2_Service_Biometry];
    self._isLocked = NO;

    return YES;
}

- (BOOL)_isEmpty {
    NSString *v1 = [SAMKeychain passwordForService:SecurityV2_Service_AttemptCounter account:SecurityV2_GlobalAccount];
    NSString *v2 = [SAMKeychain passwordForService:SecurityV2_Service_Code account:SecurityV2_GlobalAccount];
    NSString *v3 = [SAMKeychain passwordForService:SecurityV2_Service_Creds account:SecurityV2_GlobalAccount];
    // не запрашивается, так как вызывает запрос на аутенитификацию по биометрии
//    NSString *v4 = [SAMKeychain passwordForService:SecurityV2_Service_Biometry account:SecurityV2_GlobalAccount];
    BOOL isEmpty = !v1 && !v2 && !v3;

    return isEmpty;
}

//lock(options?: {}): Promise<void>;

RCT_EXPORT_METHOD(lock:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    self._isLocked = YES;
    callback(@[[NSNull null]]);
}

//save(cred: string | undefined, options?: {}): Promise<void>;

RCT_EXPORT_METHOD(save:(NSString*)creds options:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSError* error = [self ensureUnlocked];

    if(!error) {
        [SAMKeychain setAccessibilityType:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
        BOOL ok = [SAMKeychain setPassword:creds forService:SecurityV2_Service_Creds account:SecurityV2_GlobalAccount];
        if (!ok) {
            error = [NSError errorWithDomain:@"Error" code:1 userInfo:nil];
        }
    }

    if(!error) {
        callback(@[[NSNull null]]);
    } else {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
    }
}

//read(options?: {}): Promise<string | undefined>;

RCT_EXPORT_METHOD(read:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSError* error = [self ensureUnlocked];

    if(!error) {
        NSString *creds = [SAMKeychain passwordForService:SecurityV2_Service_Creds account:SecurityV2_GlobalAccount];
        if (!creds) {
            error = [NSError errorWithDomain:@"Error" code:3 userInfo:nil];
        } else {
            callback(@[[NSNull null], creds]);
        }
    }

    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
    }
}

//setUnlockCode(code: string, options?: {}): Promise<void>;

RCT_EXPORT_METHOD(setUnlockCode:(NSString*)code options:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSError* error = [self ensureUnlocked];

    if(!error) {
        [SAMKeychain setAccessibilityType:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
        BOOL ok = [SAMKeychain setPassword:code forService:SecurityV2_Service_Code account:SecurityV2_GlobalAccount];
        if (!ok) {
            error = [NSError errorWithDomain:@"Error" code:41 userInfo:nil];
        }
    }

    if(!error) {
        callback(@[[NSNull null]]);
    } else {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
    }
}

//unlockByCode(code: string, options?: {}): Promise<void>;

RCT_EXPORT_METHOD(unlockByCode:(NSString*)code options:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSError* error = NULL;

    NSString *unlockCode = [SAMKeychain passwordForService:SecurityV2_Service_Code account:SecurityV2_GlobalAccount];
    BOOL ok = unlockCode && code && [unlockCode isEqualToString:code];
    if (!ok) {
        self._isLocked = YES;
        error = [NSError errorWithDomain:@"Error" code:21 userInfo:nil];
    } else {
        self._isLocked = NO;
        [self setAttemptCounterValue:0];
    }

    if(!error) {
        callback(@[[NSNull null]]);
    } else {
        BOOL cleanOk = [self incrementAttemptCounterOrCleanWhenLimitExceeded];
        if(!cleanOk)
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        else {
            error = [NSError errorWithDomain:@"Error" code:20 userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        }
    }
}

//setUnlockBiometry(options?: {}): Promise<void>;

RCT_EXPORT_METHOD(setUnlockBiometry:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSError* error = [self ensureUnlocked];
    if(!error) {
        error = [self ensureBiometrySupported];
    }

    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        return;
    }

    // logic

    CFErrorRef errorRef = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    kSecAccessControlTouchIDAny, &errorRef);
    if (sacObject == NULL || errorRef != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecAccessControlCreateWithFlags error: %@", errorRef];
        NSError* error = [NSError errorWithDomain:@"saveCredByBiometry error" code:1 userInfo:nil];
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
    }
    else {
        NSArray* array = @[SecurityV2_BiometryKeyChainValue];
        NSData *data = [NSKeyedArchiver archivedDataWithRootObject:array];
        NSDictionary *attributes = @{
                                     (id)kSecClass: (id)kSecClassGenericPassword,
                                     (id)kSecAttrService: SecurityV2_Service_Biometry,
                                     (id)kSecValueData: data,
                                     (id)kSecAttrAccount: SecurityV2_GlobalAccount,
                                     (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIAllow,
                                     (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                     };

        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);

        // if item exists, delete it and add new one
        if(status == errSecDuplicateItem) {
            [SAMKeychain deletePasswordForService:SecurityV2_Service_Biometry];
            status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        }

        if(status == errSecSuccess) {
            callback(@[[NSNull null]]);
        }
        else {
            NSString *errorString = [NSString stringWithFormat:@"SecItemAdd status: %@", [self keychainErrorToString:status]];
            error = [NSError errorWithDomain:@"setUnlockBiometry error" code:42 userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], errorString, error)]);
        }
    }
}

//unlockByBiometry(options?: {}): Promise<void>;

RCT_EXPORT_METHOD(unlockByBiometry:(NSDictionary *)options completion:(RCTResponseSenderBlock)callback) {
    NSString* secUseOperationPrompt = options ? options[@"text"] : NULL;
    NSError* error = [self ensureBiometrySupported];
    if(error) {
        callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
        return;
    }

    NSDictionary *query = @{
                            (id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrService: SecurityV2_Service_Biometry,
                            (id)kSecAttrAccount: SecurityV2_GlobalAccount,
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
            NSString *value = array[0];
            BOOL ok = value && [value isEqualToString:SecurityV2_BiometryKeyChainValue];
            if(ok) {
                self._isLocked = NO;
                [self setAttemptCounterValue:0];
                callback(@[[NSNull null]]);
            } else {
                NSError* error = [NSError errorWithDomain:@"unlockByBiometry error" code:3 userInfo:nil];
                callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], error.domain, error)]);
            }
        }
        else {
            NSString *message = [NSString stringWithFormat:@"SecItemCopyMatching status: %@", [self keychainErrorToString:status]];
            NSInteger code = 3;
            if(status == errSecUserCanceled) {
                code = 12;
            }
            NSError* error = [NSError errorWithDomain:@"unlockByBiometry error" code:code userInfo:nil];
            callback(@[RCTJSErrorFromCodeMessageAndNSError([@(error.code) stringValue], message, error)]);
        }
    });
}

@end
