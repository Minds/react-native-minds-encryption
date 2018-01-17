#import "Crypto.h"
#import "RSANative.h"

@implementation Crypto

- (dispatch_queue_t)methodQueue {
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.publicKey = key;
    NSString *encodedMessage = [rsa encrypt:message];
    resolve(encodedMessage);
}

RCT_EXPORT_METHOD(decrypt:(NSString *)encodedMessage withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.privateKey = key;
    NSString *message = [rsa decrypt:encodedMessage];
    resolve(message);
}

RCT_EXPORT_METHOD(encrypt64:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.publicKey = key;
    NSString *encodedMessage = [rsa encrypt64:message];
    resolve(encodedMessage);
}

RCT_EXPORT_METHOD(decrypt64:(NSString *)encodedMessage withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.privateKey = key;
    NSString *message = [rsa decrypt64:encodedMessage];
    resolve(message);
}


RCT_EXPORT_METHOD(sign:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.privateKey = key;
    NSString *signature = [rsa sign:message];
    resolve(signature);
}

RCT_EXPORT_METHOD(sign64:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.privateKey = key;
    NSString *signature = [rsa sign64:message];
    resolve(signature);
}

RCT_EXPORT_METHOD(verify:(NSString *)signature withMessage:(NSString *)message andKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.publicKey = key;
    BOOL valid = [rsa verify:signature withMessage:message];
    resolve(@(valid));
}

RCT_EXPORT_METHOD(verify64:(NSString *)signature withMessage:(NSString *)message andKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    rsa.publicKey = key;
    BOOL valid = [rsa verify64:signature withMessage:message];
    resolve(@(valid));
}

@end