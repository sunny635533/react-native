/**
 * Copyright (c) 2015-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#import "RCTHTTPRequestHandler.h"

#import <mutex>

#import "RCTNetworking.h"

@interface RCTHTTPRequestHandler () <NSURLSessionDataDelegate>

@end

@implementation RCTHTTPRequestHandler
{
  NSMapTable *_delegates;
  NSURLSession *_session;
  std::mutex _mutex;
}

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE()

- (void)invalidate
{
  [_session invalidateAndCancel];
  _session = nil;
}

- (BOOL)isValid
{
  // if session == nil and delegates != nil, we've been invalidated
  return _session || !_delegates;
}

#pragma mark - NSURLRequestHandler

- (BOOL)canHandleRequest:(NSURLRequest *)request
{
  static NSSet<NSString *> *schemes = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    // technically, RCTHTTPRequestHandler can handle file:// as well,
    // but it's less efficient than using RCTFileRequestHandler
    schemes = [[NSSet alloc] initWithObjects:@"http", @"https", nil];
  });
  return [schemes containsObject:request.URL.scheme.lowercaseString];
}

- (NSURLSessionDataTask *)sendRequest:(NSURLRequest *)request
                         withDelegate:(id<RCTURLRequestDelegate>)delegate
{
  // Lazy setup
  if (!_session && [self isValid]) {
    NSOperationQueue *callbackQueue = [NSOperationQueue new];
    callbackQueue.maxConcurrentOperationCount = 1;
    callbackQueue.underlyingQueue = [[_bridge networking] methodQueue];
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    [configuration setHTTPShouldSetCookies:YES];
    [configuration setHTTPCookieAcceptPolicy:NSHTTPCookieAcceptPolicyAlways];
    [configuration setHTTPCookieStorage:[NSHTTPCookieStorage sharedHTTPCookieStorage]];
    _session = [NSURLSession sessionWithConfiguration:configuration
                                             delegate:self
                                        delegateQueue:callbackQueue];

    std::lock_guard<std::mutex> lock(_mutex);
    _delegates = [[NSMapTable alloc] initWithKeyOptions:NSPointerFunctionsStrongMemory
                                           valueOptions:NSPointerFunctionsStrongMemory
                                               capacity:0];
  }

  NSURLSessionDataTask *task = [_session dataTaskWithRequest:request];
  {
    std::lock_guard<std::mutex> lock(_mutex);
    [_delegates setObject:delegate forKey:task];
  }
  [task resume];
  return task;
}

- (void)cancelRequest:(NSURLSessionDataTask *)task
{
  {
    std::lock_guard<std::mutex> lock(_mutex);
    [_delegates removeObjectForKey:task];
  }
  [task cancel];
}

#pragma mark - NSURLSession delegate

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    // 忽略证书验证
//    completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
    
    NSLog(@"didReceiveChallenge ");
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString *host = challenge.protectionSpace.host;
        NSLog(@"-------------server 11111---------%@", host);
        
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    }else if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])
    {
         NSLog(@"-------------server 22222222---------");
        //TODO:设置客户端证书认证
         SecIdentityRef myIdentity;
        
        SecCertificateRef myCertificateTest = [self getSecCertificateRef:@"HSWLROOTCAforInternalTest" toIdentity:&myIdentity];
        SecCertificateRef myCertificate = [self getSecCertificateRef:@"HSWLROOTCA" toIdentity:&myIdentity];
        
        
        const void *certs[] = { myCertificateTest,myCertificate };
        CFArrayRef certsArray =CFArrayCreate(NULL, certs,1,NULL);
        NSURLCredential *credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    }
}

-(SecCertificateRef) getSecCertificateRef:(NSString *)name toIdentity:(SecIdentityRef*)identity{
    NSString * cerPath = [[NSBundle mainBundle] pathForResource:name ofType:@"crt"]; //证书的路径
    NSData *p12data = [NSData dataWithContentsOfFile:cerPath];
    CFDataRef inP12data = (__bridge CFDataRef)p12data;
    
    OSStatus status = [self extractIdentity:inP12data toIdentity:identity];
    if (status != 0) {
        return NULL;
    }
    SecCertificateRef myCertificate;
    SecIdentityCopyCertificate(*identity, &myCertificate);
    return myCertificate;
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data toIdentity:(SecIdentityRef*)identity {
    OSStatus securityError = errSecSuccess;
    CFStringRef password = CFSTR("123456");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    if (securityError == 0)
    {
        CFDictionaryRef ident = (CFDictionaryRef)CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
    }
    else
    {
        NSLog(@"clinet.p12 error!");
    }
    
    if (options) {
        CFRelease(options);
    }
    return securityError;
}


- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didSendDataWithProgress:totalBytesSent];
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveResponse:response];
  completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
    didReceiveData:(NSData *)data
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
    [_delegates removeObjectForKey:task];
  }
  [delegate URLRequest:task didCompleteWithError:error];
}

@end
