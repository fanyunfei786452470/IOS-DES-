//
//  NSString+DES.m
//  test
//
//  Created by 范云飞 on 2018/5/4.
//  Copyright © 2018年 范云飞. All rights reserved.
//

#import "NSString+DES.h"

#import <CommonCrypto/CommonDigest.h>

#import <CommonCrypto/CommonCryptor.h>

@implementation NSString (DES)

- (NSData *)jm_hexStringConvertToBytesData
{
    //异常字符串
    if (self.length % 2 != 0) {
        return nil;
    }
    
    Byte bytes[1024*3] = {0};
    
    int bytesIndex = 0;
    
    for(int i = 0; i < [self length]; i++)
    {
        
        int int_char;  /// 两位16进制数转化后的10进制数
        
        unichar hex_charUpper = [self characterAtIndex:i]; ///两位16进制数中的第一位(高位*16)
        int int_charUpper;
        if(hex_charUpper >= '0' && hex_charUpper <='9') {
            int_charUpper = (hex_charUpper - 48 ) * 16;   // 0 的Ascll - 48
        } else if(hex_charUpper >= 'A' && hex_charUpper <= 'F') {
            int_charUpper = (hex_charUpper - 55 ) * 16; /// A 的Ascll - 65
        } else {
            int_charUpper = (hex_charUpper - 87 ) * 16; // a 的Ascll - 97
        }
        
        i++;
        
        unichar hex_charLower = [self characterAtIndex:i]; ///两位16进制数中的第二位(低位)
        int int_charLower;
        if(hex_charLower >= '0' && hex_charLower <= '9') {
            int_charLower = (hex_charLower - 48); /// 0 的Ascll - 48
        } else if(hex_charUpper >= 'A' && hex_charUpper <='F') {
            int_charLower = (hex_charLower - 55); ///  A 的Ascll - 65
        } else {
            int_charLower = hex_charLower - 87; /// a 的Ascll - 97
        }
        
        int_char = int_charUpper + int_charLower;
        bytes[bytesIndex] = int_char;  ///将转化后的数放入Byte数组里
        bytesIndex++;
    }
    
    NSUInteger dataLength = self.length / 2;
    
    NSData *data = [[NSData alloc] initWithBytes:bytes length:dataLength];
    
    return data;
}

- (NSString *)jm_urlDecode {
    
    NSString *decodedString = [self stringByRemovingPercentEncoding];
    
    return decodedString;
}

- (NSString *)jm_urlEncode {
    
    NSString *encodedString = [self stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"!*'();:@&=+$,/?%#[]"]];
    
    return encodedString;
}

- (NSString *)jm_encryptUseDESByKey:(NSString *)key iv:(NSString *)iv
{
    NSString *ciphertext;
    NSString *encode = [self jm_urlEncode];
    //    NSLog(@"%s encode::%@", __func__, encode);
    
    NSData *data = [encode dataUsingEncoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = data.length;
    
    NSUInteger bufferLength = 1024;
    
    unsigned char buffer[bufferLength];
    
    memset(buffer, 0, sizeof(char));
    
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          [iv UTF8String] , //iv向量
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferLength,
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        //NSLog(@"%s buffer::%s", __func__, buffer);
        //NSLog(@"%s data::%@", __func__, data);
        
        ciphertext = @"";
        for (int index = 0; index < data.length; index++) {
            char byte;
            [data getBytes:&byte range:NSMakeRange(index, 1)];
            NSString *text = [NSString stringWithFormat:@"%x", byte&0xff];
            
            //不足两位，前面补0
            if([text length] == 1) {
                text = [NSString stringWithFormat:@"0%@", text];
            }
            
            ciphertext = [ciphertext stringByAppendingString:text];
        }
    }
    
    NSLog(@"%s encryptText::%@", __func__, ciphertext);
    return ciphertext;
}

- (NSString *)jm_decryptUseDesByKey:(NSString *)key iv:(NSString *)iv
{
    NSString *decryptText;
    
    NSData *encryptData = [self jm_hexStringConvertToBytesData];
    
    const char *textBytes = [encryptData bytes];
    
    NSUInteger dataLength = encryptData.length;
    
    NSUInteger bufferLength = dataLength + 0x8 & 0xfffffff8;
    
    unsigned char buffer[bufferLength];
    
    memset(buffer, 0, sizeof(char));
    
    size_t numBytesEncrypted = 0;
    
    //将encryptText转化为bytes
    CCCryptorStatus decryptStatus = CCCrypt(kCCDecrypt,
                                            kCCAlgorithmDES,
                                            kCCOptionPKCS7Padding,
                                            [key UTF8String],
                                            kCCKeySizeDES,
                                            [iv UTF8String] , //iv向量
                                            textBytes,
                                            dataLength,
                                            buffer,
                                            bufferLength,
                                            &numBytesEncrypted);
    if (decryptStatus == kCCSuccess ) {
        
        NSLog(@"%s buffer::%s", __func__, buffer);
        
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        
        NSLog(@"%s data::%@", __func__, data);
        
        decryptText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"%s decryptText::%@", __func__, decryptText);
        
        decryptText = [decryptText jm_urlDecode];
        NSLog(@"%s decodeUrl::%@", __func__, decryptText);
        
    }
    
    return decryptText;
}

@end
