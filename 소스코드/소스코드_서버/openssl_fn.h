#pragma once

#include <fstream>

#include <thread>






#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "authserver.h"

#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  59     //Public exponent should be a prime number.
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

#define AA 12
#define LOG(x)  (cout << x << endl)
 
RSA* load_RSA(int pem_type, char* file_name);

int public_encrypt(unsigned char* data, int data_len, RSA* key, unsigned char* encrypted);

int private_decrypt(unsigned char* enc_data, int data_len, RSA* key, unsigned char* decrypted);


#endif //RSA_ALGORITHM_H

int publicEncrypt(char* encrypt, char* result);

void privateDecrypt(int len, char* encrypt, char* result);

void hasing_(char* string, char* mdString);

void hasing(char* string, char* mdString, int n);

char* base64(const unsigned char* input, int length, int& result_len);

char* decode64(unsigned char* input, int length);