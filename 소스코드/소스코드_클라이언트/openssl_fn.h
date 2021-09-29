#pragma once

#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  59     
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0

#define AA 12
#define LOG(x)  (cout << x << endl)

RSA* load_RSA(int pem_type, char* file_name);

#endif //RSA_ALGORITHM_H


int public_encrypt(unsigned char* data, int data_len, RSA* key, unsigned char* encrypted);

int publicEncrypt(char* encrypt, char* result);

char* decode64(unsigned char* input, int length);

char* base64(const unsigned char* input, int length, int& result_len);

void hasing_(char* string, char* mdString);

void hasing(char* string, char* mdString, int n);

char* ConvertWCtoC(wchar_t* str);

wchar_t* ConverCtoWC(char* str);
