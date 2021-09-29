#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <Windows.h>
#include "openssl_fn.h"

using namespace std;

int padding = RSA_PKCS1_PADDING;


/*
해시함수
*parameter: 평문 메시지, 해시된 메시지를 넣을 변수
*return: 없음
*/
void hasing_(char* string, char* mdString) {
	unsigned char digest[SHA_DIGEST_LENGTH];

	SHA1((unsigned char*)string, strlen(string), (unsigned char*)digest);

	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);
}


/*
해시함수 n번 반복
*parameter: 평문 메시지, 해시된 메시지, 해시함수 반복 횟수
*return: 없음
*/
void hasing(char* string, char* mdString, int n)
{
	unsigned char tmp[SHA_DIGEST_LENGTH * 2 + 1];
	memcpy(tmp, string, strlen((char*)string) + 1);

	for (int i = 0; i < n; i++)
	{
		hasing_((char*)tmp, (char*)mdString);
		strcpy((char*)tmp, (char*)mdString);
	}
};


/*
유니코드 문자열을 아스키 문자열로 변환
*parameter: 유니코드 문자열
*return: 아스키 문자열
*/
//네이버 블로그 소스코드 인용
char* ConvertWCtoC(wchar_t* str)
{
	char* pStr;
	int strSize = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
	pStr = new char[strSize];
	WideCharToMultiByte(CP_ACP, 0, str, -1, pStr, strSize, 0, 0);
	return pStr;
}


/*
아스키 문자열을 유니코드 문자열로 변환
*parameter: 아스키 문자열
*return: 유니코드 문자열
*/
//네이버 블로그 소스코드 인용
wchar_t* ConverCtoWC(char* str)
{
	wchar_t* pStr;
	int strSize = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, NULL);
	pStr = new WCHAR[strSize];
	MultiByteToWideChar(CP_ACP, 0, str, strlen(str) + 1, pStr, strSize);
	return pStr;
}


/*
RSA 키 파일 불러오기
*parameter: 키 타입( 0: 개인키, 1: 공개키 ), 파일 이름
*return: RSA 구조체
*/
RSA* load_RSA(int pem_type, char* file_name) 
{
	RSA* rsa = NULL;
	FILE* fp = NULL;

	if (pem_type == PUBLIC_KEY_PEM) 
	{
		fp = fopen(file_name, "rb");
		PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
		fclose(fp);
	}
	else if (pem_type == PRIVATE_KEY_PEM) 
	{
		fp = fopen(file_name, "rb");
		PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
		fclose(fp);
	}
	return rsa;
}


/*
서버 공개키로 암호화
*parameter: 평문 메시지, 암호화된 메시지가 저장될 문자열 변수
*return: 암호화된 메시지 길이
*/
int publicEncrypt(char* encrypt, char* result)
{
	RSA* publicKey = load_RSA(PUBLIC_KEY_PEM, (char*)"public_key");

	int encrypted_length = public_encrypt((unsigned char*)encrypt, strlen(encrypt), publicKey, (unsigned char*)result);
	if (encrypted_length == -1) 
	{
		exit(0);
	}
	result[encrypted_length] = 0;
	RSA_free(publicKey);

	return encrypted_length;
}
int public_encrypt(unsigned char* data, int data_len, RSA* key, unsigned char* encrypted)
{
	int result = RSA_public_encrypt(data_len, data, encrypted, key, padding);
	return result; 
}


/*
BASE64 인코딩 된 메시지를 본문으로 디코딩
*parameter: BASE64 인코딩된 문자열, BASE64인코딩된 문자열의 길이
*return: 디코딩된 본문 메시지
*/
char* decode64(unsigned char* input, int length)
{
	BIO* b64, *bmem;

	char* buffer = (char*)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}


/*
평문 메시지를 BASE64 인코딩 된 메시지로 인코딩
*parameter: 평문 메시지, 인코딩 결과물의 길이, 결과물의 길이가 삽입될 변수
*return: BASE64 인코딩 된 메시지
*/
char* base64(const unsigned char* input, int length, int& result_len)
{
	BIO* bmem, *b64;
	BUF_MEM* bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char* buff = (char*)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length - 1);
	buff[bptr->length - 1] = 0;
	result_len = bptr->length - 1;
	BIO_free_all(b64);

	return buff;
}
