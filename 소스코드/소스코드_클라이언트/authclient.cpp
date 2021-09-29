#include <string>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "authclient.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2
#define RSA_ALGORITHM_H

/*클라이언트 객체 생성자. 매개변수의 값을 통하여 해당 서버로 연결 수행.
*parameter: 서버 IP, 포트번호
*return: 없음
*/
AuthClient::AuthClient(const char* ip, int port)
{
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	hServSock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&servAdr, 0, sizeof(servAdr));
	servAdr.sin_family = AF_INET;

	servAdr.sin_addr.s_addr = inet_addr(ip);

	servAdr.sin_port = htons(50000);

	connect(hServSock, (SOCKADDR*)& servAdr, sizeof(servAdr));

	std::string msg_buf = "";
	int recv_len = sizeof(SOCK_MSG);
	int len = 0;

} //서버를 열기위한 생성자


/*클라이언트 객체 소멸자. 사용한 자원 해제.
*parameter: 서버 IP, 포트번호
*return: 없음
*/
AuthClient::~AuthClient()
{
	closesocket(hServSock);
	WSACleanup();
}


/*패킷 메시지의 공백 문자 '#'을 제거
*parameter: 메시지 본문
*return: 없음
*/
void split(char* buf)
{
	char* msg = buf;
	for (int i = 0; i < 4096; i++)
	{
		if (msg[i] == '#') {
			msg[i] = 0;
			break;
		}
	}

}


/*메시지 본문에서 ','를 기준으로 메시지를 분리
*parameter: 메시지 본문, 분리될 메시지 개수, 각 메시지가 삽입될 문자열 변수들(가변인자).
*return: 없음
*/
void AuthClient::parse_msg(const char* msg, int Count, ...)
{
	char* buf;
	//-----가변인자
	va_list Marker;
	va_start(Marker, Count);
	buf = strtok((char*)msg, ",");
	for (int i = 0; i < Count; i++) {
		strcpy(va_arg(Marker, char*), buf);

		if (i != Count - 1) buf = strtok(NULL, ",");
	}
	va_end(Marker);
	//-----가변인자 끝
}


/*서버로부터 수신된 메시지를 길이에 맞게 수신. 처리된 메시지는 메시지 처리 함수로 전달.
*parameter: 메시지 처리 함수 콜백함수.
*return: 없음
*/
void AuthClient::recv_msg(void (*fp)(SOCK_MSG& msg, AuthClient& obj)) {
	std::string msg_buf = "";
	int recv_len = sizeof(SOCK_MSG);
	int len = 0;
	char buf[8192];
	while (1) 
	{
		len = recv(hServSock, (char*)& buf, recv_len, 0);
		if (len == -1)
			break;

		buf[len] = 0;

		recv_len -= len;
		msg_buf += buf;
		if (recv_len == 0)
		{
			//process_msg(msg_buf);
			SOCK_MSG* message = (SOCK_MSG*)msg_buf.c_str(); //string을 char로 바꿔서 구조체로 만들어줌
			split(message->header); //헤더랑 컨텐츠의 첫 #을 널문자로 바꿔줌
			split(message->contents);
			fp(*message, *this);

			msg_buf = "";
			recv_len = sizeof(SOCK_MSG);
		}
	}
}


/*DES 암호화 함수
*parameter: 암호화된 메시지가 저장 될 변수, 평문 메시지, 평문 메시지 길이, 대칭키값
*return: 암호화된 메시지 길이
*/
//깃허브 소스코드 참조
int AuthClient::encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	int addLen = 0, orgLen = 0;
	unsigned long err = 0;

	ERR_load_crypto_strings();
	EVP_CIPHER_CTX_init(ctx);
	if (EVP_EncryptInit(ctx, EVP_des_cfb8(), key, NULL) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptInit() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}
	if (EVP_EncryptUpdate(ctx, cipherText, &orgLen, plainText, plainTextLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptUpdate() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}

	if (EVP_EncryptFinal(ctx, cipherText + orgLen, &addLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_EncryptFinal() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	ERR_free_strings();
	return addLen + orgLen;
}

/*DES 복호화 함수
*parameter: 복호화된 메시지가 저장 될 변수, 암호화된 메시지 본문, 암호화된 메시지 본문 길이, 대칭키값
*return: 복화화된 메시지 길이
*/
//깃허브 소스코드 참조
int AuthClient::decrypt_block(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned long err = 0;
	int toLen = 0, outLen = 0;

	ERR_load_crypto_strings();
	EVP_CIPHER_CTX_init(ctx);

	if (EVP_DecryptInit(ctx, EVP_des_cfb8(), key, NULL) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptInit() - %s\n", ERR_error_string(err, NULL));
		return -1;
	}
	if (EVP_DecryptUpdate(ctx, plainText, &toLen, cipherText, cipherTextLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptUpdate() - %s\n", ERR_error_string(err, NULL));

		return -1;
	}

	if (EVP_DecryptFinal(ctx, &plainText[cipherTextLen], &outLen) != 1) {
		err = ERR_get_error();
		printf("ERR: EVP_DecryptFinal() - %s\n", ERR_error_string(err, NULL));

		return -1;
	}

	EVP_CIPHER_CTX_cleanup(ctx);
	ERR_free_strings();

	return toLen + outLen;
}

/*서버측으로 전송할 메시지를 입력받아 메시지 프로토콜에 맞게 설정 후 전송.
*parameter: 메시지 헤더, 내용의 개수, 내용(가변인자)
*return: 없음
*/
void AuthClient::send_msg(const char* header,int Count, ...)
{
	SOCK_MSG msg;
	std::string buf="";
	char header_[16];
	char contents_[4096];
	strcpy(header_, header);
	
	//-----가변인자
	va_list Marker = NULL;
	va_start(Marker, Count);
	for (int i = 0; i < Count; i++){
		buf += va_arg(Marker, char*);
		if (i != (Count - 1))
			buf.append(",");
	}
	va_end(Marker);
	//-----가변인자 끝
	strcpy(contents_, buf.c_str());

	for (int i = strlen(header_); i < 16; i++)
		header_[i] = '#'; //문자열의 마지막에 # 넣어줌
	for (int i = buf.size(); i < 4096; i++)
		contents_[i] = '#'; //문자열의 마지막에 # 넣어줌

	strncpy(msg.header, header_, 16);
	strncpy(msg.contents, contents_, 4096);
	send(hServSock, (char*)& msg, sizeof(SOCK_MSG), 0);
}
