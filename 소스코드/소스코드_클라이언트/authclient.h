#pragma once
#include "openssl_fn.h"

#include <WinSock2.h>

typedef struct SOCK_MSG
{
	char header[16];  //메시지 헤더
	char contents[4096]; //메시지 본문
}SOCK_MSG;

class AuthClient
{
private:
	WSADATA wsaData;
	SOCKET hServSock;
	SOCKADDR_IN servAdr;

	char* encrypt;
	char* decrypt;

public:
	char sym_key[64];
	//static std::queue<MSG_QUEUE> msg_list; //수신된 메세지가 저장되는 큐
	AuthClient(const char* ip, int port); //서버를 열기위한 생성자
	~AuthClient();

	int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key); //DES 암호화 함수
	int decrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key); //DES 복호화 함수

	void parse_msg(const char* msg, int Count, ...); //메시지 처리 함수
	void recv_msg(void (*fp)(SOCK_MSG& msg, AuthClient& obj)); //메시지 받는 함수
	void send_msg(const char* header, int Count, ...); //메시지 보내는 함수
};