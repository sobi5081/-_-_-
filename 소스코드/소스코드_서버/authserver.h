#pragma once
#include <queue>
#include <WinSock2.h>

#include "openssl_fn.h"

typedef struct SOCK_MSG
{
	char header[16];
	char contents[4096];
}SOCK_MSG;

typedef struct MSG_QUEUE
{
	SOCKET sock;
	SOCK_MSG msg;
	char sym_key[32];
}MSG_QUEUE;

class AuthServer
{
private:
	WSADATA wsaData;
	SOCKET hServSock, hCintSock;
	SOCKADDR_IN servAdr, cIntAdr;
	RSA* keypair;
	RSA* private_key;
	RSA* public_key;
	char* encrypt;
	char* decrypt;
	char private_key_pem[12] = "private_key";
	char public_key_pem[11] = "public_key";
public:
	static std::queue<MSG_QUEUE> msg_list; //수신된 메세지가 저장되는 큐
	AuthServer(int port); //서버를 열기위한 생성자
	~AuthServer();
	void wait(); //사용자 접속을 대기하는 함수

	int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);
	int decrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);

	bool isEmpty(); //수신된 메시지 존재 여부 확인 함수
	MSG_QUEUE& peekMessage(); //큐에 쌓인 메시지 중 가장 먼저 도착한 메시지를 가져옴
	void popMessage(); //큐에서 메시지를 뺌

	static void parse_msg(const char* msg, int Count, ...); //메시지 보내는 함수
	static void send_msg(SOCKET sock, const char* header, int Count, ...); //메시지 보내는 함수
	static void process_msg(SOCKET sock, std::string msg, std::string &sym_key); //수신된 메시지 처리해서 큐에 넣어줌(구조체화시켜서 샵같은거빼고 스레드에넣어줌)
	static void clientThread(SOCKET sock);//클라이언트인증+수신된메시지를 proces_msg에 넣어줌
};