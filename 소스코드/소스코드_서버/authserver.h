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
	static std::queue<MSG_QUEUE> msg_list; //���ŵ� �޼����� ����Ǵ� ť
	AuthServer(int port); //������ �������� ������
	~AuthServer();
	void wait(); //����� ������ ����ϴ� �Լ�

	int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);
	int decrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);

	bool isEmpty(); //���ŵ� �޽��� ���� ���� Ȯ�� �Լ�
	MSG_QUEUE& peekMessage(); //ť�� ���� �޽��� �� ���� ���� ������ �޽����� ������
	void popMessage(); //ť���� �޽����� ��

	static void parse_msg(const char* msg, int Count, ...); //�޽��� ������ �Լ�
	static void send_msg(SOCKET sock, const char* header, int Count, ...); //�޽��� ������ �Լ�
	static void process_msg(SOCKET sock, std::string msg, std::string &sym_key); //���ŵ� �޽��� ó���ؼ� ť�� �־���(����üȭ���Ѽ� �������Ż��� �����忡�־���)
	static void clientThread(SOCKET sock);//Ŭ���̾�Ʈ����+���ŵȸ޽����� proces_msg�� �־���
};