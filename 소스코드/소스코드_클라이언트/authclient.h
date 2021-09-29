#pragma once
#include "openssl_fn.h"

#include <WinSock2.h>

typedef struct SOCK_MSG
{
	char header[16];  //�޽��� ���
	char contents[4096]; //�޽��� ����
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
	//static std::queue<MSG_QUEUE> msg_list; //���ŵ� �޼����� ����Ǵ� ť
	AuthClient(const char* ip, int port); //������ �������� ������
	~AuthClient();

	int encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key); //DES ��ȣȭ �Լ�
	int decrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key); //DES ��ȣȭ �Լ�

	void parse_msg(const char* msg, int Count, ...); //�޽��� ó�� �Լ�
	void recv_msg(void (*fp)(SOCK_MSG& msg, AuthClient& obj)); //�޽��� �޴� �Լ�
	void send_msg(const char* header, int Count, ...); //�޽��� ������ �Լ�
};