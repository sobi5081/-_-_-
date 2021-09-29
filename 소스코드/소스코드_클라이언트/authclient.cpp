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

/*Ŭ���̾�Ʈ ��ü ������. �Ű������� ���� ���Ͽ� �ش� ������ ���� ����.
*parameter: ���� IP, ��Ʈ��ȣ
*return: ����
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

} //������ �������� ������


/*Ŭ���̾�Ʈ ��ü �Ҹ���. ����� �ڿ� ����.
*parameter: ���� IP, ��Ʈ��ȣ
*return: ����
*/
AuthClient::~AuthClient()
{
	closesocket(hServSock);
	WSACleanup();
}


/*��Ŷ �޽����� ���� ���� '#'�� ����
*parameter: �޽��� ����
*return: ����
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


/*�޽��� �������� ','�� �������� �޽����� �и�
*parameter: �޽��� ����, �и��� �޽��� ����, �� �޽����� ���Ե� ���ڿ� ������(��������).
*return: ����
*/
void AuthClient::parse_msg(const char* msg, int Count, ...)
{
	char* buf;
	//-----��������
	va_list Marker;
	va_start(Marker, Count);
	buf = strtok((char*)msg, ",");
	for (int i = 0; i < Count; i++) {
		strcpy(va_arg(Marker, char*), buf);

		if (i != Count - 1) buf = strtok(NULL, ",");
	}
	va_end(Marker);
	//-----�������� ��
}


/*�����κ��� ���ŵ� �޽����� ���̿� �°� ����. ó���� �޽����� �޽��� ó�� �Լ��� ����.
*parameter: �޽��� ó�� �Լ� �ݹ��Լ�.
*return: ����
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
			SOCK_MSG* message = (SOCK_MSG*)msg_buf.c_str(); //string�� char�� �ٲ㼭 ����ü�� �������
			split(message->header); //����� �������� ù #�� �ι��ڷ� �ٲ���
			split(message->contents);
			fp(*message, *this);

			msg_buf = "";
			recv_len = sizeof(SOCK_MSG);
		}
	}
}


/*DES ��ȣȭ �Լ�
*parameter: ��ȣȭ�� �޽����� ���� �� ����, �� �޽���, �� �޽��� ����, ��ĪŰ��
*return: ��ȣȭ�� �޽��� ����
*/
//����� �ҽ��ڵ� ����
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

/*DES ��ȣȭ �Լ�
*parameter: ��ȣȭ�� �޽����� ���� �� ����, ��ȣȭ�� �޽��� ����, ��ȣȭ�� �޽��� ���� ����, ��ĪŰ��
*return: ��ȭȭ�� �޽��� ����
*/
//����� �ҽ��ڵ� ����
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

/*���������� ������ �޽����� �Է¹޾� �޽��� �������ݿ� �°� ���� �� ����.
*parameter: �޽��� ���, ������ ����, ����(��������)
*return: ����
*/
void AuthClient::send_msg(const char* header,int Count, ...)
{
	SOCK_MSG msg;
	std::string buf="";
	char header_[16];
	char contents_[4096];
	strcpy(header_, header);
	
	//-----��������
	va_list Marker = NULL;
	va_start(Marker, Count);
	for (int i = 0; i < Count; i++){
		buf += va_arg(Marker, char*);
		if (i != (Count - 1))
			buf.append(",");
	}
	va_end(Marker);
	//-----�������� ��
	strcpy(contents_, buf.c_str());

	for (int i = strlen(header_); i < 16; i++)
		header_[i] = '#'; //���ڿ��� �������� # �־���
	for (int i = buf.size(); i < 4096; i++)
		contents_[i] = '#'; //���ڿ��� �������� # �־���

	strncpy(msg.header, header_, 16);
	strncpy(msg.contents, contents_, 4096);
	send(hServSock, (char*)& msg, sizeof(SOCK_MSG), 0);
}
