#include "authserver.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2
#define RSA_ALGORITHM_H

/*DES ��ȣȭ �Լ�
*parameter: ��ȣȭ�� �޽����� ���� �� ����, �� �޽���, �� �޽��� ����, ��ĪŰ��
*return: ��ȣȭ�� �޽��� ����
*/
//����� �ҽ��ڵ� �ο�
int AuthServer::encrypt_block(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key)
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
//����� �ҽ��ڵ� �ο�
int AuthServer::decrypt_block(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned long err = 0;
	int toLen = 0, outLen = 0;
	int ret = 0;

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


/*Ŭ���̾�Ʈ�κ��� ���ŵ� �޽����� ����� �޽��� ť
���ŵ� �޽����� ����ü�� ��ȯ�ǰ� �ش� ť�� ���εȴ�.
*parameter: ����.
*return: ����.
*/
std::queue<MSG_QUEUE> AuthServer::msg_list; // Ŭ���� static ���� �ʱ�ȭ
											//���� ���� 


/*���� ��ü ������. �ش� ��Ʈ�� ������ ����.
*parameter: ���� ��Ʈ
*return: ����
*/
AuthServer::AuthServer(int port) 
{
	keypair = NULL;
	private_key = NULL;
	public_key = NULL;
	encrypt = NULL;
	decrypt = NULL;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	hServSock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&servAdr, 0, sizeof(servAdr));
	servAdr.sin_family = AF_INET;
	servAdr.sin_addr.s_addr = htonl(INADDR_ANY);

	servAdr.sin_port = htons(port);

	bind(hServSock, (SOCKADDR*)& servAdr, sizeof(servAdr));

	listen(hServSock, 5);
}


/*���� ��ü �Ҹ���. ����� �ڿ��� �����Ѵ�.
*parameter: ����
*return: ����
*/
AuthServer::~AuthServer() {
	RSA_free(keypair);
	if (private_key != 0) RSA_free(private_key);
	if (public_key != 0) RSA_free(public_key);
	if (encrypt != 0) free(encrypt);
	if (decrypt != 0) free(decrypt);
	closesocket(hServSock);
	WSACleanup();
}


/*Ŭ���̾�Ʈ ���� ���� ���. ����ڰ� ���� ��û �� accept�� ���Ͽ� ���� ����.
*parameter: ����
*return: ����
*/
void AuthServer::wait()
{
	int cIntAdrSize = 0;
	cIntAdrSize = (int)sizeof(cIntAdr);//Ŭ���̾�Ʈ ���� ����ִ� ����ü�� ũ�� (�ؿ��� ���� �����Ҷ� ����ü ũ�⸸ŭ �����ؾߵż�)
	std::thread *th;
	while (1) { //���ѷ��� ���鼭 ���� Ȯ��
		hCintSock = accept(hServSock, (SOCKADDR*)& cIntAdr, &cIntAdrSize); //����������
		printf("����!\n");
		th = new std::thread(AuthServer::clientThread, hCintSock); //���������
	}
}


/*��Ŷ �޽����� ���� ���� '#'�� ����
*parameter: �޽��� ����
*return: ����
*/
void split(char *buf) 
{
	char *msg = buf;
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
void AuthServer::parse_msg(const char* msg, int Count, ...)
{
	char* buf = NULL;
	//-----��������
	va_list Marker;
	va_start(Marker, Count);
	buf = strtok((char*)msg, ",");
	for (int i = 0; i < Count; i++) {
		strcpy(va_arg(Marker, char*),buf);

		if ( i != Count-1) buf = strtok(NULL, ",");
	}
	va_end(Marker);
	//-----�������� ��
}


/*�ش� Ŭ���̾�Ʈ�� �޽����� ����. �������ڸ� ���Ͽ� ���� ������ ����.
*parameter: Ŭ���̾�Ʈ ����, �޽��� ���, �޽��� ���� ����, �� �޽��� ����
*return: ����
*/
void AuthServer::send_msg(SOCKET sock, const char* header, int Count, ...)
{
	SOCK_MSG msg;
	std::string buf = "";
	char header_[16];
	char contents_[4096];
	strcpy(header_, header);

	//-----��������
	va_list Marker;
	va_start(Marker, Count);

	for (int i = 0; i < Count; i++) {
		buf += va_arg(Marker, char*);
		if (i != Count - 1) buf += ",";
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
	send(sock, (char*)& msg, sizeof(SOCK_MSG), 0);

}


/*������ ������ �޽����� ���޹޾� ���鹮�ڸ� ó���Ͽ� �޽���ť�� ����.
*parameter: Ŭ���̾�Ʈ ����, �޽���, ��ĪŰ��
*return: ����
*/
void AuthServer::process_msg(SOCKET sock, std::string msg, std::string &sym_key)
{
	SOCK_MSG*message = (SOCK_MSG*)msg.c_str(); //string�� char�� �ٲ㼭 ����ü�� �������
	//printf("%s 1111 %s\n", msg);

	split(message->header); //����� �������� ù #�� �ι��ڷ� �ٲ���
	split(message->contents);

	MSG_QUEUE msg_queue; 
	SOCK_MSG sock_msg; 
	msg_queue.sock = sock; //ť���뿡 ������ �־���
	strcpy(sock_msg.header,message->header); //���ŵ� ����� ť���뿡 ���� sock_msg�� ����� �־���
	strcpy(sock_msg.contents, message->contents); //�������� ��������
	msg_queue.msg = sock_msg; //�� ���� sock_msg�� ť������ msg�� �־���
	if (strcmp(sock_msg.header, "login") == 0) {
		char arg[3][4096];
		char final_buf[128];

		parse_msg(message->contents, 3, arg[0], arg[1], arg[2]);
		privateDecrypt(atoi(arg[1]), decode64((unsigned char*)arg[2], 2048), final_buf);
		sym_key = final_buf;


	}
	strcpy(msg_queue.sym_key, sym_key.c_str());
	msg_list.push(msg_queue); //�� ���� ť������ ť�� �־���
}


/*ť�� ������� Ȯ��
*parameter: ����
*return: ����
*/
bool AuthServer::isEmpty() 
{
	return (AuthServer::msg_list.size() == 0); //ť�� ����� 0�̸� 1
}


/*ť�� �ֻ��� �޽��� ��ȯ
*parameter: ����
*return: ť�� �ֻ��� �޽���
*/
MSG_QUEUE& AuthServer::peekMessage() 
{
	return AuthServer::msg_list.front(); //ť���� �� ���� �� �޽����� ��ȯ 
}


/*ť�� �ֻ��� �޽����� ����
*parameter: ����
*return: ����
*/
void AuthServer::popMessage()
{
	if (AuthServer::msg_list.size() != 0) 
	{
		AuthServer::msg_list.pop(); //�޽��� ��
	}
}


/*�� Ŭ���̾�Ʈ�� �޽����� ����, ó���ϴ� �Լ�
*parameter: Ŭ���̾�Ʈ ����
*return: ����
*/
void AuthServer::clientThread(SOCKET sock) //�Һ�:Ŭ���̾�Ʈ����+���ŵȸ޽����� proces_msg�� �־���
{
	printf("����Ϸ�!\n");
	send_msg(sock, "success", 1, "1"); //Ŭ���̾�Ʈ�� sucess ������ �α��� ȭ�� �������ϴϱ�
	char buf[8192];
	std::string msg_buf = "";
	msg_buf.clear();
	int recv_len = sizeof(SOCK_MSG);
	int len = 0;
	std::string sym_key="";
	while (1)
	{
		len = recv(sock,  buf, recv_len, 0); //���� �ޱ�� �� ���̴� recv_len�ε� ���� �����Ÿ� buf�� �ְ� ���� ���� ���̸� ��ȯ
		if (len == -1)
			break;
		buf[len] = 0; //0�� ���ڿ��� ���� �˷���

		recv_len -= len; //���� �������� ���̿��� ���� ���� ���̸� �� -> ���� �������� ���̸�ŭ �� ���������� ���°�
		msg_buf += buf;
		if (recv_len == 0) //�����ϴ� ������ �޽����� �� ������ ���
		{
			process_msg(sock, msg_buf, sym_key); //�޽����� ����ü�� ������ִ� �Լ��� ������

			msg_buf.clear(); //�޽��� ���۴� �ٽ� �����
			recv_len = sizeof(SOCK_MSG); //������ �޽��� ���̸� ���� ���� ���̸�ŭ �ʱ�ȭ
		}
	}
	printf("����� ����!\n");
	closesocket(sock);
}